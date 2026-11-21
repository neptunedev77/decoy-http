"""decoy-http: a small low-interaction HTTP honeypot.

The server is a passive recorder. Every byte received is untrusted data that
is only parsed into strings. It is never executed, evaluated, deserialised,
used as a filesystem path or used to open a network connection.

Responses come only from static content in config.py, looked up by exact path.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import socket
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, unquote_plus

import config

STATUS_TEXT = {
    200: "OK",
    301: "Moved Permanently",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    414: "Request-URI Too Long",
    429: "Too Many Requests",
    501: "Not Implemented",
}

# --------------------------------------------------------------------------
# Sanitisation and classification
# --------------------------------------------------------------------------

# C0/C1 control characters (includes ESC, so no ANSI sequences survive), DEL,
# and Unicode format characters that can reorder or hide text in a terminal
# (bidi overrides, zero-width chars, BOM, line/paragraph separators).
_UNSAFE_CHARS = re.compile(
    "[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁩﻿]"
)


def _escape_char(match: re.Match[str]) -> str:
    cp = ord(match.group())
    return f"\\x{cp:02x}" if cp <= 0xFF else f"\\u{cp:04x}"


def sanitize(value: str) -> str:
    """Make a string safe to print in a terminal or store in one log line."""
    return _UNSAFE_CHARS.sub(_escape_char, value)


def _decode(raw: bytes) -> str:
    # Never fails: invalid UTF-8 becomes \xNN escapes.
    return raw.decode("utf-8", errors="backslashreplace")


_RULES = [
    (name, re.compile(pattern, re.IGNORECASE | re.DOTALL), parts)
    for name, pattern, parts in config.CATEGORY_RULES
]


def _with_decoded(raw: str, plus: bool = False) -> str:
    # Raw text plus one and two rounds of URL-decoding, to catch %2e%2e and
    # double-encoded %252e%252e payloads. Decoding is only used for matching.
    dec = unquote_plus if plus else unquote
    once = dec(raw)
    return "\n".join((raw, once, dec(once)))


def classify(
    path: str, query: str, body: str, headers: list[tuple[str, str]]
) -> list[str]:
    texts = {
        "path": _with_decoded(path),
        "query": _with_decoded(query, plus=True),
        "body": _with_decoded(body, plus=True),
        "headers": "\n".join(value for _, value in headers),
    }
    found = [
        name
        for name, regex, parts in _RULES
        if any(regex.search(texts[part]) for part in parts)
    ]
    return found or ["unknown"]


# --------------------------------------------------------------------------
# Event log (JSON Lines, rotated by size)
# --------------------------------------------------------------------------


def _sanitize_tree(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, dict):
        return {sanitize(str(k)): _sanitize_tree(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_tree(v) for v in value]
    return value


class EventLog:
    def __init__(self, log_dir: str | Path, console: bool = True) -> None:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        # Private Logger instances (not registered globally) so several
        # servers, e.g. in tests, never share handlers.
        self._file = logging.Logger("decoy-http.requests")
        handler = RotatingFileHandler(
            Path(log_dir) / config.LOG_FILE_NAME,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._file.addHandler(handler)
        self._console = logging.Logger("decoy-http.console")
        if console:
            self._console.addHandler(logging.StreamHandler(sys.stdout))

    def write(self, event: dict[str, Any]) -> None:
        event = _sanitize_tree(event)
        # ensure_ascii also escapes any non-ASCII character as \uXXXX.
        self._file.info(json.dumps(event, ensure_ascii=True))
        self._console.info(_summary_line(event))

    def close(self) -> None:
        for lg in (self._file, self._console):
            for h in list(lg.handlers):
                h.close()
                lg.removeHandler(h)


def _summary_line(event: dict[str, Any]) -> str:
    # Values are already sanitised; just keep the line short.
    path = str(event.get("path", ""))[:100]
    ua = str(event.get("user_agent", ""))[:60]
    flags = [k for k, v in event.get("flags", {}).items() if v]
    return (
        f"{event['ts']} {event['src_ip']:>15} {event.get('method', '-'):7} "
        f"{path} -> {event.get('status')} [{','.join(event.get('categories', []))}]"
        f"{' {' + ','.join(flags) + '}' if flags else ''} \"{ua}\""
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


# --------------------------------------------------------------------------
# Rate limiting (fixed one-minute window per IP, in memory)
# --------------------------------------------------------------------------


class RateLimiter:
    def __init__(self, limit: int, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            start, count = self._hits.get(ip, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            self._hits[ip] = (start, count + 1)
            if len(self._hits) > config.RATE_LIMIT_MAX_TRACKED_IPS:
                # Bound memory: forget expired windows (or everything).
                self._hits = {
                    k: v for k, v in self._hits.items() if now - v[0] < self.window
                }
                if len(self._hits) > config.RATE_LIMIT_MAX_TRACKED_IPS:
                    self._hits.clear()
            return count + 1 <= self.limit


# --------------------------------------------------------------------------
# Bounded socket reader
# --------------------------------------------------------------------------


class SocketReader:
    """Buffered reader with per-read timeouts and an overall deadline.

    The deadline stops slowloris-style clients that trickle one byte at a
    time: each recv() is given only the time left for the whole request.
    """

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock = sock
        self.deadline = deadline
        self.buf = bytearray()
        self.received = 0

    def _fill(self) -> bool:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        self.sock.settimeout(min(config.SOCKET_TIMEOUT, remaining))
        chunk = self.sock.recv(4096)
        if not chunk:
            return False
        self.received += len(chunk)
        self.buf += chunk
        return True

    def readline(self, limit: int) -> tuple[bytes, bool]:
        """Return (line, too_long). Never buffers much more than `limit`."""
        while b"\n" not in self.buf and len(self.buf) <= limit:
            if not self._fill():
                break
        idx = self.buf.find(b"\n", 0, limit + 1)
        if idx < 0:
            if len(self.buf) > limit:
                line = bytes(self.buf[:limit])
                del self.buf[:limit]
                return line, True
            idx = len(self.buf) - 1  # EOF without newline
        line = bytes(self.buf[: idx + 1])
        del self.buf[: idx + 1]
        return line, False

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill():
                break
        data = bytes(self.buf[:n])
        del self.buf[:n]
        return data

    def discard(self, n: int) -> None:
        """Read and throw away up to n bytes (best effort)."""
        try:
            while n > 0:
                if not self.buf and not self._fill():
                    return
                take = min(n, len(self.buf))
                del self.buf[:take]
                n -= take
        except OSError:  # includes timeouts
            return


# --------------------------------------------------------------------------
# HTTP handling
# --------------------------------------------------------------------------

_METHOD_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$")
_VERSION_RE = re.compile(r"^HTTP/\d\.\d$")
_ABSOLUTE_URI_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


class BadRequest(Exception):
    def __init__(self, response: config.FakeResponse = config.BAD_REQUEST) -> None:
        super().__init__(response.status)
        self.response = response


def is_proxy_attempt(method: str, target: str) -> bool:
    if method == "CONNECT":
        return True
    # Absolute URI ("http://other.host/...") or authority form ("host:443").
    return bool(_ABSOLUTE_URI_RE.match(target)) or not (
        target.startswith("/") or target == "*"
    )


def choose_response(method: str, target: str, path: str) -> config.FakeResponse:
    """Pick a static response. `path` is only ever used as a dict key."""
    if method == "CONNECT":
        return config.METHOD_NOT_ALLOWED  # never tunnel
    if is_proxy_attempt(method, target):
        return config.BAD_REQUEST  # never forward
    if method == "OPTIONS":
        return config.OPTIONS_RESPONSE
    if method in ("GET", "HEAD"):
        return config.ENDPOINTS.get(path, config.NOT_FOUND)
    if method == "POST":
        if path in config.POST_OVERRIDES:
            return config.POST_OVERRIDES[path]
        return config.ENDPOINTS.get(path, config.NOT_FOUND)
    if method in config.DISABLED_METHODS:
        return config.METHOD_NOT_ALLOWED
    return config.NOT_IMPLEMENTED


def _body_fields(body: bytes) -> dict[str, Any]:
    try:
        return {"body": body.decode("utf-8"), "body_encoding": "utf-8"}
    except UnicodeDecodeError:
        return {"body": base64.b64encode(body).decode("ascii"), "body_encoding": "base64"}


def _parse_query(query: str) -> dict[str, list[str]]:
    try:
        return parse_qs(query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        return {}


class TrapHandler(socketserver.BaseRequestHandler):
    server: TrapServer

    def handle(self) -> None:
        started = time.monotonic()
        event: dict[str, Any] = {
            "ts": _now_iso(),
            "src_ip": self.client_address[0],
            "src_port": self.client_address[1],
            "flags": {
                "truncated": False,
                "rate_limited": False,
                "malformed": False,
                "timeout": False,
            },
        }
        reader = SocketReader(self.request, started + config.REQUEST_DEADLINE)
        # An exception in one request must never take the server down: every
        # error is caught here, logged as a flag, and the connection closed.
        try:
            response = self._process(reader, event)
        except BadRequest as exc:
            event["flags"]["malformed"] = True
            response = exc.response
        except TimeoutError:
            event["flags"]["timeout"] = True
            response = config.REQUEST_TIMEOUT if reader.received else None
        except OSError:
            event["flags"]["connection_error"] = True
            response = None
        except Exception as exc:  # defensive: unexpected parser bug
            event["error"] = type(exc).__name__
            response = config.BAD_REQUEST

        if reader.received == 0:
            return  # bare TCP connect with no data: nothing to record

        event.setdefault("categories", ["unknown"])
        event["status"] = response.status if response is not None else None
        event["duration_ms"] = round((time.monotonic() - started) * 1000)
        # Log before answering, so the record exists by the time the client
        # sees the response.
        try:
            self.server.event_log.write(event)
        except Exception as exc:  # e.g. disk full: keep serving
            print(f"log write failed: {type(exc).__name__}", file=sys.stderr)
        if response is not None:
            self._send(response, event.get("method", ""))

    def _process(self, reader: SocketReader, event: dict[str, Any]) -> config.FakeResponse:
        flags = event["flags"]

        # --- request line -------------------------------------------------
        raw_line, too_long = reader.readline(config.MAX_REQUEST_LINE)
        request_line = _decode(raw_line).rstrip("\r\n")
        event["request_line"] = request_line[:1024]
        if too_long:
            flags["truncated"] = True
            raise BadRequest(config.URI_TOO_LONG)
        parts = request_line.split()
        if len(parts) != 3 or not _METHOD_RE.match(parts[0]) or not _VERSION_RE.match(parts[2]):
            raise BadRequest()
        method, target, version = parts
        raw_path, _, query = target.split("#", 1)[0].partition("?")
        event.update(
            method=method,
            target=target,
            path=raw_path,
            query_raw=query,
            http_version=version,
        )
        if is_proxy_attempt(method, target):
            event["categories"] = ["proxy-attempt"]

        # --- headers --------------------------------------------------------
        headers: list[tuple[str, str]] = []
        event["headers"] = headers
        total = 0
        while True:
            raw, too_long = reader.readline(config.MAX_HEADER_LINE)
            total += len(raw)
            if too_long or total > config.MAX_HEADERS_TOTAL:
                flags["truncated"] = True
                raise BadRequest()
            if raw in (b"\r\n", b"\n", b""):
                break
            line = _decode(raw).rstrip("\r\n")
            if line[:1] in (" ", "\t") and headers:  # obsolete line folding
                name, value = headers[-1]
                headers[-1] = (name, value + " " + line.strip())
                continue
            name, sep, value = line.partition(":")
            if not sep:
                flags["malformed"] = True
            headers.append((name.strip(), value.strip()))
            if len(headers) > config.MAX_HEADERS:
                flags["truncated"] = True
                raise BadRequest()

        def header(name: str) -> list[str]:
            return [v for n, v in headers if n.lower() == name]

        event["user_agent"] = (header("user-agent") or [""])[0]

        # --- rate limit -----------------------------------------------------
        if not self.server.rate_limiter.allow(event["src_ip"]):
            # Short record only: no headers, no body.
            flags["rate_limited"] = True
            del event["headers"]
            event["path"] = raw_path[:200]
            event["categories"] = event.get("categories") or classify(raw_path, query, "", [])
            return config.TOO_MANY_REQUESTS

        # --- body -----------------------------------------------------------
        lengths = set(header("content-length"))
        length = 0
        if len(lengths) > 1 or (lengths and not next(iter(lengths)).isdigit()):
            raise BadRequest()
        if lengths:
            length = int(next(iter(lengths)))
        if any("chunked" in v.lower() for v in header("transfer-encoding")):
            flags["body_not_read"] = True  # chunked bodies are not decoded
            length = 0

        # Fill in everything we know before reading the body, so a timeout
        # while reading it still produces a useful record.
        event.update(query=_parse_query(query), body_length=length)
        body = reader.read(min(length, config.MAX_BODY_LOG_BYTES))
        if length > len(body):
            flags["truncated"] = True
            reader.discard(min(length - len(body), config.MAX_BODY_DRAIN_BYTES))
        event.update(body_logged_bytes=len(body), **_body_fields(body))

        categories = classify(raw_path, query, _decode(body), headers)
        if "proxy-attempt" in event.get("categories", []):
            categories = ["proxy-attempt"] + [c for c in categories if c != "unknown"]
        event["categories"] = categories
        return choose_response(method, target, unquote(raw_path))

    def _send(self, resp: config.FakeResponse, method: str) -> None:
        body = resp.body.encode("utf-8")
        # Only static values go into the response head: nothing from the
        # request is ever reflected back.
        lines = [
            f"HTTP/1.1 {resp.status} {STATUS_TEXT.get(resp.status, '')}",
            f"Date: {formatdate(usegmt=True)}",
            f"Server: {config.SERVER_HEADER}",
        ]
        if resp.php:
            lines.append(f"X-Powered-By: {config.X_POWERED_BY}")
        lines += [f"{k}: {v}" for k, v in resp.headers]
        lines += [
            f"Content-Length: {len(body)}",
            f"Content-Type: {resp.content_type}",
            "Connection: close",
        ]
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        try:
            self.request.settimeout(config.SOCKET_TIMEOUT)
            self.request.sendall(head if method == "HEAD" else head + body)
        except OSError:
            pass


class TrapServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        address: tuple[str, int],
        log_dir: str | Path,
        rate_limit: int = config.RATE_LIMIT_PER_MINUTE,
        console: bool = True,
    ) -> None:
        self.event_log = EventLog(log_dir, console=console)
        self.rate_limiter = RateLimiter(rate_limit)
        self._slots = threading.BoundedSemaphore(config.MAX_CONNECTIONS)
        self.dropped_connections = 0
        super().__init__(address, TrapHandler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind() does a getfqdn() lookup; skip it so the
        # server never does name resolution of any kind.
        socketserver.TCPServer.server_bind(self)
        self.server_name = config.SERVER_NAME
        self.server_port = self.server_address[1]

    def process_request(self, request: Any, client_address: Any) -> None:
        # Limit simultaneous connections: beyond the limit, close at once
        # instead of spawning more threads.
        if not self._slots.acquire(blocking=False):
            self.dropped_connections += 1
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Don't dump tracebacks (which may contain client data) to the console.
        print(f"handler error: {sys.exc_info()[0].__name__}", file=sys.stderr)

    def server_close(self) -> None:
        super().server_close()
        self.event_log.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="decoy-http honeypot")
    parser.add_argument(
        "--local",
        action="store_true",
        help="bind only to 127.0.0.1 (safe local testing, nothing exposed)",
    )
    args = parser.parse_args(argv)

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("refusing to run as root", file=sys.stderr)
        return 1

    host = "127.0.0.1" if args.local else os.environ.get("DECOY_HOST", "0.0.0.0")
    port = int(os.environ.get("DECOY_PORT", "8080"))
    log_dir = os.environ.get("DECOY_LOG_DIR", "logs")
    with TrapServer((host, port), log_dir) as server:
        print(f"decoy-http listening on {host}:{port}, logging to {log_dir}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
