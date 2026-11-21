"""decoy-http: a small low-interaction HTTP honeypot.

The server is a passive recorder. Every byte received is untrusted data that
is only parsed into strings. It is never executed, evaluated, deserialised,
used as a filesystem path or used to open a network connection.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import socket
import socketserver
import sys
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
    def __init__(self, log_dir: str | Path) -> None:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        # A private Logger instance (not registered globally) so several
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
        self._console.addHandler(logging.StreamHandler(sys.stdout))

    def write(self, event: dict[str, Any]) -> None:
        event = _sanitize_tree(event)
        # ensure_ascii also escapes any non-ASCII byte as \uXXXX.
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
# HTTP handling
# --------------------------------------------------------------------------


class SocketReader:
    """Minimal buffered reader on top of the raw socket."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = bytearray()

    def _fill(self) -> bool:
        chunk = self.sock.recv(4096)
        if not chunk:
            return False
        self.buf += chunk
        return True

    def readline(self) -> bytes:
        while b"\n" not in self.buf:
            if not self._fill():
                break
        idx = self.buf.find(b"\n")
        end = len(self.buf) if idx < 0 else idx + 1
        line = bytes(self.buf[:end])
        del self.buf[:end]
        return line

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill():
                break
        data = bytes(self.buf[:n])
        del self.buf[:n]
        return data


def choose_response(method: str, path: str) -> config.FakeResponse:
    """Pick a static response. `path` is only ever used as a dict key."""
    if method in ("GET", "HEAD"):
        return config.ENDPOINTS.get(path, config.NOT_FOUND)
    if method == "POST":
        if path in config.POST_OVERRIDES:
            return config.POST_OVERRIDES[path]
        return config.ENDPOINTS.get(path, config.NOT_FOUND)
    return config.FakeResponse(
        501, "<h1>Not Implemented</h1>\n", headers=(("Allow", "GET,POST,HEAD"),)
    )


def _body_fields(body: bytes) -> dict[str, Any]:
    try:
        return {"body": body.decode("utf-8"), "body_encoding": "utf-8"}
    except UnicodeDecodeError:
        return {"body": base64.b64encode(body).decode("ascii"), "body_encoding": "base64"}


class TrapHandler(socketserver.BaseRequestHandler):
    server: TrapServer

    def handle(self) -> None:
        ip, port = self.client_address[0], self.client_address[1]
        event: dict[str, Any] = {
            "ts": _now_iso(),
            "src_ip": ip,
            "src_port": port,
            "flags": {"truncated": False, "rate_limited": False, "malformed": False},
        }
        reader = SocketReader(self.request)

        request_line = _decode(reader.readline())
        event["request_line"] = request_line.rstrip("\r\n")
        parts = request_line.split()
        if len(parts) != 3:
            event["flags"]["malformed"] = True
            event["categories"] = ["unknown"]
            self.send(config.FakeResponse(400, "<h1>Bad Request</h1>\n"), "GET", event)
            return
        method, target, version = parts

        headers: list[tuple[str, str]] = []
        while True:
            line = reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            name, sep, value = _decode(line).partition(":")
            if not sep:
                event["flags"]["malformed"] = True
            headers.append((name.strip(), value.strip()))

        length = 0
        for name, value in headers:
            if name.lower() == "content-length" and value.isdigit():
                length = int(value)
        body = reader.read(min(length, config.MAX_BODY_LOG_BYTES))
        if length > len(body):
            event["flags"]["truncated"] = True

        raw_path, _, query = target.split("#", 1)[0].partition("?")
        body_text = _decode(body)
        event.update(
            method=method,
            target=target,
            path=raw_path,
            query_raw=query,
            query=_parse_query(query),
            http_version=version,
            headers=[[n, v] for n, v in headers],
            user_agent=next((v for n, v in headers if n.lower() == "user-agent"), ""),
            body_length=length,
            body_logged_bytes=len(body),
            **_body_fields(body),
            categories=classify(raw_path, query, body_text, headers),
        )
        self.send(choose_response(method, unquote(raw_path)), method, event)

    def send(self, resp: config.FakeResponse, method: str, event: dict[str, Any]) -> None:
        event["status"] = resp.status
        try:
            body = resp.body.encode("utf-8")
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
            self.request.sendall(head if method == "HEAD" else head + body)
        finally:
            self.server.event_log.write(event)


def _parse_query(query: str) -> dict[str, list[str]]:
    try:
        return parse_qs(query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        return {}


class TrapServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], log_dir: str | Path) -> None:
        self.event_log = EventLog(log_dir)
        super().__init__(address, TrapHandler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind() does a getfqdn() lookup; skip it so the
        # server never does name resolution of any kind.
        socketserver.TCPServer.server_bind(self)
        self.server_name = config.SERVER_NAME
        self.server_port = self.server_address[1]

    def server_close(self) -> None:
        super().server_close()
        self.event_log.close()


def main() -> None:
    host = os.environ.get("DECOY_HOST", "0.0.0.0")
    port = int(os.environ.get("DECOY_PORT", "8080"))
    log_dir = os.environ.get("DECOY_LOG_DIR", "logs")
    with TrapServer((host, port), log_dir) as server:
        print(f"decoy-http listening on {host}:{port}, logging to {log_dir}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    sys.exit(main())
