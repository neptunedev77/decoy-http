"""decoy-http: a small low-interaction HTTP honeypot.

The server is a passive recorder. Every byte received is untrusted data that
is only parsed into strings. It is never executed, evaluated, deserialised,
used as a filesystem path or used to open a network connection.
"""

from __future__ import annotations

import os
import socket
import socketserver
import sys
from email.utils import formatdate
from http.server import ThreadingHTTPServer
from urllib.parse import unquote

import config

STATUS_TEXT = {
    200: "OK",
    301: "Moved Permanently",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    501: "Not Implemented",
}


class Request:
    """A parsed HTTP request. All fields are plain strings/bytes."""

    def __init__(self) -> None:
        self.method = ""
        self.target = ""
        self.version = ""
        self.headers: list[tuple[str, str]] = []
        self.body = b""


def _decode(raw: bytes) -> str:
    # Never fails: invalid UTF-8 becomes \xNN escapes.
    return raw.decode("utf-8", errors="backslashreplace")


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


class TrapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        reader = SocketReader(self.request)
        req = Request()

        parts = _decode(reader.readline()).split()
        if len(parts) != 3:
            self.send(config.FakeResponse(400, "<h1>Bad Request</h1>\n"), "GET")
            return
        req.method, req.target, req.version = parts

        while True:
            line = reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            name, _, value = _decode(line).partition(":")
            req.headers.append((name.strip(), value.strip()))

        length = 0
        for name, value in req.headers:
            if name.lower() == "content-length" and value.isdigit():
                length = int(value)
        req.body = reader.read(length)

        path = unquote(req.target.split("?", 1)[0].split("#", 1)[0])
        self.send(choose_response(req.method, path), req.method)

    def send(self, resp: config.FakeResponse, method: str) -> None:
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


class TrapServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self) -> None:
        # HTTPServer.server_bind() does a getfqdn() lookup; skip it so the
        # server never does name resolution of any kind.
        socketserver.TCPServer.server_bind(self)
        self.server_name = config.SERVER_NAME
        self.server_port = self.server_address[1]


def main() -> None:
    host = os.environ.get("DECOY_HOST", "0.0.0.0")
    port = int(os.environ.get("DECOY_PORT", "8080"))
    with TrapServer((host, port), TrapHandler) as server:
        print(f"decoy-http listening on {host}:{port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    sys.exit(main())
