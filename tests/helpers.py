"""Shared test helpers: run a TrapServer on a random local port."""

from __future__ import annotations

import json
import shutil
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

import config
import trap


class ServerTestCase(unittest.TestCase):
    rate_limit = 10_000

    @classmethod
    def setUpClass(cls) -> None:
        cls.log_dir = Path(tempfile.mkdtemp(prefix="decoy-test-"))
        # Port 0 = random free port; only ever bound to 127.0.0.1.
        cls.server = trap.TrapServer(
            ("127.0.0.1", 0), cls.log_dir, rate_limit=cls.rate_limit, console=False
        )
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.log_dir, ignore_errors=True)

    def raw(self, data: bytes, timeout: float = 10) -> tuple[int, dict[str, str], bytes]:
        """Send raw bytes, return (status, headers, body). status 0 = no reply."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall(data)
            out = b""
            try:
                while chunk := s.recv(65536):
                    out += chunk
            except ConnectionError:
                pass
        if not out:
            return 0, {}, b""
        head, _, body = out.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        return status, headers, body

    def get(
        self, path: str, method: str = "GET", extra: bytes = b""
    ) -> tuple[int, dict[str, str], bytes]:
        return self.raw(
            f"{method} {path} HTTP/1.1\r\nHost: test\r\n".encode() + extra + b"\r\n"
        )

    def log_lines(self) -> list[str]:
        path = self.log_dir / config.LOG_FILE_NAME
        if not path.exists():
            return []
        return path.read_text(encoding="utf-8").splitlines()

    def last_event(self) -> dict[str, Any]:
        return json.loads(self.log_lines()[-1])
