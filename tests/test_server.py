"""End-to-end tests against a real TrapServer bound to 127.0.0.1."""

from __future__ import annotations

import socket
import time
import unittest
from pathlib import Path
from unittest import mock

import config
import trap
from tests.helpers import ServerTestCase


class EndpointTests(ServerTestCase):
    def test_fake_endpoints(self) -> None:
        for path, resp in config.ENDPOINTS.items():
            with self.subTest(path=path):
                status, headers, body = self.get(path)
                self.assertEqual(status, resp.status)
                self.assertEqual(body, resp.body.encode())
                self.assertEqual(headers["server"], config.SERVER_HEADER)
                self.assertEqual(headers["connection"], "close")

    def test_php_header_only_on_php_pages(self) -> None:
        _, headers, _ = self.get("/wp-login.php")
        self.assertEqual(headers["x-powered-by"], config.X_POWERED_BY)
        _, headers, _ = self.get("/.env")
        self.assertNotIn("x-powered-by", headers)

    def test_unknown_path_is_apache_404(self) -> None:
        for path in ("/nope", "/wp-content/plugins/x.php", "/a/b/c?d=e"):
            status, _, body = self.get(path)
            self.assertEqual(status, 404)
            self.assertEqual(body, config.NOT_FOUND_PAGE.encode())

    def test_head_has_no_body(self) -> None:
        status, headers, body = self.get("/.env", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(int(headers["content-length"]), len(config.FAKE_DOTENV.encode()))

    def test_wp_login_post_always_fails_and_is_logged(self) -> None:
        body = b"log=someuser&pwd=hunter2"
        status, _, page = self.raw(
            b"POST /wp-login.php HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\n\r\n%s"
            % (len(body), body)
        )
        self.assertEqual(status, 200)
        self.assertIn(b"login_error", page)
        self.assertNotIn(b"someuser", page)  # submitted data is never reflected
        event = self.last_event()
        self.assertEqual(event["body"], body.decode())
        self.assertIn("wordpress-probe", event["categories"])

    def test_methods(self) -> None:
        self.assertEqual(self.get("/", "OPTIONS")[0], 200)
        for method in ("PUT", "DELETE", "PATCH", "PROPFIND", "TRACE"):
            self.assertEqual(self.get("/", method)[0], 405, method)
        self.assertEqual(self.get("/", "FOOBAR")[0], 501)

    def test_no_active_content_in_responses(self) -> None:
        for resp in list(config.ENDPOINTS.values()) + list(config.POST_OVERRIDES.values()):
            self.assertNotIn("<script", resp.body.lower())


class PathTraversalTests(ServerTestCase):
    VARIANTS = [
        "/../../etc/passwd",
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd",
        "/.env/../../../etc/passwd",
        "/..\\..\\windows\\win.ini",
        "/static/..%c0%af..%c0%afetc/passwd",
        "/.git/../../../../etc/shadow",
        "/?file=../../../../etc/passwd",
        "/" + "../" * 30 + "trap.py",
        "/config.py",
        "/trap.py",
    ]

    def test_traversal_never_returns_real_files(self) -> None:
        real = Path(trap.__file__).read_bytes()[:200]
        static = {r.body.encode() for r in config.ENDPOINTS.values()}
        for path in self.VARIANTS:
            with self.subTest(path=path):
                status, _, body = self.get(path)
                self.assertIn(status, (200, 400, 404))
                if status == 200:  # e.g. "/?file=..." is just the index page
                    self.assertIn(body, static)
                self.assertNotIn(b"root:", body)
                self.assertNotIn(real, body)
                self.assertNotIn(b"import ", body)

    def test_traversal_is_classified(self) -> None:
        for path in self.VARIANTS[:9]:
            with self.subTest(path=path):
                self.get(path)
                self.assertIn("path-traversal", self.last_event()["categories"])


class RobustnessTests(ServerTestCase):
    def test_large_body_is_truncated(self) -> None:
        size = 200_000
        status, _, _ = self.raw(
            b"POST /x HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % size + b"A" * size
        )
        self.assertEqual(status, 404)
        event = self.last_event()
        self.assertTrue(event["flags"]["truncated"])
        self.assertEqual(event["body_length"], size)
        self.assertEqual(event["body_logged_bytes"], config.MAX_BODY_LOG_BYTES)
        self.assertEqual(len(event["body"]), config.MAX_BODY_LOG_BYTES)

    def test_binary_body_is_base64(self) -> None:
        self.raw(b"POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\n\xff\x00\xfe\x01")
        event = self.last_event()
        self.assertEqual(event["body_encoding"], "base64")
        self.assertEqual(event["body"], "/wD+AQ==")

    def test_malformed_requests_do_not_kill_server(self) -> None:
        bad = [
            b"garbage\r\n\r\n",
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + bytes(range(256)),
            b"GET / HTTP/1.1\r\nContent-Length: -5\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"GET / HTTP/9\r\n\r\n",
            b"GET /\xff\xfe HTTP/1.1\r\nX-\xff: \xfe\r\nno colon here\r\n\r\n",
            b"GET /" + b"a" * (config.MAX_REQUEST_LINE + 10) + b" HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nX: " + b"b" * (config.MAX_HEADER_LINE + 10) + b"\r\n\r\n",
            b"GET / HTTP/1.1\r\n" + b"X: y\r\n" * (config.MAX_HEADERS + 5) + b"\r\n",
            b"\r\n",
        ]
        for data in bad:
            with self.subTest(data=data[:40]):
                status, _, _ = self.raw(data)
                self.assertIn(status, (400, 404, 414))
        # A bare connect with no data, then the server still works.
        socket.create_connection(("127.0.0.1", self.port)).close()
        self.assertEqual(self.get("/")[0], 200)

    def test_too_long_request_line_is_414(self) -> None:
        status, _, _ = self.raw(
            b"GET /" + b"a" * (config.MAX_REQUEST_LINE + 10) + b" HTTP/1.1\r\n\r\n"
        )
        self.assertEqual(status, 414)
        self.assertTrue(self.last_event()["flags"]["truncated"])

    def test_exception_in_handler_is_contained(self) -> None:
        with mock.patch.object(trap, "classify", side_effect=RuntimeError("boom")):
            status, _, _ = self.get("/")
        self.assertEqual(status, 400)
        self.assertEqual(self.last_event()["error"], "RuntimeError")
        self.assertEqual(self.get("/")[0], 200)

    def test_slow_client_hits_deadline(self) -> None:
        with mock.patch.object(config, "REQUEST_DEADLINE", 1.0):
            with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
                start = time.monotonic()
                s.sendall(b"GET / HTTP/1.1\r\n")
                for _ in range(2):  # trickle a few bytes, then go quiet
                    time.sleep(0.3)
                    s.sendall(b"X")
                reply = s.recv(4096)
                # Cut at the 1 s request deadline, not 10 s after the last byte.
                self.assertLess(time.monotonic() - start, 3)
        self.assertTrue(reply.startswith(b"HTTP/1.1 408"))
        self.assertTrue(self.last_event()["flags"]["timeout"])


class ProxyTests(ServerTestCase):
    def setUp(self) -> None:
        # A local "upstream" that would receive a connection if we ever proxied.
        self.upstream = socket.socket()
        self.upstream.bind(("127.0.0.1", 0))
        self.upstream.listen(5)
        self.upstream.settimeout(0.5)
        self.up_port = self.upstream.getsockname()[1]

    def tearDown(self) -> None:
        self.upstream.close()

    def assert_no_upstream_connection(self) -> None:
        with self.assertRaises(TimeoutError):
            self.upstream.accept()

    def test_connect_is_not_tunnelled(self) -> None:
        status, _, _ = self.raw(
            f"CONNECT 127.0.0.1:{self.up_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.up_port}\r\n\r\n".encode()
        )
        self.assertEqual(status, 405)
        self.assert_no_upstream_connection()
        self.assertIn("proxy-attempt", self.last_event()["categories"])

    def test_absolute_uri_is_not_forwarded(self) -> None:
        status, _, _ = self.raw(
            f"GET http://127.0.0.1:{self.up_port}/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode()
        )
        self.assertEqual(status, 400)
        self.assert_no_upstream_connection()
        self.assertEqual(self.last_event()["categories"][0], "proxy-attempt")


class LogSanitizationTests(ServerTestCase):
    def test_control_and_ansi_chars_are_escaped(self) -> None:
        ua = b"\x1b[31mred\x1b[0m\x07bell\x08\xe2\x80\xaeRTL\x00"
        self.raw(b"GET /\x1b]0;title\x07 HTTP/1.1\r\nUser-Agent: " + ua + b"\r\n\r\n")
        raw = (self.log_dir / config.LOG_FILE_NAME).read_bytes()
        for bad in (b"\x1b", b"\x07", b"\x08", b"\x00", b"\xe2\x80\xae"):
            self.assertNotIn(bad, raw)
        event = self.last_event()
        self.assertEqual(
            event["user_agent"], "\\x1b[31mred\\x1b[0m\\x07bell\\x08\\u202eRTL\\x00"
        )
        self.assertNotIn("\x1b", event["path"])

    def test_one_event_per_line(self) -> None:
        before = len(self.log_lines())
        body = b'x\n{"injected": true}\r\n'
        self.raw(b"POST / HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        self.assertEqual(len(self.log_lines()), before + 1)
        self.assertNotIn("\n", self.last_event()["body"])

    def test_sanitize_function(self) -> None:
        self.assertEqual(trap.sanitize("a\x1b[2Jb"), "a\\x1b[2Jb")
        self.assertEqual(trap.sanitize("​⁦x"), "\\u200b\\u2066x")
        self.assertEqual(trap.sanitize("olá ✓"), "olá ✓")


class RateLimitTests(ServerTestCase):
    rate_limit = 3

    def test_rate_limit(self) -> None:
        statuses = [self.get("/")[0] for _ in range(6)]
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertEqual(statuses[3:], [429, 429, 429])
        event = self.last_event()
        self.assertTrue(event["flags"]["rate_limited"])
        self.assertNotIn("headers", event)  # short record
        self.assertEqual(event["path"], "/")

    def test_limiter_window_resets(self) -> None:
        limiter = trap.RateLimiter(limit=2, window=0.2)
        self.assertEqual([limiter.allow("a") for _ in range(3)], [True, True, False])
        self.assertTrue(limiter.allow("b"))
        time.sleep(0.25)
        self.assertTrue(limiter.allow("a"))


if __name__ == "__main__":
    unittest.main()
