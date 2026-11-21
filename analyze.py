"""Print statistics from decoy-http logs.

Usage:
    python analyze.py                  # reads logs/requests.jsonl*
    python analyze.py path/to/logs     # a folder or specific .jsonl files

Everything in the logs is attacker-controlled. It is treated as inert text:
sanitised before printing, URLs defanged, and nothing is ever fetched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from trap import sanitize

INTERESTING = (
    "command-injection",
    "log4shell",
    "shellshock",
    "sqli-attempt",
    "path-traversal",
    "router-iot-exploit",
    "proxy-attempt",
)

_URL_RE = re.compile(r"(?i)\b(h(?:tt|xx)ps?|s?ftp|tftp|ldaps?|rmi|dns)://([^\s/'\"<>`]+)")


def defang(text: str) -> str:
    """http://evil.example/x -> hxxp://evil[.]example/x (not clickable)."""

    def repl(m: re.Match[str]) -> str:
        scheme = re.sub(r"(?i)^http", "hxxp", m.group(1))
        return f"{scheme}://{m.group(2).replace('.', '[.]')}"

    return _URL_RE.sub(repl, text)


def safe(value: Any, limit: int = 200) -> str:
    """Sanitised, defanged, truncated text for display."""
    text = sanitize(str(value))
    if len(text) > limit:
        text = text[:limit] + "..."
    return defang(text)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def _rotation_order(path: Path) -> int:
    # requests.jsonl.9 is the oldest, requests.jsonl the newest.
    suffix = path.name.rsplit(".", 1)[-1]
    return -int(suffix) if suffix.isdigit() else 0


def find_log_files(inputs: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            files += sorted(p.glob("requests.jsonl*"), key=_rotation_order)
        elif p.is_file():
            files.append(p)
    return files


def load_events(inputs: Iterable[str]) -> Iterator[dict[str, Any]]:
    for path in find_log_files(inputs):
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict) and "ts" in event:
                    yield event


def parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------
# Statistics (shared with export_results.py)
# --------------------------------------------------------------------------


def compute_stats(events: list[dict[str, Any]]) -> dict[str, Any]:
    times = [t for t in (parse_ts(e.get("ts", "")) for e in events) if t]
    span = (max(times) - min(times)).total_seconds() if times else 0.0
    bucket_fmt = "%Y-%m-%d %H:%M" if span <= 3 * 3600 else "%Y-%m-%d %H:00"
    flag_counts: Counter[str] = Counter()
    for e in events:
        flag_counts.update(k for k, v in e.get("flags", {}).items() if v)
    return {
        "total": len(events),
        "unique_ips": len({e.get("src_ip") for e in events}),
        "first": min(times).isoformat() if times else None,
        "last": max(times).isoformat() if times else None,
        "duration_seconds": round(span),
        "flags": dict(flag_counts),
        "categories": Counter(c for e in events for c in e.get("categories", [])),
        "methods": Counter(str(e.get("method", "-")) for e in events),
        "statuses": Counter(str(e.get("status")) for e in events),
        "paths": Counter(str(e.get("path", "")) for e in events if "path" in e),
        "user_agents": Counter(str(e.get("user_agent", "")) for e in events),
        "ips": Counter(str(e.get("src_ip")) for e in events),
        "timeline_unit": "minute" if span <= 3 * 3600 else "hour",
        "timeline": Counter(t.strftime(bucket_fmt) for t in times),
    }


def interesting_payloads(
    events: list[dict[str, Any]], per_category: int = 5
) -> dict[str, list[dict[str, Any]]]:
    """Distinct request examples for each interesting category."""
    out: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for e in events:
        for cat in e.get("categories", []):
            if cat not in INTERESTING:
                continue
            body = e.get("body", "") if e.get("body_encoding") == "utf-8" else ""
            key = (cat, f"{e.get('target', e.get('request_line', ''))}|{body}")
            bucket = out.setdefault(cat, [])
            if key in seen or len(bucket) >= per_category:
                continue
            seen.add(key)
            bucket.append(e)
    return out


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def _print_counter(title: str, counter: Counter[str], top: int, width: int = 90) -> None:
    print(f"\n== {title} ==")
    if not counter:
        print("  (none)")
    for value, n in counter.most_common(top):
        print(f"  {n:6}  {safe(value, width)}")


def _print_timeline(stats: dict[str, Any]) -> None:
    print(f"\n== Requests per {stats['timeline_unit']} (UTC) ==")
    timeline: Counter[str] = stats["timeline"]
    if not timeline:
        print("  (none)")
        return
    peak = max(timeline.values())
    for bucket in sorted(timeline):
        n = timeline[bucket]
        print(f"  {bucket}  {n:6}  {'#' * max(1, round(40 * n / peak))}")


def report(events: list[dict[str, Any]], top: int = 15, payloads: int = 5) -> None:
    stats = compute_stats(events)
    print("== Totals ==")
    print(f"  requests:     {stats['total']}")
    print(f"  unique IPs:   {stats['unique_ips']}")
    print(f"  first / last: {stats['first']}  /  {stats['last']}")
    print(f"  duration:     {stats['duration_seconds'] // 60} min")
    for flag, n in sorted(stats["flags"].items()):
        print(f"  {flag + ':':13} {n}")

    _print_counter("Categories", stats["categories"], 50)
    _print_counter("Methods", stats["methods"], top)
    _print_counter("Status codes", stats["statuses"], top)
    _print_counter("Top paths", stats["paths"], top)
    _print_counter("Top user-agents", stats["user_agents"], top)
    _print_counter("Top source IPs", stats["ips"], top)
    _print_timeline(stats)

    print("\n== Interesting payloads (defanged, never open these) ==")
    found = interesting_payloads(events, payloads)
    if not found:
        print("  (none)")
    for cat, items in found.items():
        print(f"\n-- {cat} --")
        for e in items:
            print(f"  {safe(e.get('ts'), 30)}  {safe(e.get('src_ip'), 40)}")
            print(f"    {safe(e.get('method', '-'), 20)} {safe(e.get('target', e.get('request_line', '')), 300)}")
            if e.get("user_agent"):
                print(f"    UA:   {safe(e['user_agent'], 200)}")
            if e.get("body"):
                body = e["body"] if e.get("body_encoding") == "utf-8" else f"<binary, base64: {e['body'][:60]}...>"
                print(f"    body: {safe(body, 300)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Statistics from decoy-http logs")
    parser.add_argument("inputs", nargs="*", default=["logs"], help="log folder or .jsonl files")
    parser.add_argument("--top", type=int, default=15, help="rows per top-N table")
    parser.add_argument("--payloads", type=int, default=5, help="examples per category")
    args = parser.parse_args(argv)

    if not find_log_files(args.inputs):
        print("no log files found", file=sys.stderr)
        return 1
    report(list(load_events(args.inputs)), args.top, args.payloads)
    return 0


if __name__ == "__main__":
    sys.exit(main())
