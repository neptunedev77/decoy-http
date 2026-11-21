"""Build a publishable, anonymised results/ folder from decoy-http logs.

Usage:
    python export_results.py --region "West Europe"
    python export_results.py path/to/logs --out results --sample 50

Outputs:
    results/summary.json  aggregated statistics + session metadata
    results/sample.jsonl  a small sample of requests

Guarantees: no full IP address ends up in results/ (source IPs are masked and
any IP inside paths, payloads or user-agents is masked too), no full headers,
payloads truncated to 300 characters, URLs defanged.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyze import INTERESTING, compute_stats, defang, find_log_files, load_events
from trap import sanitize

TEXT_LIMIT = 300

_IPV4_RE = re.compile(r"(?<!\d)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d])")
_IPV6_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*")


def mask_ip(ip: str) -> str:
    """203.0.113.57 -> 203.0.x.x ; 2001:db8:1:2::5 -> 2001:db8:x:x:x:x:x:x"""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return "x.x.x.x"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv4Address):
        a, b, _, _ = str(addr).split(".")
        return f"{a}.{b}.x.x"
    groups = addr.exploded.split(":")
    return ":".join(g.lstrip("0") or "0" for g in groups[:2]) + ":x:x:x:x:x:x"


def _mask_ipv6_token(m: re.Match[str]) -> str:
    token = m.group(0)
    for candidate in (token, token.strip(":.")):
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        return token.replace(candidate, mask_ip(candidate))
    return token  # e.g. a time like "15:36:24", not an address


def mask_ips_in_text(text: str) -> str:
    text = _IPV4_RE.sub(lambda m: f"{m.group(1)}.{m.group(2)}.x.x", text)
    return _IPV6_CANDIDATE_RE.sub(_mask_ipv6_token, text)


def clean(value: Any, limit: int = TEXT_LIMIT) -> str:
    """Attacker text -> sanitised, IP-masked, truncated, defanged."""
    text = mask_ips_in_text(sanitize(str(value)))
    if len(text) > limit:
        text = text[:limit] + "..."
    return defang(text)


def _top(counter: Counter[str], n: int) -> list[dict[str, Any]]:
    return [{"value": clean(v, 200), "count": c} for v, c in counter.most_common(n)]


def build_summary(events: list[dict[str, Any]], region: str, name: str, top: int) -> dict[str, Any]:
    stats = compute_stats(events)
    prefixes = Counter(mask_ip(e.get("src_ip", "")) for e in events)
    return {
        "session": {
            "name": name,
            "region": region,
            "date": stats["first"][:10] if stats["first"] else None,
            "start_utc": stats["first"],
            "end_utc": stats["last"],
            "duration_minutes": round(stats["duration_seconds"] / 60, 1),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "totals": {
            "requests": stats["total"],
            "unique_source_ips": stats["unique_ips"],  # a count only
            "flags": stats["flags"],
        },
        "categories": dict(stats["categories"].most_common()),
        "methods": dict(stats["methods"].most_common()),
        "status_codes": dict(stats["statuses"].most_common()),
        "top_paths": _top(stats["paths"], top),
        "top_user_agents": _top(stats["user_agents"], top),
        "top_source_prefixes": [{"prefix": p, "count": c} for p, c in prefixes.most_common(top)],
        f"requests_per_{stats['timeline_unit']}": dict(sorted(stats["timeline"].items())),
    }


def sample_record(e: dict[str, Any]) -> dict[str, Any]:
    if e.get("body_encoding") == "base64":
        body = f"<binary body, {e.get('body_logged_bytes', 0)} bytes>"
    else:
        body = clean(e.get("body", ""))
    return {
        "ts": clean(e.get("ts", ""), 40),
        "src": mask_ip(e.get("src_ip", "")),
        "method": clean(e.get("method", "-"), 40),
        "path": clean(e.get("path", e.get("request_line", ""))),
        "query": clean(e.get("query_raw", "")),
        "body": body,
        "user_agent": clean(e.get("user_agent", "")),
        "categories": [clean(c, 40) for c in e.get("categories", [])],
        "status": e.get("status"),
        "flags": sorted(clean(k, 40) for k, v in e.get("flags", {}).items() if v),
    }


def choose_sample(events: list[dict[str, Any]], size: int, seed: int = 1) -> list[dict[str, Any]]:
    """A few examples of every category first, then random fill (deterministic)."""
    rng = random.Random(seed)
    chosen: list[int] = []
    by_cat: dict[str, list[int]] = {}
    for i, e in enumerate(events):
        for c in e.get("categories", []):
            by_cat.setdefault(c, []).append(i)
    per_cat = 3 if size >= 3 * len(by_cat) else 1
    for cat in sorted(by_cat, key=lambda c: (c not in INTERESTING, c)):
        for i in rng.sample(by_cat[cat], min(per_cat, len(by_cat[cat]))):
            if i not in chosen and len(chosen) < size:
                chosen.append(i)
    taken = set(chosen)
    rest = [i for i in range(len(events)) if i not in taken]
    chosen += rng.sample(rest, min(size - len(chosen), len(rest)))
    return [events[i] for i in sorted(chosen)]


def _final_check(text: str) -> str:
    # Belt and braces: mask anything that still looks like an IP address.
    return mask_ips_in_text(text)


def export(inputs: list[str], out_dir: Path, region: str, name: str, sample_size: int, top: int) -> None:
    events = list(load_events(inputs))
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = build_summary(events, region, name, top)
    (out_dir / "summary.json").write_text(
        _final_check(json.dumps(summary, indent=2, ensure_ascii=False)) + "\n", encoding="utf-8"
    )
    lines = [json.dumps(sample_record(e), ensure_ascii=False) for e in choose_sample(events, sample_size)]
    (out_dir / "sample.jsonl").write_text(
        "".join(_final_check(line) + "\n" for line in lines), encoding="utf-8"
    )
    print(f"wrote {out_dir / 'summary.json'} and {out_dir / 'sample.jsonl'} "
          f"({len(events)} events, {len(lines)} sampled)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export anonymised results")
    parser.add_argument("inputs", nargs="*", default=["logs"], help="log folder or .jsonl files")
    parser.add_argument("--out", default="results", help="output folder (default: results)")
    parser.add_argument("--region", default="unknown", help="Azure region of the session")
    parser.add_argument("--name", default="Session 1", help="session name")
    parser.add_argument("--sample", type=int, default=50, help="number of sampled requests")
    parser.add_argument("--top", type=int, default=20, help="rows per top-N list")
    args = parser.parse_args(argv)

    if not find_log_files(args.inputs):
        print("no log files found", file=sys.stderr)
        return 1
    export(args.inputs, Path(args.out), args.region, args.name, args.sample, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
