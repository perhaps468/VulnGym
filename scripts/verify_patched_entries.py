#!/usr/bin/env python3
"""Verify the five rewritten entries satisfy the VulnGym schema.

Loads data/entries.jsonl, checks that the targeted entries (entry-00185,
entry-00197, entry-00290, entry-00320, entry-00391) each have well-formed
entry_point, critical_operation, and a non-empty trace whose nodes each
contain (file, line, code) triples.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ENTRIES_PATH = Path(__file__).resolve().parent.parent / "data" / "entries.jsonl"
TARGETED = ("entry-00185", "entry-00197", "entry-00290", "entry-00320", "entry-00391")


def main() -> int:
    found: dict[str, dict] = {}
    with ENTRIES_PATH.open("r", encoding="utf-8") as src:
        for raw in src:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("entry_id") in TARGETED:
                found[obj["entry_id"]] = obj

    missing = [eid for eid in TARGETED if eid not in found]
    if missing:
        print(f"missing entries: {missing}", file=sys.stderr)
        return 1

    failures = 0
    for eid in TARGETED:
        entry = found[eid]
        for key in ("entry_point", "critical_operation"):
            node = entry.get(key) or {}
            missing_keys = [k for k in ("file", "line", "code") if not node.get(k)]
            if missing_keys:
                print(f"{eid}: {key} missing {missing_keys}", file=sys.stderr)
                failures += 1
            if not (node.get("desc") or "").strip():
                print(f"{eid}: {key} missing desc", file=sys.stderr)
                failures += 1

        trace = entry.get("trace") or []
        if not trace:
            print(f"{eid}: empty trace", file=sys.stderr)
            failures += 1
        for idx, node in enumerate(trace):
            missing_keys = [k for k in ("file", "line", "code") if not node.get(k)]
            if missing_keys:
                print(f"{eid}: trace[{idx}] missing {missing_keys}", file=sys.stderr)
                failures += 1
            if not (node.get("desc") or "").strip():
                print(f"{eid}: trace[{idx}] missing desc", file=sys.stderr)
                failures += 1

        print(
            f"ok {eid} commit={entry.get('commit')[:8]} "
            f"entry_point={entry['entry_point']['file']}:{entry['entry_point']['line']} "
            f"critical={entry['critical_operation']['file']}:{entry['critical_operation']['line']} "
            f"trace_nodes={len(trace)} verify={entry.get('verify')}"
        )

    if failures:
        print(f"{failures} schema failures", file=sys.stderr)
        return 1
    print("all 5 entries match schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
