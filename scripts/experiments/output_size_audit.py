"""Output size distribution + other truncation markers.

Caps come from vendor settings: 2,000 lines / 50 KiB per tool result.
Measured 11-15: p50 550 B, p99 16.7 KB, max 51,039 B, zero outputs over 50 KiB
-- the bound never fires on this population (docs/32 §9.4)."""
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

ROOTS = [Path("/home/rjq/runs"), Path("/var/tmp/ctfbox")]
MARKERS = {
    "ansi_or_headc": re.compile(r"head -c|\[\.\.\. omitted|output truncated|\.\.\.\(truncated", re.I),
    "chunked": re.compile(r"Chunk ID:"),
    "truncated_notice": re.compile(r"lines \(.*?bytes\) truncated"),
}
seen, dirs = set(), []
for root in ROOTS:
    for d in sorted(root.glob("2026*")):
        if d.is_dir() and d.name not in seen:
            seen.add(d.name)
            dirs.append(d)


def load_calls(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        items = con.execute("select message_data from agent_messages order by id").fetchall()
    finally:
        con.close()
    pending, calls = {}, []
    for (raw,) in items:
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "function_call":
            pending[obj.get("call_id")] = (obj.get("name") or "", obj.get("arguments") or "")
        elif obj.get("type") == "function_call_output" and obj.get("call_id") in pending:
            pending.pop(obj["call_id"])
            out = obj.get("output")
            if not isinstance(out, str):
                out = json.dumps(out, ensure_ascii=False) if out is not None else ""
            calls.append(out)
    return calls


sizes = []
by_tool_max = Counter()
over10k = over50k = 0
markers = Counter()
total = 0
for d in dirs:
    dbs = list(d.glob("strix_runs/*/.state/agents.db"))
    if not dbs:
        continue
    try:
        outs = load_calls(dbs[0])
    except Exception:
        continue
    for o in outs:
        n = len(o.encode("utf-8", errors="replace"))
        sizes.append(n)
        total += n
        if n > 10_000:
            over10k += 1
        if n > 50 * 1024:
            over50k += 1
        for k, rx in MARKERS.items():
            if rx.search(o):
                markers[k] += 1

sizes.sort()
if sizes:
    def pct(p):
        return sizes[min(len(sizes) - 1, int(len(sizes) * p))]
    print(f"outputs={len(sizes)} total={total/1e6:.1f}MB")
    print(f"p50={pct(.5)} p90={pct(.9)} p99={pct(.99)} max={sizes[-1]}")
    print(f">10KB: {over10k}  >50KB: {over50k}")
print("markers:", dict(markers))