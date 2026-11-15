"""Exact replay of today's 40 A/B runs through the shipped guard.

The A/B reported that the hint fired zero times.  Two very different worlds
produce that number: the runs genuinely never repeated a shape six times in a
row (the change is inert on this population), or the wiring is broken and the
counter never saw what it should have.  The run's own agents.db holds exactly
the inputs the guard received, so replaying it through the real guard separates
the two -- and it costs zero tokens and touches no target.
"""
import json
import os
import sqlite3
import re
import sys
from pathlib import Path

os.environ["CTF_STRUCT_SIG"] = "1"  # the treatment arm's setting
sys.path.insert(0, "/home/rjq/work/strix-ctf-agent/src")

from ctf_strix import enum_guard  # noqa: E402

SUFFIX = re.compile(r"\| stall: max=(\d+) hits=(\d+) class_max=(\d+) class_hits=(\d+)")
RUNS = Path("/home/rjq/runs")

rows = []
for run_dir in sorted(RUNS.glob("20261115-*")):
    dbs = list(run_dir.glob("strix_runs/*/.state/agents.db"))
    if not dbs:
        continue
    con = sqlite3.connect(f"file:{dbs[0]}?mode=ro", uri=True)
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
            name, args = pending.pop(obj["call_id"])
            out = obj.get("output")
            if not isinstance(out, str):
                out = json.dumps(out, ensure_ascii=False) if out is not None else ""
            calls.append((name, args, out))
    if not calls:
        continue

    guard = enum_guard.EnumerationGuard()
    for name, args, out in calls:
        guard.observe(name, args, out)

    printed = None
    log = run_dir / "run.log"
    if log.exists():
        found = SUFFIX.search(log.read_text(encoding="utf-8", errors="replace"))
        if found:
            printed = tuple(map(int, found.groups()))
    rows.append((run_dir.name, len(calls), guard.max_stall, guard.stall_hits,
                 guard.max_class_streak, guard.class_hits, printed))

print(f"{'run':44} {'calls':>5} {'replay_max':>10} {'hits':>4} {'cls_max':>7} {'cls_hit':>7}  printed")
for name, calls, peak, hits, cpk, chits, printed in rows:
    shown = "-" if printed is None else f"max={printed[0]} hits={printed[1]}"
    print(f"{name:44} {calls:5} {peak:10} {hits:4} {cpk:7} {chits:7}  {shown}")

peaks = [r[2] for r in rows]
print(f"\nruns={len(rows)}  replay max stall over runs={max(peaks) if peaks else 0}  "
      f"runs reaching {enum_guard._STALL_AFTER}: {sum(1 for p in peaks if p >= enum_guard._STALL_AFTER)}")
agree = sum(1 for r in rows if r[6] is not None and r[6][0] == r[2])
checked = sum(1 for r in rows if r[6] is not None)
print(f"printed == replays (where a line exists): {agree}/{checked}")