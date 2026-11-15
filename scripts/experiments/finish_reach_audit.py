"""How often do failed runs reach finish_scan at all?

The finish-time ledger is only visible if the run calls finish_scan and gets
refused.  Runs that exhaust their turn budget never see it, so their share
bounds the mechanism's ceiling -- and decides whether a periodic digest is
needed as a second channel.
"""
import json
import re
import sqlite3
from pathlib import Path

ROOTS = [Path("/home/rjq/runs"), Path("/var/tmp/ctfbox")]
CUT = "2026-11-07"


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
            nm, ar = pending.pop(obj["call_id"])
            out = obj.get("output")
            if not isinstance(out, str):
                out = json.dumps(out, ensure_ascii=False) if out is not None else ""
            calls.append((nm, ar, out))
    return calls


seen, dirs = set(), []
for root in ROOTS:
    for d in sorted(root.glob("2026*")):
        if d.is_dir() and d.name not in seen:
            seen.add(d.name)
            dirs.append(d)

stats = {"failed": 0, "failed_finish": 0, "failed_refused": 0,
         "solved": 0, "solved_finish": 0}
by_band = {}
for d in dirs:
    day = d.name[:10]
    day = f"{day[:4]}-{day[4:6]}-{day[6:8]}"
    dbs = list(d.glob("strix_runs/*/.state/agents.db"))
    if not dbs:
        continue
    try:
        calls = load_calls(dbs[0])
    except Exception:
        continue
    if len(calls) < 5:
        continue
    log = d / "run.log"
    log_text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    solved = ("ACCEPTED:" in "\n".join(c[2] for c in calls)) or bool(re.search(r"\bSOLVED\b", log_text))
    fin = [c for c in calls if c[0] == "finish_scan"]
    refused = any(("REFUSED" in c[2]) or ('"success": false' in c[2].lower()) for c in fin)
    key = "solved" if solved else "failed"
    stats[key] += 1
    if fin:
        stats[f"{key}_finish"] += 1
    if refused:
        stats["failed_refused" if not solved else "solved_refused"] = stats.get(
            "failed_refused" if not solved else "solved_refused", 0) + 1
    band = "pre-11-07" if day < CUT else "11-07+"
    b = by_band.setdefault(band, {"failed": 0, "failed_finish": 0, "failed_refused": 0,
                                  "solved": 0, "solved_finish": 0})
    b[key] += 1
    if fin:
        b[f"{key}_finish"] += 1
    if refused and not solved:
        b["failed_refused"] += 1

for band in ("pre-11-07", "11-07+", "ALL"):
    b = stats if band == "ALL" else by_band.get(band, {})
    if not b:
        continue
    f, ff, fr = b["failed"], b["failed_finish"], b["failed_refused"]
    s, sf = b["solved"], b["solved_finish"]
    print(f"{band:10} failed={f:3} reached_finish={ff:3} ({100*ff/max(f,1):.0f}%) "
          f"refused={fr:3} ({100*fr/max(f,1):.0f}%) | solved={s:3} reached_finish={sf:3}")