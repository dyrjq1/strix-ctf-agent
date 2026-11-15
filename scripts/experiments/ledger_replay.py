"""零 token 仪表预检：把历史 run 的 item 流逐条喂给真的 FactLedger。

判据（docs/32 §11.5）要求实验臂被拒收的 finish 至少 80% 带非空台账。
在花任何 token 之前，先用同分布的历史总体回答：**如果这个台账当时就在，
它会说什么、说几次**。S2 的教训是判据通过但机制零触发，所以这一步先跑。

用法（VM）::

    PYTHONPATH=/home/rjq/work/strix-ctf-agent/src python3 ledger_replay.py
"""

import json
import re
import sqlite3
import sys
from pathlib import Path

ROOTS = [Path("/home/rjq/runs"), Path("/var/tmp/ctfbox")]
CUT = "2026-11-07"

sys.path.insert(0, "/home/rjq/work/strix-ctf-agent/src")
from ctf_strix.fact_ledger import FactLedger  # noqa: E402


def load_calls(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        items = con.execute(
            "select message_data from agent_messages order by id"
        ).fetchall()
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
            pending[obj.get("call_id")] = (
                obj.get("name") or "",
                obj.get("arguments") or "",
            )
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

rows = []
for d in dirs:
    day = d.name[:10]
    day = f"{day[:4]}-{day[4:6]}-{day[6:8]}"
    if day < CUT:
        continue
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
    solved = ("ACCEPTED:" in "\n".join(c[2] for c in calls)) or bool(
        re.search(r"\bSOLVED\b", log_text)
    )
    ledger = FactLedger()
    refused = 0
    with_ledger = 0
    lines_max = 0
    samples = []
    for name, args, out in calls:
        if name == "finish_scan":
            refused_now = ("REFUSED" in out) or ('"success": false' in out.lower())
            if refused_now:
                refused += 1
                text = ledger.render()
                if text:
                    with_ledger += 1
                    lines_max = max(lines_max, len(text.splitlines()))
                    if len(samples) < 1:
                        samples.append(text)
        ledger.observe(name, args, out)
    if refused:
        rows.append((d.name, solved, refused, with_ledger, lines_max, samples))

print(f"11-07+ runs with >=1 refused finish: {len(rows)}")
tot_ref = sum(r[2] for r in rows)
tot_with = sum(r[3] for r in rows)
print(
    f"refused finishes={tot_ref} carrying a non-empty ledger={tot_with} "
    f"({100 * tot_with / max(tot_ref, 1):.0f}%)"
)
runs_with = sum(1 for r in rows if r[3])
print(f"runs whose refusal would name at least one entry: {runs_with}/{len(rows)}")
for tag, sel in (("solved", True), ("failed", False)):
    grp = [r for r in rows if r[1] is sel]
    if not grp:
        continue
    ref = sum(r[2] for r in grp)
    wit = sum(r[3] for r in grp)
    print(
        f"  {tag:6} runs={len(grp):3} refusals={ref:3} non-empty={wit:3} "
        f"({100 * wit / max(ref, 1):.0f}%) runs>0={sum(1 for r in grp if r[3]):3}"
    )
print("\nlongest sample:")
for r in sorted(rows, key=lambda x: -x[4])[:3]:
    if r[5]:
        print(f"--- {r[0]} lines={r[4]} refusals={r[2]} non-empty={r[3]}")
        print(r[5][0])