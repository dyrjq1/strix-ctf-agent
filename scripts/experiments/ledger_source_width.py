"""台账来源宽度：只认 route_map vs 认所有工具输出（仅同族已活）。

`ledger_replay.py` 显示 v1（只认 route_map 候选）在历史拒收里只有 7% 能指名
条目——机制对这批总体太窄。这个脚本量一个放宽变体：候选来自**任何工具输出**
里的路由形态 token，但只保留「同族已经有过 <400 响应」的条目（精度优先）。

若放宽后仍低，整条线就地作废；若明显变高，把新规则重新预注册后再做 A/B。
"""

import json
import re
import sqlite3
import sys
from pathlib import Path

ROOTS = [Path("/home/rjq/runs"), Path("/var/tmp/ctfbox")]
CUT = "2026-11-07"

sys.path.insert(0, "/home/rjq/work/strix-ctf-agent/src")
from ctf_strix.fact_ledger import (  # noqa: E402
    FactLedger,
    _acceptable,
    _family,
    _norm,
)

PATH_TOKEN = re.compile(r"(?<![\w.])/[A-Za-z0-9_][A-Za-z0-9_\-./]{2,}")


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


def alive_families(ledger: FactLedger) -> set[str]:
    fams = set()
    for (_method, path), (status, _size, _ctype) in ledger.probes.items():
        if status < 400:
            fams.add(_family(path))
    return fams


seen, dirs = set(), []
for root in ROOTS:
    for d in sorted(root.glob("2026*")):
        if d.is_dir() and d.name not in seen:
            seen.add(d.name)
            dirs.append(d)

stats = {"v1": [0, 0], "wide": [0, 0]}
per_run = []
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
    ledger = FactLedger()
    wide_seen: set[str] = set()
    refusals = v1_hit = wide_hit = 0
    for name, args, out in calls:
        if name == "finish_scan" and (("REFUSED" in out) or ('"success": false' in out.lower())):
            refusals += 1
            if ledger.render():
                v1_hit += 1
                stats["v1"][1] += 1
            stats["v1"][0] += 1
            fams = alive_families(ledger)
            untried = [
                p
                for p in wide_seen
                if p not in ledger.requested and _family(p) in fams
            ]
            if untried:
                wide_hit += 1
                stats["wide"][1] += 1
            stats["wide"][0] += 1
        if name != "finish_scan":
            for tok in PATH_TOKEN.findall(out or ""):
                p = _norm(tok)
                if _acceptable(p):
                    wide_seen.add(p)
        ledger.observe(name, args, out)
    if refusals:
        per_run.append((d.name, refusals, v1_hit, wide_hit))

print(f"runs with refused finishes: {len(per_run)}")
for tag, key in (("route_map-only", "v1"), ("wide+alive-family", "wide")):
    total, hit = stats[key]
    runs_hit = sum(1 for r in per_run if r[2 if key == "v1" else 3] > 0)
    print(
        f"{tag:20} refusals={total:3} non-empty={hit:3} "
        f"({100 * hit / max(total, 1):.0f}%) runs>0={runs_hit}/{len(per_run)}"
    )
print("\nwidest runs (wide variant):")
for name, ref, v1, wide in sorted(per_run, key=lambda x: -x[3])[:10]:
    print(f"  {name:44} refusals={ref:2} v1={v1:2} wide={wide:2}")