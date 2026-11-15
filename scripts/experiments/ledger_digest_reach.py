"""周期注入变体的触达率：有没有一条 run 在中途就已有「可指名的活候选」。

v1（只认 route_map、只挂在收工拒绝）在历史拒收里只有 7% 能说话。这个脚本回答
另一个问题：如果改成每 K 次调用注入一次，**有多少 run 至少会说一次**，
以及第一次可说话出现在第几次调用。

仍然只用同族已活的候选（精度优先），来源放宽到所有工具输出。
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
    wide: set[str] = set()
    first_hit = 0
    hit_calls = 0
    for index, (name, args, out) in enumerate(calls, 1):
        if name != "finish_scan":
            for tok in PATH_TOKEN.findall(out or ""):
                p = _norm(tok)
                if _acceptable(p):
                    wide.add(p)
        ledger.observe(name, args, out)
        fams = {
            _family(q)
            for (_m, q), (status, _s, _c) in ledger.probes.items()
            if status < 400
        }
        untried = [p for p in wide if p not in ledger.requested and _family(p) in fams]
        if untried:
            hit_calls += 1
            if not first_hit:
                first_hit = index
    rows.append((d.name, solved, len(calls), first_hit, hit_calls))

failed = [r for r in rows if not r[1]]
solved = [r for r in rows if r[1]]
for tag, grp in (("failed", failed), ("solved", solved)):
    if not grp:
        continue
    with_hit = [r for r in grp if r[3]]
    print(
        f"{tag:7} runs={len(grp):3} with >=1 inertable call={len(with_hit):3} "
        f"({100 * len(with_hit) / len(grp):.0f}%)"
    )
    if with_hit:
        firsts = sorted(r[3] for r in with_hit)
        counts = sorted(r[4] for r in with_hit)
        print(
            f"        first hit call p50={firsts[len(firsts) // 2]} "
            f"p90={firsts[int(len(firsts) * 0.9)]} | hit calls p50={counts[len(counts) // 2]} "
            f"p90={counts[int(len(counts) * 0.9)]}"
        )
print("\nfailed runs with the most inertable calls:")
for name, _s, total, first, hits in sorted(failed, key=lambda x: -x[4])[:10]:
    print(f"  {name:44} calls={total:3} first={first:3} hit_calls={hits:3}")