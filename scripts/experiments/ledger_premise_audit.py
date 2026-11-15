"""Ledger premise audit: of the routes route_map PATHED, how many were never
requested afterwards?

The fact/intent ledger may only re-surface entries that come from a
structured source (route_map candidate lines), not from free-text body
tokens -- the earlier intent audit (p50 51 unexplored) was dominated by
bundle prose and IPs.  This measures the precise payload the ledger would
carry, and whether the run that received it acted on it.
"""
import json
import re
import sqlite3
from pathlib import Path

ROOTS = [Path("/home/rjq/runs"), Path("/var/tmp/ctfbox")]
HTTP_TOOLS = {"http_probe", "method_sweep", "path_variants", "route_map",
              "traffic_view", "traffic_list"}
CAND = re.compile(r"^\s*(?:\d+\.\s+|\?\s+)(/[A-Za-z0-9_][A-Za-z0-9_\-./]*)", re.M)
REQ = re.compile(r"https?://[^\s\"'`]+")
SHELL_PATH = re.compile(r"[\"'](/[A-Za-z0-9_][A-Za-z0-9_\-./]{2,})[\"']")


def norm(u):
    u = u.split("?")[0].split("#")[0].rstrip("/.")
    return u or "/"


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


def requested_of(nm, ar):
    got = set()
    for u in REQ.findall(ar):
        got.add(norm(u))
    for p in SHELL_PATH.findall(ar):
        got.add(norm(p))
    if nm in HTTP_TOOLS:
        try:
            obj = json.loads(ar)
        except Exception:
            obj = {}
        for k in ("url", "base_url", "urls", "paths"):
            v = obj.get(k)
            if isinstance(v, str):
                for tok in re.split(r"[\s,]+", v):
                    if tok.startswith("/") or tok.startswith("http"):
                        got.add(norm(tok))
    return got


seen, dirs = set(), []
for root in ROOTS:
    for d in sorted(root.glob("2026*")):
        if d.is_dir() and d.name not in seen:
            seen.add(d.name)
            dirs.append(d)

rows = []
for d in dirs:
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

    # candidates from route_map outputs, with the call index at which they appeared
    cand_at = {}
    for i, (nm, ar, out) in enumerate(calls):
        if nm != "route_map":
            continue
        for p in CAND.findall(out):
            p = norm(p)
            if p.count("/") < 1:
                continue
            cand_at.setdefault(p, i)
    if not cand_at:
        continue
    # requests, by call index
    req_after = {p: [] for p in cand_at}
    for i, (nm, ar, out) in enumerate(calls):
        for p in requested_of(nm, ar):
            if p in req_after:
                req_after[p].append(i)
    never = [p for p in cand_at if not req_after[p]]
    # of the never-requested, how many appeared with >= 3 calls left to act
    actionable = [p for p in never if len(calls) - cand_at[p] >= 3]
    rows.append((d.name, solved, len(calls), len(cand_at), len(never),
                 len(actionable), sorted(never)[:5]))

print(f"runs_with_route_map={len(rows)}")
sol = [r for r in rows if r[1]]
fail = [r for r in rows if not r[1]]
for name, grp in (("solved", sol), ("failed", fail)):
    if not grp:
        continue
    nv = sorted(r[4] for r in grp)
    ac = sorted(r[5] for r in grp)
    print(f"{name:7} n={len(grp):3} never-req p50={nv[len(nv)//2]:3} p90={nv[int(len(nv)*0.9)]:3} "
          f"max={nv[-1]:3} | actionable p50={ac[len(ac)//2]:3} "
          f"runs>0={sum(1 for v in ac if v > 0)}")
print("\nfailed runs with most actionable candidates:")
for r in sorted(fail, key=lambda x: -x[5])[:10]:
    print(f"  {r[0]:42} calls={r[2]:3} cand={r[3]:3} never={r[4]:3} actionable={r[5]:3} e.g. {r[6][:4]}")