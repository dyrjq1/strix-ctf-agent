"""Refined ledger premise: restrict to functional API-looking candidates.

Round 1 showed raw route_map candidates do not separate solved from failed
(solved p50=4 never-requested vs failed p50=3) because both lists are full of
framework noise (/_next, /_tree, /a/b, /a/i).  This pass keeps only paths that
look like real endpoints and also records whether the run ever called
method_sweep -- the action route_map itself prescribes.
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
NOISE = re.compile(r"^/_(?:next|nuxt|tree|app|document|layout)", re.I)
NOISE_EQ = {"/a/b", "/a/i", "/a", "/b"}
STATIC = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webmanifest)$", re.I)


def norm(u):
    u = u.split("?")[0].split("#")[0].rstrip("/.")
    return u or "/"


def functional(p):
    if p in NOISE_EQ or NOISE.search(p):
        return False
    if STATIC.search(p) or "{" in p or "}" in p or ":" in p:
        return False
    if p.count("/") < 2:          # need at least /a/b
        return False
    return True


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

    cand_at = {}
    for i, (nm, ar, out) in enumerate(calls):
        if nm != "route_map":
            continue
        for p in CAND.findall(out):
            p = norm(p)
            if functional(p):
                cand_at.setdefault(p, i)
    if not cand_at:
        continue
    req_after = {p: [] for p in cand_at}
    for i, (nm, ar, out) in enumerate(calls):
        for p in requested_of(nm, ar):
            if p in req_after:
                req_after[p].append(i)
    never = [p for p in cand_at if not req_after[p]]
    actionable = [p for p in never if len(calls) - cand_at[p] >= 3]
    swept = any(nm == "method_sweep" for nm, _, _ in calls)
    sweep_after_map = False
    first_map = min(cand_at.values())
    if swept:
        sweep_after_map = any(nm == "method_sweep" for nm, _, _ in calls[first_map + 1:])
    rows.append((d.name, solved, len(calls), len(cand_at), len(never),
                 len(actionable), sweep_after_map, sorted(never)[:4]))

print(f"runs_with_functional_candidates={len(rows)}")
for name, grp in (("solved", [r for r in rows if r[1]]),
                  ("failed", [r for r in rows if not r[1]])):
    if not grp:
        continue
    nv = sorted(r[4] for r in grp)
    ac = sorted(r[5] for r in grp)
    swept = sum(1 for r in grp if r[6])
    print(f"{name:7} n={len(grp):3} cand p50={sorted(r[3] for r in grp)[len(grp)//2]:3} "
          f"never p50={nv[len(nv)//2]:3} p90={nv[int(len(nv)*0.9)]:3} max={nv[-1]:3} | "
          f"actionable p50={ac[len(ac)//2]:2} runs>3={sum(1 for v in ac if v > 3):3} | "
          f"method_sweep_after_map={swept}/{len(grp)}")

print("\nfailed runs, most actionable functional candidates:")
for r in sorted([r for r in rows if not r[1]], key=lambda x: -x[5])[:10]:
    print(f"  {r[0]:42} calls={r[2]:3} cand={r[3]:2} never={r[4]:2} act={r[5]:2} "
          f"sweep={int(r[6])} e.g. {r[7][:3]}")