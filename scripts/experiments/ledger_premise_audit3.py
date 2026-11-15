"""Same audit, split by date band.

The actionable-candidate signal is concentrated in 2026-10-30/31 runs (old
tool set, 8-20 calls).  The S2 lesson says an offline finding only holds in
the same population, so this prints the same stats for the current-code era
(runs on/after 2026-11-07) to see whether the gap still exists today.
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
CUT = "2026-11-07"


def norm(u):
    u = u.split("?")[0].split("#")[0].rstrip("/.")
    return u or "/"


def functional(p):
    if p in NOISE_EQ or NOISE.search(p):
        return False
    if STATIC.search(p) or "{" in p or "}" in p or ":" in p:
        return False
    return p.count("/") >= 2


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
    day = d.name[:10]
    day = f"{day[:4]}-{day[4:6]}-{day[6:8]}"
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
    first_map = min(cand_at.values())
    sweep_after = any(nm == "method_sweep" for nm, _, _ in calls[first_map + 1:])
    rows.append((d.name, day, solved, len(calls), len(cand_at), len(never),
                 len(actionable), sweep_after))

for band, sel in (("pre-11-07", lambda r: r[1] < CUT),
                  ("11-07+", lambda r: r[1] >= CUT)):
    grp = [r for r in rows if sel(r)]
    print(f"\n=== {band}: runs={len(grp)} solved={sum(1 for r in grp if r[2])}")
    for tag, sub in (("solved", [r for r in grp if r[2]]),
                     ("failed", [r for r in grp if not r[2]])):
        if not sub:
            print(f"  {tag:7} n=0")
            continue
        nv = sorted(r[5] for r in sub)
        ac = sorted(r[6] for r in sub)
        cl = sorted(r[3] for r in sub)
        print(f"  {tag:7} n={len(sub):3} calls p50={cl[len(cl)//2]:3} cand p50={sorted(r[4] for r in sub)[len(sub)//2]:2} "
              f"never p50={nv[len(nv)//2]:2} p90={nv[int(len(nv)*0.9)]:2} max={nv[-1]:2} | "
              f"actionable p50={ac[len(ac)//2]:2} runs>3={sum(1 for v in ac if v > 3):2} | "
              f"sweep-after={sum(1 for r in sub if r[7])}/{len(sub)}")

print("\n11-07+ failed runs, most actionable:")
for r in sorted([r for r in rows if r[1] >= CUT and not r[2]], key=lambda x: -x[6])[:10]:
    print(f"  {r[0]:44} calls={r[3]:3} cand={r[4]:2} never={r[5]:2} act={r[6]:2} sweep={int(r[7])}")