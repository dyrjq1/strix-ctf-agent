"""Precision check for the ledger's candidate list.

For every untouched route_map candidate, decide whether its path family is
known-alive in that same run:

  alive  -- a sibling path (same first two segments) appeared in a
            method_sweep output (404s are dropped there, so presence means
            non-404) or in an http_probe line with status < 400
  dead   -- only siblings with 4xx were ever probed
  unprobed -- no sibling was probed at all

A ledger that names dead-family candidates sends the agent into a ditch, so
the live-entry count is the number that matters.
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
PROBE_LINE = re.compile(r"(?<![\w.])([1-5]\d{2})(?![\w.])[^\n]{0,80}?(/[A-Za-z0-9_][A-Za-z0-9_\-./]*)")
URL_PATH = re.compile(r"https?://[^\s\"'`]+?(/[A-Za-z0-9_][A-Za-z0-9_\-./]*)")
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


def family(p):
    segs = [s for s in p.split("/") if s]
    return "/" + "/".join(segs[:2])


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

tot = {"alive": 0, "dead": 0, "unprobed": 0}
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
    log = d / "run.log"
    log_text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    if ("ACCEPTED:" in "\n".join(c[2] for c in calls)) or re.search(r"\bSOLVED\b", log_text):
        continue

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
    requested = set()
    for nm, ar, _ in calls:
        requested |= requested_of(nm, ar)
    untouched = [p for p in cand_at if p not in requested]
    if not untouched:
        continue

    # status knowledge: family -> alive / dead
    fam = {}
    for nm, ar, out in calls:
        if nm == "method_sweep":
            for p in URL_PATH.findall(out) + re.findall(r"(/[A-Za-z0-9_][A-Za-z0-9_\-./]{3,})", out):
                p = norm(p)
                if functional(p):
                    fam[family(p)] = 1
        elif nm in ("http_probe", "path_variants"):
            for status, path in PROBE_LINE.findall(out):
                p = norm(path)
                if not functional(p):
                    continue
                f = family(p)
                if int(status) < 400:
                    fam[f] = 1
                else:
                    fam.setdefault(f, 0)
    counts = {"alive": 0, "dead": 0, "unprobed": 0}
    for p in untouched:
        k = fam.get(family(p))
        counts["alive" if k == 1 else ("dead" if k == 0 else "unprobed")] += 1
    for k in tot:
        tot[k] += counts[k]
    per_run.append((d.name, len(untouched), counts))

print(f"11-07+ failed runs with untouched candidates: {len(per_run)}")
print(f"untouched candidates total={sum(tot.values())} alive={tot['alive']} "
      f"dead={tot['dead']} unprobed={tot['unprobed']}")
if per_run:
    alive_runs = [r for r in per_run if r[2]["alive"] > 0]
    print(f"runs with >=1 alive untouched: {len(alive_runs)}")
    for name, n, c in sorted(per_run, key=lambda x: -x[2]["alive"])[:12]:
        print(f"  {name:44} untouched={n:2} alive={c['alive']:2} dead={c['dead']:2} unprobed={c['unprobed']:2}")