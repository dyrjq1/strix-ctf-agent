"""Same signature sweep, but a shape only counts when the result came from the
target (HTTP status, transport phase, or a real exit code).

Without that gate, two shell listings with the same byte length are "the same
shape" and the hint fires on plain filesystem noise.  This measures how much of
the recall came from those.
"""
import json
import re
import sqlite3
import statistics as st
import sys
from pathlib import Path

sys.path.insert(0, "/home/rjq/work/strix-ctf-agent/src")

from ctf_strix import enum_guard  # noqa: E402

BOX = Path("/var/tmp/ctfbox")
dirs = {d.name: d for d in BOX.glob("2026*") if d.is_dir()}
rows = {}
for p in Path("/home/rjq").rglob("*.jsonl"):
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        if isinstance(record, dict) and record.get("run_id") in dirs:
            rows[str(record["run_id"])] = record

streams = []
for run_id, run_dir in sorted(dirs.items()):
    record = rows.get(run_id)
    dbs = list(run_dir.glob("strix_runs/*/.state/agents.db"))
    if not record or not dbs:
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
            output = obj.get("output")
            if not isinstance(output, str):
                output = json.dumps(output, ensure_ascii=False) if output is not None else ""
            calls.append((name, args, output))
    if len(calls) >= 3:
        streams.append((run_id, bool(record.get("correct")), calls))

STATUS = re.compile(r"(?:\[HTTP\s+(\d{3})\]|HTTP/1\.[01]\s+(\d{3})|phase=([A-Z][A-Z_]+)"
                    r"|Process exited with code\s+(-?\d+))")
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
TAG = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)")


def gate(result):
    text = result if isinstance(result, str) else str(result)
    match = STATUS.search(text)
    if not match:
        return None
    head = next(g for g in match.groups() if g)
    _, _, body = text.partition("\n")
    low = body[:400].lower()
    ctype = "html" if "<html" in low or "<!doctype html" in low else (
        "json" if body.lstrip()[:1] in "{[" else "text"
    )
    return head, ctype, body


def sig_core(result, args):
    got = gate(result)
    if got is None:
        return ""
    head, ctype, body = got
    return f"{head}|{ctype}|{len(body)//200}"


def sig_words(result, args):
    got = gate(result)
    if got is None:
        return ""
    head, ctype, body = got
    words = {w.lower() for w in WORD.findall(body[:2000])}
    return f"{head}|{ctype}|{len(body)//200}|vocab={len(words)//25}"


def sig_tags(result, args):
    got = gate(result)
    if got is None:
        return ""
    head, ctype, body = got
    return f"{head}|{ctype}|{len(body)//200}|tags={len({t.lower() for t in TAG.findall(body[:4000])})}"


#: Count a shape stall only between two *consecutive gated* results, i.e. two
#: real responses with no shell call in between.  Implemented by wrapping
#: observe so the replay matches what the guard would do with the same rule.
def replay(sig_fn, break_on_ungated=True):
    out = []
    previous = {"stall": 0, "hits": 0, "max": 0}
    orig = enum_guard._obs_signature
    enum_guard._obs_signature = sig_fn
    try:
        for run_id, correct, calls in streams:
            guard = enum_guard.EnumerationGuard()
            seen = set()
            stall = hits = peak = 0
            for name, args, output in calls:
                sig = sig_fn(output, args)
                guard.observe(name, args, output)
                if not sig:
                    if break_on_ungated:
                        stall = 0
                    continue
                if sig in seen:
                    stall += 1
                    peak = max(peak, stall)
                    if stall >= enum_guard._STALL_AFTER:
                        hits += 1
                else:
                    seen.add(sig)
                    stall = 0
            out.append((correct, len(calls), peak, hits))
    finally:
        enum_guard._obs_signature = orig
    return out


for label, fn in (
    ("status|ctype|size", sig_core),
    ("+ word bucket", sig_words),
    ("+ tag vocabulary", sig_tags),
):
    for break_on_ungated in (True, False):
        results = replay(fn, break_on_ungated)
        failed = [r for r in results if not r[0]]
        solved = [r for r in results if r[0]]
        row = []
        for thresh in (4, 6, 8):
            f_hit = sum(1 for r in failed if r[2] >= thresh)
            s_hit = sum(1 for r in solved if r[2] >= thresh)
            row.append(f">={thresh}: F {100*f_hit/len(failed):3.0f}% S {100*s_hit/len(solved):3.0f}%")
        print(f"{label:<20} break_on_shell={str(break_on_ungated):<5}  " + " | ".join(row))