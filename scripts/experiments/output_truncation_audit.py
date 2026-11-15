"""P5 premise audit: is oversize output already spilled, and is the spill read?

Result on the 11-15 corpus (453 runs / 12,259 outputs): 4 truncation notices,
all ``load_skill``; 0 spill notices.  P5 has no target population -- see
docs/32 §9.4.

For every historical agents.db:
  - how many function_call_outputs carry a truncation notice, split into
    "full output saved to <path>" (spill) vs plain "[... N lines truncated ...]";
  - of the spilled calls, did a later call mention `.tool-output` or the path,
    and did that follow-up succeed (no "No such file")?
Read-only.
"""
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

ROOTS = [Path("/home/rjq/runs"), Path("/var/tmp/ctfbox")]
SPILL = re.compile(r"full output saved to ([^\s;]+)")
PLAIN = re.compile(r"\[\.\.\. (\d+) lines \((\d+) bytes\) truncated \.\.\.\]")
SPILL_ANY = re.compile(r"\[\.\.\. (\d+) lines \((\d+) bytes\) truncated — full output saved to ([^\s;]+)")


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
    if not root.exists():
        continue
    for d in sorted(root.glob("2026*")):
        if d.is_dir() and d.name not in seen:
            seen.add(d.name)
            dirs.append(d)

tot_calls = tot_spill = tot_plain = 0
runs_with_spill = runs_with_plain = 0
spill_paths = []
read_attempts = read_ok = read_fail = 0
dropped_bytes = 0
by_tool = Counter()
examples = []

for d in dirs:
    dbs = list(d.glob("strix_runs/*/.state/agents.db"))
    if not dbs:
        continue
    try:
        calls = load_calls(dbs[0])
    except Exception:
        continue
    tot_calls += len(calls)
    n_spill = n_plain = 0
    for i, (nm, ar, out) in enumerate(calls):
        m = SPILL_ANY.search(out)
        if m:
            n_spill += 1
            dropped_bytes += int(m.group(2))
            by_tool[nm] += 1
            path = m.group(3)
            later = calls[i + 1:]
            hit = [o for _n, a, o in later if path in a or ".tool-output" in a]
            if hit:
                read_attempts += 1
                if any("No such file" in h or "not found" in h.lower() for h in hit[:3]):
                    read_fail += 1
                else:
                    read_ok += 1
            elif len(examples) < 8:
                examples.append((d.name, nm, int(m.group(1)), int(m.group(2)), path))
            continue
        m2 = PLAIN.search(out)
        if m2:
            n_plain += 1
            dropped_bytes += int(m2.group(2))
            by_tool[nm] += 1
    tot_spill += n_spill
    tot_plain += n_plain
    runs_with_spill += 1 if n_spill else 0
    runs_with_plain += 1 if n_plain else 0

print(f"runs={len(dirs)} calls={tot_calls}")
print(f"truncated outputs: spill={tot_spill} plain={tot_plain} "
      f"(runs with spill={runs_with_spill}, plain-only runs={runs_with_plain})")
print(f"dropped bytes (as reported in notices)={dropped_bytes:,}")
print(f"by tool: {by_tool.most_common(10)}")
print(f"spilled calls followed by a read of the path: {read_attempts} "
      f"(ok={read_ok}, failed={read_fail})")
print("spilled-but-never-read examples:")
for e in examples:
    print(f"  {e[0]} tool={e[1]} dropped={e[2]} lines/{e[3]} bytes path={e[4]}")