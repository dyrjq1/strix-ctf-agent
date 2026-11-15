"""Rebuild a per-solve structural catalog from the surviving agents.db item streams.

Writes /home/rjq/solve_catalog.jsonl, one line per solved run that still has a
transcript. Flag-shaped strings are redacted, so the file is safe to move
around and to show to a human.
"""
import collections
import glob
import json
import os
import re
import sqlite3

FLAG_RE = re.compile(r"[A-Za-z0-9_.-]{2,40}\{[^{}\s]{4,}\}")
CATEGORY = {
    "load_skill", "read_file", "bash", "write_file", "edit_file",
    "submit_flag", "list_dir", "grep", "glob", "browser", "python",
}


def redact(text):
    return FLAG_RE.sub("<FLAG>", text or "")


def items_of(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    rows = con.execute(
        "SELECT message_data FROM agent_messages ORDER BY id").fetchall()
    con.close()
    out = []
    for (raw,) in rows:
        try:
            item = json.loads(raw)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


# ---- collect solved rows -------------------------------------------------
rows = []
for path in glob.glob("/home/rjq/*.jsonl"):
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass

solved = [r for r in rows if r.get("correct") is True]
ctf_prefixes = ("CTFARENA", "CYBENCH", "XBOW", "UPLOADLABS", "SQLILABS", "SAMPLE")
ctf = [r for r in solved if (r.get("challenge") or "").split("-")[0] in ctf_prefixes]

# newest first so the catalog keeps the most recent solve per challenge
ctf.sort(key=lambda r: r.get("started") or 0, reverse=True)

records = []
stats = {"rows": len(rows), "solved": len(solved), "ctf_solved": len(ctf),
         "with_db": 0, "with_items": 0, "no_flag_in_row": 0}
archetypes = collections.Counter()
tool_total = collections.Counter()
seen_challenge = {}

for r in ctf:
    rid = r.get("run_id") or ""
    hits = glob.glob(f"/home/rjq/runs/{rid}/strix_runs/*/.state/agents.db")
    if not hits:
        continue
    stats["with_db"] += 1
    items = items_of(hits[0])
    if not items:
        continue
    stats["with_items"] += 1

    calls = []
    for idx, it in enumerate(items):
        if it.get("type") == "function_call":
            name = it.get("name") or "?"
            calls.append(name)
            tool_total[name] += 1

    # final assistant prose = last message item carrying output_text
    final_text = ""
    for it in reversed(items):
        if it.get("type") == "message" and it.get("role") == "assistant":
            chunks = [c.get("text", "") for c in (it.get("content") or [])
                      if isinstance(c, dict)]
            text = "\n".join(chunks).strip()
            if text:
                final_text = redact(text)[:1200]
                break

    key = r.get("challenge")
    seen_challenge[key] = seen_challenge.get(key, 0) + 1
    rec = {
        "challenge": key,
        "run_id": rid,
        "wall_s": round(r["total_s"]) if r.get("total_s") else None,
        "turns": len(items),
        "n_calls": len(calls),
        "tool_sequence": calls,
        "solved_by": r.get("solved_by"),
        "final_text": final_text,
        "db": hits[0],
    }
    records.append(rec)
    sig = " > ".join(dict.fromkeys(calls))[:120]
    archetypes[sig] += 1

out_path = "/home/rjq/solve_catalog.jsonl"
tmp_path = out_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
os.replace(tmp_path, out_path)

print("stats:", json.dumps(stats, ensure_ascii=False))
print("records written:", len(records), "->", out_path)
print("\ntools used across these solves:")
for name, n in tool_total.most_common(15):
    print(f"  {n:5d}  {name}")
print("\ntop 12 call-order archetypes:")
for sig, n in archetypes.most_common(12):
    print(f"  {n:3d}  {sig}")
print("\nchallenges solved more than once:",
      sum(1 for v in seen_challenge.values() if v > 1), "of", len(seen_challenge))
print("\n--- 3 sample final reports (flags redacted) ---")
for rec in records[:3]:
    print(f"\n[{rec['challenge']}] wall={rec['wall_s']}s items={rec['turns']} calls={rec['n_calls']}")
    print(rec["final_text"][:700])