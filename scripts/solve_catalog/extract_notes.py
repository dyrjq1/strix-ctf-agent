"""Pull the self-reported writeup out of every solved run's finish_scan call.

Writes /home/rjq/solve_notes.jsonl (flags redacted) and prints coverage +
a naive technique histogram so we can see what the solves actually consisted of.
"""
import collections
import json
import re
import sqlite3

FLAG_RE = re.compile(r"[A-Za-z0-9_.-]{2,40}\{[^{}\s]{4,}\}")

TECHNIQUES = {
    "idor": ["idor", "student_id", "broken access control", "object reference"],
    "auth_bypass": ["auth bypass", "authentication bypass", "no authentication",
                    "missing authentication", "403 bypass", "header bypass"],
    "sqli": ["sqli", "sql injection", "union select", "blind sql"],
    "ssti": ["ssti", "template injection", "jinja", "twig"],
    "ssrf": ["ssrf", "server-side request"],
    "path_traversal": ["path traversal", "directory traversal", "../", "lfi"],
    "command_injection": ["command injection", "rce", "os command"],
    "deserialization": ["deserial", "pickle", "ysoserial", "unserialize"],
    "jwt": ["jwt", "alg none", "json web token"],
    "xss": ["xss", "cross-site scripting"],
    "xxe": ["xxe", "xml external"],
    "file_upload": ["upload", "webshell"],
    "business_logic": ["business logic", "race condition", "price manipul"],
    "info_disclosure": ["info disclosure", "information disclosure", "leak",
                        "debug endpoint", "sensitive data exposure"],
    "crypto_weak": ["weak crypto", "predictable", "hardcoded key", "md5",
                    "hash length extension"],
}

def redact(text):
    return FLAG_RE.sub("<FLAG>", text or "").strip()

records = [json.loads(line) for line in open("/home/rjq/solve_catalog.jsonl",
                                             encoding="utf-8")]
out = []
coverage = {"records": len(records), "with_finish": 0, "with_summary": 0,
            "with_methodology": 0}
for rec in records:
    con = sqlite3.connect(f"file:{rec['db']}?mode=ro", uri=True)
    rows = con.execute(
        "SELECT message_data FROM agent_messages ORDER BY id").fetchall()
    con.close()
    summary = methodology = ""
    for (raw,) in rows:
        try:
            it = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(it, dict) or it.get("type") != "function_call":
            continue
        if it.get("name") != "finish_scan":
            continue
        try:
            args = json.loads(it.get("arguments") or "{}")
        except ValueError:
            continue
        summary = redact(args.get("executive_summary"))
        methodology = redact(args.get("methodology"))
    if summary or methodology:
        coverage["with_finish"] += 1
    if summary:
        coverage["with_summary"] += 1
    if methodology:
        coverage["with_methodology"] += 1
    out.append({
        "challenge": rec["challenge"],
        "run_id": rec["run_id"],
        "wall_s": rec["wall_s"],
        "n_calls": rec["n_calls"],
        "tools": list(dict.fromkeys(rec["tool_sequence"])),
        "summary": summary,
        "methodology": methodology,
    })

import os
tmp = "/home/rjq/solve_notes.jsonl.tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    for rec in out:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
os.replace(tmp, "/home/rjq/solve_notes.jsonl")

print("coverage:", json.dumps(coverage))
hist = collections.Counter()
unlabelled = []
for rec in out:
    blob = (rec["summary"] + " " + rec["methodology"]).lower()
    hits = [k for k, words in TECHNIQUES.items() if any(w in blob for w in words)]
    for h in hits:
        hist[h] += 1
    if not hits:
        unlabelled.append(rec["challenge"])
print("\ntechnique histogram (naive keyword, multi-label):")
for name, n in hist.most_common():
    print(f"  {n:3d}  {name}")
print("\nunlabelled:", len(unlabelled), unlabelled[:12])
print("\nby challenge:", len({r['challenge'] for r in out}))