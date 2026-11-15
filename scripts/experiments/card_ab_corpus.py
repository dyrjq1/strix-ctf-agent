"""Emit the 74-challenge card A/B regression corpus (no flags, no transcripts).

One row per solved challenge: the cheapest successful run, its cost shape and
tool chain. This is the counterfactual baseline for card changes -- every row
solved with method cards NOT injected (0/402 runs ever carried them), so the
baseline is real rather than the void 11-12 A/B.

Grouping for analysis should come from platform tags at run time, not from text
keywords: a keyword screen mislabels anything whose writeup says "no
authentication was required" as an auth bypass.
"""
import json
import os
import re

FLAG_RE = re.compile(r"[A-Za-z0-9_.-]{2,40}\{[^{}\s]{4,}\}")
HOST_RE = re.compile(r"https?://[A-Za-z0-9.-]*ctfy\.run[A-Za-z0-9/._-]*")

recs = [json.loads(l) for l in open("/home/rjq/solve_notes.jsonl", encoding="utf-8")]

best = {}
for rec in recs:
    row = {
        "challenge": rec["challenge"],
        "run_id": rec["run_id"],
        "wall_s": rec["wall_s"],
        "n_calls": rec["n_calls"],
        "tools": rec["tools"],
        "cards_injected": False,
    }
    cur = best.get(rec["challenge"])
    key = (rec["wall_s"] or 10 ** 6, rec["n_calls"])
    if cur is None or key < (cur["wall_s"] or 10 ** 6, cur["n_calls"]):
        best[rec["challenge"]] = row

rows = [best[ch] for ch in sorted(best)]
payload = {
    "generated": "2026-11-15",
    "source": "docs/44 solution catalog (99 solved runs / 74 challenges)",
    "note": "Every row solved with method cards NOT injected (0/402 runs ever did). "
            "Use as the counterfactual baseline for card changes: measure turns and "
            "wallclock, never treat 'still all green' as an ability result.",
    "challenges": rows,
}
out = "/home/rjq/card_ab_corpus.json"
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=1)
    fh.write("\n")
os.replace(tmp, out)

text = open(out, encoding="utf-8").read()
print("challenges:", len(rows))
print("flag leaks:", len(FLAG_RE.findall(text)))
print("hostnames  :", len(HOST_RE.findall(text)))
med = sorted(r["wall_s"] for r in rows if r["wall_s"])
print("wall_s p50/p90:", med[len(med) // 2], med[int(len(med) * 0.9)])
print("wrote", out, os.path.getsize(out), "bytes")