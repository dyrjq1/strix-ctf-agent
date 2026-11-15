"""Pre-registered S3 pool: 20 of the 23 untouched, by hash order, no peeking."""
import hashlib
import json

UNTOUCHED = (
    "033 071 075 070 005 062 068 109 099 056 088 060 066 076 104 101 089 111 "
    "092 093 100 105 110"
).split()
ids = [f"CTFARENA-{n}" for n in UNTOUCHED]
ordered = sorted(ids, key=lambda i: hashlib.sha256(("s3-transfer-v1" + i).encode()).hexdigest())
pools = json.load(open(
    r"C:\Users\rjq\Downloads\strix-ctf-agent\.claude\worktrees\night-20261113\experiments\pools.json",
    encoding="utf-8"))
meta = {m["id"]: m for m in (pools.get("diagnostic") or []) + (pools.get("reserve") or [])}

print("order:", " ".join(ordered))
print("\ntop 20 (the arm set):")
for i in ordered[:20]:
    m = meta.get(i, {})
    print(f"  {i:14} {m.get('difficulty','?'):7} solves_count={m.get('solves_count','?')}")
print("\nspares (replacement order):", " ".join(ordered[20:]))
print("\nplan json:")
print(json.dumps([{"id": i, "difficulty": meta.get(i, {}).get("difficulty", "hard"),
                   "allow_burned": True} for i in ordered[:20]], indent=1))