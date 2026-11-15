"""Read-only: how many questions are still untouched, for planning S3.

Untouched means: no agent run in any jsonl under /home/rjq, and not in the
sealed set (the sealed set may each be run exactly once, at the end).
"""
import json
import pathlib
from collections import defaultdict

pools = json.loads(
    pathlib.Path("/home/rjq/work/strix-ctf-agent/experiments/pools.json").read_text(encoding="utf-8")
)
sealed = set(pools.get("sealed_excluded") or [])
candidates = [item["id"] for item in (pools.get("diagnostic") or []) + (pools.get("reserve") or [])]

seen = defaultdict(int)
solves = defaultdict(int)
for path in pathlib.Path("/home/rjq").rglob("*.jsonl"):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        if not isinstance(record, dict):
            continue
        challenge = record.get("challenge") or record.get("id")
        if not isinstance(challenge, str):
            continue
        seen[challenge] += 1
        if record.get("correct"):
            solves[challenge] += 1

print(f"pool-file candidates (diagnostic+reserve): {len(candidates)}")
clean = []
for challenge in candidates:
    if seen.get(challenge):
        print(f"  BURNED SINCE pools.json: {challenge:14} runs={seen[challenge]} solves={solves[challenge]}")
    else:
        clean.append(challenge)

print(f"\nstill untouched: {len(clean)}")
print(" ".join(clean))
print(f"\nsealed (each usable exactly once, at the end): {len(sealed)}")

# any run at all on a sealed id is a violation worth knowing about
for challenge in sealed:
    if seen.get(challenge):
        print(f"  WARNING sealed id has runs: {challenge} runs={seen[challenge]}")