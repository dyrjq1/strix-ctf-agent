"""Read-only: pull the "| stall:" suffix out of each run log of the A/B.

batch_eval on the VM predates the parser change, so the JSONL rows carry no
stall counters.  The counters *are* printed on the summary line, which lands in
each run's own log; this recovers them post hoc so we can tell whether the
treatment actually fired (the S1 lesson: an installed guard that never fires
looks exactly like a guard that works).
"""
import pathlib
import re
import sys
import time

LINE_RE = re.compile(r"\| stall: max=(\d+) hits=(\d+) class_max=(\d+) class_hits=(\d+)")
since = float(sys.argv[1]) if len(sys.argv) > 1 else 0.0

rows = []
for path in pathlib.Path("/home/rjq").rglob("run.log"):
    try:
        if path.stat().st_mtime < since:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        continue
    match = LINE_RE.search(text)
    if match is None:
        continue
    challenge = ""
    for part in path.parts:
        found = re.match(r"(CTFARENA-\d{3})", part)
        if found:
            challenge = found.group(1)
            break
    rows.append((challenge, str(path), *map(int, match.groups())))

rows.sort()
print(f"logs with a stall suffix since {time.strftime('%H:%M', time.localtime(since))}: {len(rows)}")
for challenge, path, stall_max, hits, class_max, class_hits in rows:
    print(f"{challenge:16} stall_max={stall_max:3} hits={hits:3} class_max={class_max:3} "
          f"class_hits={class_hits:3}  {path}")