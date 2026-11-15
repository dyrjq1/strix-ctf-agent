"""Strip CR from the given files and report byte deltas.

Why not ``sed -i``: passing ``s/\\r$//`` through PowerShell -> ssh mangled the
escape into a bare ``r`` and silently deleted a trailing ``r`` from every line
of four source files.  A file rewrite has no quoting surface at all.
"""
import sys
from pathlib import Path

for arg in sys.argv[1:]:
    path = Path(arg)
    raw = path.read_bytes()
    fixed = raw.replace(b"\r\n", b"\n")
    if fixed != raw:
        path.write_bytes(fixed)
    print(f"{path}: {len(raw)} -> {len(fixed)} bytes, CR removed: {raw.count(b'\\r')}")