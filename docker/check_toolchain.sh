#!/usr/bin/env bash
# 镜像 A 档工具面自检。构建期跑：缺依赖时让 build 失败，而不是比赛里 import 才炸。
#
# 只依赖标准库 + requirements.lock 里已装的轮子；不联网。
# 由 docker/Dockerfile 在 pip install --no-deps 之后调用。
set -euo pipefail

LOCK="${1:-/app/requirements.lock}"
CLOSURE="${2:-/app/docker/a_tier_closure.txt}"

echo "[toolchain] checking lock and closure"
python3 - "$LOCK" "$CLOSURE" <<'PY'
import re
import sys
from pathlib import Path

lock_path, closure_path = Path(sys.argv[1]), Path(sys.argv[2])
text = lock_path.read_text(encoding="ascii")
if "\r" in text or not text.endswith("\n"):
    sys.exit(f"{lock_path}: must stay LF-terminated without CR")

pins = {}
for line in text.splitlines():
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", line)
    if not match:
        sys.exit(f"{lock_path}: not an exact pin: {line!r}")
    name, version = match.groups()
    if name in pins:
        sys.exit(f"{lock_path}: duplicate {name}")
    pins[name] = version

closure = []
for raw in closure_path.read_text(encoding="ascii").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    name, version = line.split("==", 1)
    closure.append((name, version))

problems = []
for name, version in closure:
    if name not in pins:
        problems.append(f"missing from lock: {name}=={version}")
    elif pins[name] != version:
        problems.append(f"version drift: {name} lock={pins[name]} closure={version}")
if problems:
    sys.exit("A-tier closure incomplete:\n  " + "\n  ".join(problems))
print(f"[toolchain] lock: {len(pins)} pins; A-tier closure: {len(closure)} pins")
PY

echo "[toolchain] checking metadata (pip check)"
# --no-deps 装出来的环境里，任何缺失的传递依赖都会在这里显形。
#
# 只把 A 档闭包范围内的抱怨当致命错误：base image 自带的包如果有历史遗留的
# 元数据问题，与本改动无关，不该让镜像构建红掉；而闭包里的包缺依赖必须红。
python3 - "$CLOSURE" <<'PY'
import re
import subprocess
import sys

closure_path = sys.argv[1]
closure = set()
for raw in open(closure_path, encoding="ascii"):
    line = raw.strip()
    if line and not line.startswith("#"):
        closure.add(re.sub(r"[-_.]+", "-", line.split("==", 1)[0]).lower())

proc = subprocess.run(
    [sys.executable, "-m", "pip", "check"], capture_output=True, text=True
)
out = ((proc.stdout or "") + (proc.stderr or "")).strip()
print(out or "No broken requirements found.")

fatal = []
for line in out.splitlines():
    match = re.match(r"([A-Za-z0-9_.-]+)\s+\S+\s+requires\s+([^,]+),", line)
    if not match:
        continue
    requirer = re.sub(r"[-_.]+", "-", match.group(1)).lower()
    if requirer in closure:
        fatal.append(line)
if fatal:
    sys.exit("A-tier dependency closure broken:\n  " + "\n  ".join(fatal))
print("[toolchain] pip check: no A-tier closure gaps")
PY

echo "[toolchain] importing and exercising the A-tier namespaces"
python3 - <<'PY'
import importlib
import importlib.util
import io
import sys

MODULES = ("Crypto", "Cryptodome", "PIL", "pwn", "z3", "capstone", "unicorn",
           "paramiko", "rpyc", "plumbum")
missing = [name for name in MODULES if importlib.util.find_spec(name) is None]
if missing:
    sys.exit("missing namespaces: " + ", ".join(missing))

Crypto = importlib.import_module("Crypto")
Cryptodome = importlib.import_module("Cryptodome")
z3 = importlib.import_module("z3")
PIL = importlib.import_module("PIL")
pwn = importlib.import_module("pwn")

from Crypto.Cipher import AES
from Cryptodome.Cipher import AES as AESX
from PIL import Image

key = b"0" * 16
plain = b"0123456789abcdef"
assert AES.new(key, AES.MODE_ECB).decrypt(AES.new(key, AES.MODE_ECB).encrypt(plain)) == plain
assert AESX.new(key, AESX.MODE_ECB).decrypt(AESX.new(key, AESX.MODE_ECB).encrypt(plain)) == plain

x = z3.Int("x")
solver = z3.Solver()
solver.add(x > 3, x < 9, x % 2 == 0)
assert solver.check() == z3.sat and solver.model()[x].as_long() == 4

image = Image.new("RGB", (4, 4), (1, 2, 3))
buffer = io.BytesIO()
image.save(buffer, "PNG")
buffer.seek(0)
reopened = Image.open(buffer)
assert reopened.size == (4, 4) and reopened.getpixel((0, 0)) == (1, 2, 3)

assert len(pwn.cyclic(64)) == 64
assert pwn.cyclic_find(pwn.cyclic(64)[16:20]) == 16

for name in ("capstone", "unicorn", "paramiko", "rpyc", "plumbum"):
    importlib.import_module(name)

print("[toolchain] imports: Crypto=%s Cryptodome=%s z3=%s PIL=%s pwn=%s" % (
    Crypto.__version__, Cryptodome.__version__, z3.get_version_string(),
    PIL.__version__, pwn.version,
))
PY

echo "[toolchain] OK"
