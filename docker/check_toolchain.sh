#!/usr/bin/env bash
# 镜像 A 档工具面自检。构建期跑：缺依赖时让 build 失败，而不是比赛里 import 才炸。
#
# 只依赖标准库 + requirements.lock 里已装的轮子；不联网。
# 由 docker/Dockerfile 在 pip install --no-deps 之后调用。
set -euo pipefail

LOCK="${1:-/app/requirements.lock}"
A_CLOSURE="${2:-/app/docker/a_tier_closure.txt}"
B_CLOSURE="${3:-/app/docker/b_tier_closure.txt}"

echo "[toolchain] checking lock and closure"
python3 - "$LOCK" "$A_CLOSURE" "$B_CLOSURE" <<'PY'
import re
import sys
from pathlib import Path

lock_path = Path(sys.argv[1])
closure_paths = [Path(arg) for arg in sys.argv[2:]]
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

closure: list[tuple[str, str]] = []
seen: dict[str, str] = {}
for closure_path in closure_paths:
    for raw in closure_path.read_text(encoding="ascii").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, version = line.split("==", 1)
        if name in seen:
            if seen[name] != version:
                sys.exit(f"{closure_path}: {name} conflicts across manifests")
            continue
        seen[name] = version
        closure.append((name, version))

problems = []
for name, version in closure:
    if name not in pins:
        problems.append(f"missing from lock: {name}=={version}")
    elif pins[name] != version:
        problems.append(f"version drift: {name} lock={pins[name]} closure={version}")
if problems:
    sys.exit("toolchain closure incomplete:\n  " + "\n  ".join(problems))
print(f"[toolchain] lock: {len(pins)} pins; closure: {len(closure)} pins")
PY

echo "[toolchain] checking metadata (pip check)"
# --no-deps 装出来的环境里，任何缺失的传递依赖都会在这里显形。
#
# 只把 A 档闭包范围内的抱怨当致命错误：base image 自带的包如果有历史遗留的
# 元数据问题，与本改动无关，不该让镜像构建红掉；而闭包里的包缺依赖必须红。
python3 - "$A_CLOSURE" "$B_CLOSURE" <<'PY'
import re
import subprocess
import sys

closure = set()
for closure_path in sys.argv[1:]:
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
    sys.exit("dependency closure broken:\n  " + "\n  ".join(fatal))
print("[toolchain] pip check: no closure gaps")
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

echo "[toolchain] importing and exercising the B-tier namespaces"
python3 - <<'PY'
import importlib
import importlib.util
import io
import struct
import sys

MODULES = ("numpy", "sympy", "gmpy2", "scipy", "matplotlib", "pefile",
           "yara", "segno", "dnslib", "scapy", "reedsolo", "r2pipe")
missing = [name for name in MODULES if importlib.util.find_spec(name) is None]
if missing:
    sys.exit("missing namespaces: " + ", ".join(missing))

import numpy as np
import scipy
import sympy
import gmpy2
import pefile
import segno
import r2pipe  # noqa: F401 -- the r2 binaries are probed below
import scapy
import yara
from dnslib import DNSRecord
from reedsolo import RSCodec
from scipy import fft
from scapy.all import IP, TCP

assert (np.array([[1, 2], [3, 4]]) @ np.array([[1, 0], [0, 1]])).tolist() == [[1, 2], [3, 4]]

x = sympy.Symbol("x")
assert sorted(sympy.solve(sympy.Eq(x**2, 4), x), key=str) == [-2, 2]

assert gmpy2.powmod(2, 100, 1000003) == pow(2, 100, 1000003)

spectrum = fft.fft([1.0, 0.0, 0.0, 0.0])
assert abs(spectrum[0]) > 0.99

import matplotlib
matplotlib.use("Agg")
from matplotlib.figure import Figure

figure = Figure()
axes = figure.subplots()
axes.plot([0, 1], [0, 1])
buffer = io.BytesIO()
figure.savefig(buffer, format="png")
assert buffer.getvalue()[:8] == b"\x89PNG\r\n\x1a\n"

dos = bytearray(0x40)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x40)
coff = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0xF0, 0x22)
optional = bytearray(0xF0)
struct.pack_into("<H", optional, 0, 0x20B)
pe = pefile.PE(data=bytes(dos) + b"PE\0\0" + coff + bytes(optional), fast_load=True)
assert pe.FILE_HEADER.Machine == 0x8664

rule = yara.compile(source='rule t { strings: $a = "flag" condition: $a }')
assert len(rule.match(data=b"xxflagxx")) == 1

query = DNSRecord.question("example.com")
assert str(DNSRecord.parse(query.pack()).q.qname) == "example.com."

qr = io.BytesIO()
segno.make("ctf").save(qr, kind="png")
assert qr.getvalue()[:8] == b"\x89PNG\r\n\x1a\n"

packet = IP(src="127.0.0.1") / TCP(dport=80)
assert len(bytes(packet)) >= 40

codeword = bytearray(RSCodec(10).encode(b"ctfy"))
codeword[3] ^= 0xFF
assert bytes(RSCodec(10).decode(bytes(codeword))[0]) == b"ctfy"

print("[toolchain] imports: numpy=%s sympy=%s gmpy2=%s scipy=%s matplotlib=%s "
      "pefile=%s yara=%s segno=%s dnslib=ok scapy=%s reedsolo=ok r2pipe=ok" % (
          np.__version__, sympy.__version__, gmpy2.version(),
          scipy.__version__, matplotlib.__version__, pefile.__version__,
          yara.__version__, segno.__version__, scapy.__version__,
      ))
PY

echo "[toolchain] checking offline attack tools"
python3 - <<'PY'
import glob
import os
import shutil
import subprocess
import sys

# impacket 的 wheel 用 scripts=glob('examples/*.py') 把整套 CLI 落进 venv 的 bin/。
# 少于 60 个说明这层装歪了（上游当前是 70 个）；三个高频脚本必须在 PATH 上。
scripts = glob.glob("/opt/ctftools/bin/*.py")
if len(scripts) < 60:
    sys.exit(f"impacket CLI set incomplete: {len(scripts)} scripts in /opt/ctftools/bin")
for name in ("secretsdump.py", "wmiexec.py", "psexec.py"):
    if not shutil.which(name):
        sys.exit(f"missing impacket CLI on PATH: {name}")
print(f"[toolchain] impacket: {len(scripts)} CLI scripts (secretsdump/wmiexec/psexec on PATH)")

# 每项是 (可执行文件, 参数...)。sqlmap 的 --version 返回非零，所以按*输出*判定；
# 缺二进制或输出为空仍判构建失败。
PROBES = {
    "nmap": ("nmap", "--version"),
    "sqlmap": ("sqlmap", "--version"),
    "ffuf": ("ffuf", "-V"),
    "smbclient": ("smbclient", "--version"),
    "impacket": ("secretsdump.py", "-h"),
    "flask-unsign": ("flask-unsign", "--help"),
    "RsaCtfTool": ("RsaCtfTool", "--help"),
    "binwalk": ("binwalk", "--help"),
    "exiftool": ("exiftool", "-ver"),
    "7z": ("7z",),
    "upx": ("upx", "--version"),
    "sox": ("sox", "--version"),
    "pngcheck": ("pngcheck",),
    "tcpdump": ("tcpdump", "--version"),
    "steghide": ("steghide", "version"),
    "tshark": ("tshark", "-v"),
    "fls": ("fls", "-V"),
    "pdftotext": ("pdftotext", "-v"),
    "zbarimg": ("zbarimg", "--version"),
    "radare2": ("r2", "-v"),
    "rabin2": ("rabin2", "-v"),
    # 下面这一组是系统提示 Environment 段逐个点名的 CLI。提示里说「装了」的
    # 东西必须在这里探测过：否则改一次 base image 就会让提示开始说假话，
    # 而模型只会花轮次去发现工具不存在（REVIEW-20261112 PWN-10 / RT-1）。
    "checksec": ("checksec", "--help"),  # pwntools 4.15 的 console script
    "ROPgadget": ("ROPgadget", "--help"),  # requirements.lock: ropgadget==7.7
    "gdb": ("gdb", "--version"),
    "objdump": ("objdump", "--version"),
    "readelf": ("readelf", "--version"),
    "file": ("file", "--version"),
    "strings": ("strings", "--version"),
    "xxd": ("xxd", "-v"),
    "nc": ("nc", "-h"),  # netcat-openbsd：用法打在 stderr 且退出码非零，只看输出
    "curl": ("curl", "--version"),  # 提示把 curl 列为 HTTP 后备，必须证明装了
}
for label, argv in PROBES.items():
    exe = shutil.which(argv[0])
    if not exe:
        sys.exit(f"missing binary: {label} ({argv[0]})")
    proc = subprocess.run([exe, *argv[1:]], capture_output=True, text=True)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if not out:
        sys.exit(f"{label} produced no version output")
    print(f"[toolchain] {label}: {out.splitlines()[0][:90]}")
PY

echo "[toolchain] OK"
