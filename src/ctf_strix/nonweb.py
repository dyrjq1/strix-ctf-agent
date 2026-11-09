"""Non-web primitives: safe unpacking, raw TCP, batch comparison.

## Why these three and nothing else

The v2/v3 web surface answers "which request do I send next".  A rev/pwn/misc
challenge fails at a different place: the agent cannot see what it is holding.
EnIGMA (arXiv:2409.16165) reports the same split -- its gains came from
*interactive* tools that make each step observable (debugger, live socket),
not from adding one tool per challenge family.  NYU CTF Bench (arXiv:2406.05590)
adds the other half: failures cluster in multi-step composition, so the surface
must stay small and every call must return a decision, not a log dump.

So: one entry point per *question* the agent actually asks.

  * "what is inside this file?"    -> unpack_archive (recursive, budgeted)
  * "what does this service say?"  -> tcp           (banner + one round trip)
  * "which of these inputs differ?"-> tcp_batch

## Provenance (read before "improving" this by copying)

The reference pack lives in ``reference/pack-inspect-20261101/all-directions-pack-20261101``
(``tools-src/tools_misc_ext.py`` and ``tools_domain_ext.py``).  That pack ships
**no LICENSE file** -- verified by recursive search.  This module is therefore
an independent implementation written against observed behaviour, not a port:
same user-visible contract, own code, own comments.  Do not paste code from the
pack in here.

## Registration cost

``FILE_TOOLS`` and ``TCP_TOOLS`` register separately, because a file-only
challenge should not pay schema tokens for a socket tool and vice versa.  The
three schemas are ~2.5k chars; paying them on a web challenge is pure waste
(measured: 17 bookkeeping schemas cost 4.2k chars for zero calls).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import shutil
import socket
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Final

#: Same flag shape as ``flag_extract.FLAG_RE``.  Kept as a literal so this
#: module has no import cycle and can be unit-tested alone.
_FLAG_RE: Final = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[0-9a-zA-Z_\-]{2,}\}")


#: Formats ``_sniff`` can name but this module has no stdlib reader for.
#: 7z is extracted with the system binary when present (``_from_7z``) and
#: falls back to this set only when that binary is missing; RAR is handled
#: by ``_from_unar`` when the system ``unar`` binary is present.
#: Either way "nothing extracted" must become an actionable message
#: instead of silence.
_NAMES_ONLY: Final = frozenset({"7z", "rar"})

#: Extraction budget, shared across recursion depth.  Without sharing, five
#: levels of "64MB each" is 320MB on a 3GB VM -- the bomb wins by arithmetic.
_UNPACK_MAX_BYTES: Final = 64 * 1024 * 1024
_UNPACK_MAX_FILES: Final = 2000
#: Uncompressed-size gate for one member, checked before reading.
_UNPACK_MEMBER_MAX: Final = 64 * 1024 * 1024


#: tcp_batch is a one-shot comparison, not a fuzzer.  200 candidates covers
#: padding-oracle work and stays inside one tool timeout.
_BATCH_MAX: Final = 200


#: family → 决策表。每个家族直接给可执行动作，技能只作深读引用。
#:
#: ⚠️ 每一条命令都必须能在**本镜像里直接跑通**。旧版本给的是
#: ``checksec`` / ``r2`` / ``binwalk`` / ``zsteg`` / ``exiftool`` / ``tshark``——这六个
#: 在 ``docker/Dockerfile`` 里一个都没装。模型第一次调用就拿到一条
#: 跑不通的命令，这是 Misc 题的第一个致命断点（docs/27 C2）。
#:
#: 现在的写法分两类：
#:   * 镜像里有的工具（file / strings / xxd / unzip / binutils / python3）——直接给命令；
#:   * 镜像里没有 CLI 的能力（图片隐写/pcap 重组/专用反编译器）——优先用
#:     lock 里已有的 Python 库（Pillow）或 python3 手写入口，绝不给不存在的命令。
#: 模型拿到 ``next:`` 就按 1→2→3 执行，不必先加载技能再决定方向；
#: 末尾的 ``深读`` 只是需要更多手法时的索引，不是第一步。
_NEXT: Final = {
    "elf": (
        "1) `readelf -h {p}` + `readelf -lW {p} | head -30` 看类型/段/入口；\n"
        "2) `readelf -h {p}` + `readelf -W -l {p} | grep GNU_STACK` 看 NX（GNU_STACK 无 RWE → NX），`readelf -sW {p} | grep __stack_chk_fail` 看 canary，`readelf -sW {p} | grep -E 'main|win|system'` 找符号；\n"
        "3) 写利用前 `readelf -sW {p}`、`strings -a -t x {p} | grep '/bin/sh'` 定位偏移；只有动态分析才 `gdb -batch -ex 'info functions' {p}`。别一上来跑它。\n"
        "深读: ctf-reverse/ctf-reverse；利用链再看 ctf-pwn/ctf-pwn。"
    ),
    "pe": (
        "1) `objdump -x {p} | head -60` 看节/导入表；`strings -n 8 {p} | grep -iE 'flag|http|password'` 找线索；\n"
        "2) `objdump -h {p}` 看节权限，`objdump -d {p} | head -40` 从入口反汇编；\n"
        "3) 镜像没有 PE 反编译器，控制流用 objdump 加 `xxd -l 512 {p}` 手读。\n"
        "深读: ctf-reverse/ctf-reverse。"
    ),
    "macho": (
        "1) `xxd -l 64 {p}` 认 0xfeedface/0xfeedfacf 与 CPU 类型；\n"
        "2) `strings -n 8 {p} | head -40` 找 ObjC 类名/URL/flag；\n"
        "3) 镜像没有 Mach-O 反编译器，用 `xxd -l 512 {p}` 读头部后手切 load command。\n"
        "深读: ctf-reverse/ctf-reverse。"
    ),
    "zip": (
        "1) `unzip -l {p}` 先看清单与加密标记，别急着解；\n"
        "2) `unpack_archive('{p}')` 递归进嵌套，越界条目会被拒绝；\n"
        "3) 解出的最大文件再用 `file -b <name>` 确定下一个家族，不要逐个猜。\n"
        "深读: ctf-forensics/ctf-forensics；编码层看 ctf-misc/encodings。"
    ),
    "gzip": (
        "1) `python3 -c \"import gzip;d=gzip.open('{p}','rb').read();print(len(d),d[:64])\"` 看解压头；\n"
        "2) `unpack_archive('{p}')` 直接进嵌套层；\n"
        "3) `grep -arE 'FLAG|CTF|flag|ctf' extracted | head -20` 先扫文本。\n"
        "深读: ctf-misc/encodings。"
    ),
    "png": (
        "1) `xxd -l 64 {p}` 认签名/IHDR；`python3 -c \"from PIL import Image;im=Image.open('{p}');print(im.size,im.mode,im.info)\"`；\n"
        "2) 像素/位平面用 Pillow，别手解 zlib：`python3 -c \"from PIL import Image;im=Image.open('{p}').convert('RGB');print(list(im.getdata())[:8])\"`\n"
        "3) 仍无头绪再 `python3 -c \"d=open('{p}','rb').read();print(d[8:33].hex())\"` 看宽高/位深，查 alpha 低位与 tEXt。\n"
        "深读: ctf-forensics/stego-image。"
    ),
    "jpeg": (
        "1) `xxd -l 64 {p}` 看 SOI/APP 段；`python3 -c \"from PIL import Image;im=Image.open('{p}');print(im.size,im.mode)\"`\n"
        "2) `strings -n 8 {p} | head -40` 找 EXIF/注释/URL；像素用 Pillow：`python3 -c \"from PIL import Image;im=Image.open('{p}');print(list(im.getdata())[:8])\"`\n"
        "3) `python3 -c \"d=open('{p}','rb').read();i=d.rfind(b'\\xff\\xd9');print(len(d),i,d[i+2:i+66])\"` 看 EOI 后附加数据。\n"
        "深读: ctf-forensics/stego-image。"
    ),
    "pdf": (
        "1) `strings -n 8 {p} | head -60` 找 /URI /JS /OpenAction /Flag；\n"
        "2) `grep -aE '/URI|/JS|/OpenAction|/FlateDecode' {p} | head -20` 列对象；\n"
        "3) `python3 -c \"import zlib;d=open('{p}','rb').read();i=d.find(b'stream')+7;print(zlib.decompressobj().decompress(d[i:d.find(b'endstream')])[:200])\"` 解第一条流。\n"
        "深读: ctf-forensics/ctf-forensics。"
    ),
    "pcap": (
        "1) `xxd -l 32 {p}` 认 d4c3b2a1（小端）或 a1b2c3d4（大端）与链路类型；\n"
        "2) `python3 -c \"import struct;d=open('{p}','rb').read();print(len(d),struct.unpack('<IHHIIII',d[:24]))\"` 读全局头并反推包记录；\n"
        "3) 逐条切 16B 记录 + payload；`strings -n 6 {p} | grep -iE 'GET|POST|flag|http'` 常直接见明文。\n"
        "深读: ctf-forensics/network。"
    ),
    "pyc": (
        "1) `xxd {p} | head -4` 读 magic，对照 `python3 -c \"import importlib.util;print(importlib.util.MAGIC_NUMBER.hex())\"`；\n"
        "2) 版本一致时 `python3 -c \"import marshal,dis;f=open('{p}','rb');f.read(16);dis.dis(marshal.load(f))\"`；\n"
        "3) 版本不同先找对应解释器；镜像没有反编译器，`strings -n 6 {p} | head -40` 常直接见常量。\n"
        "深读: ctf-reverse/ctf-reverse。"
    ),
    "text": (
        "1) `cat {p} | head -80` 先读原文，`grep -aoE 'FLAG|CTF|flag|ctf' {p} | head` 找标记；\n"
        "2) 像 base64/hex/URL 的串用 `echo '<粘贴该串>' | base64 -d`，hex 用 `python3 -c \"print(bytes.fromhex('<粘贴该串>').decode())\"`，URL 用 `python3 -c \"import urllib.parse;print(urllib.parse.unquote('<粘贴该串>'))\"`，不要手写解码器；\n"
        "3) 认不出编码再 `file -bi {p}` 看字符集。\n"
        "深读: ctf-misc/encodings；纯谜题看 ctf-misc/ctf-misc。"
    ),
    "unknown": (
        "1) `xxd -l 64 {p}` 先读前 64 字节魔数，别猜；\n"
        "2) `strings -n 6 {p} | head -40` 找容器/版本/路径特征；\n"
        "3) 仍认不出就只回报前两步结果，不要套用别的家族命令；`file -b {p}` 已是权威类型。\n"
        "深读: ctf-triage/ctf-triage。"
    ),
    "rar": (
        "1) `unar -l {p}` 看清单；若未装 unar，`xxd {p} | head -4` 认 Rar! 签名；\n"
        "2) `unar {p}` 或 `unpack_archive('{p}')` 解出内容；\n"
        "3) 解出后对最大文件用 `file -b <name>` 定方向。\n"
        "深读: ctf-forensics/ctf-forensics。"
    ),
    "7z": (
        "1) `7z l {p}` 看清单；若未装 7z，`xxd {p} | head -4` 认 7z 签名；\n"
        "2) `7z x {p}` 或 `unpack_archive('{p}')` 解出内容；\n"
        "3) 解出后对最大文件用 `file -b <name>` 定方向。\n"
        "深读: ctf-forensics/ctf-forensics。"
    ),
}


class _NonWebError(Exception):
    """An error a model can act on; never surfaced as a traceback."""


def _clip(text: str, limit: int = 4000) -> str:
    """Truncate a tool result, but never in the middle of a flag.

    A truncated flag is indistinguishable from a wrong answer downstream, and
    the log hook has physically cut one before (old ledger defect #6), so when
    a flag is present the window widens to cover it.
    """
    if len(text) <= limit:
        return text
    match = _FLAG_RE.search(text)
    if match and match.end() > limit:
        limit = min(match.end() + 64, len(text))
    if len(text) <= limit:
        return text
    return text[: limit - 60] + f"\n...[truncated {len(text)} chars total]"


def _to_int(value: object, default: int, low: int, high: int) -> int:
    """Parse an int argument from a model, clamped; garbage falls back.

    Tool arguments arrive as strings often enough that ``int()`` raising here
    used to kill a whole turn.
    """
    if value is None or str(value).strip() == "":
        return default
    try:
        number = int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return default
    return max(low, min(number, high))


# ---------------------------------------------------------------------------
# 1. unpack_archive -- magic sniffing + a shared budget
# ---------------------------------------------------------------------------


def _sniff(path: Path) -> str:
    """Identify an archive by magic bytes; extension is not evidence."""
    try:
        # 64 KB, not 512 B: a RAR self-extracting stub legally precedes the
        # signature by up to that much, and reading less makes such a file
        # indistinguishable from an unknown blob.
        with path.open("rb") as handle:
            head = handle.read(64 * 1024)
    except OSError:
        return ""
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    # 7z and RAR are *named* before any extraction attempt: Python's stdlib
    # has no reader for either.  The system 7z binary (when present) handles
    # real 7z archives in walk(); RAR extracts via _from_unar when the system
    # Naming matters because "detected unknown, nothing extracted" reads
    # exactly like a corrupt file -- the model then retries unpack_archive
    # instead of changing method.  A RAR self-extracting stub can precede the
    # signature by up to 64 KB (rarlab technote), so search that window
    # rather than byte 0.
    window = head[: 64 * 1024]
    if window.find(b"\x37\x7a\xbc\xaf\x27\x1c") >= 0:
        return "7z"
    if window.find(b"Rar!\x1a\x07") >= 0:
        return "rar"
    return ""


class _Sink:
    """Write members under ``root`` while enforcing four escape gates.

    The gates exist because CTF attachments are hostile by construction:
    ``../../flag`` inside a zip is a normal Tuesday.  ``budget`` is shared
    across recursion so nested archives cannot multiply the limit.
    """

    def __init__(self, root: Path, budget: dict[str, int]) -> None:
        self.root = root.resolve()
        self.budget = budget
        self.skipped: list[str] = []

    def accept(self, member: str) -> Path | None:
        name = (member or "").replace("\\", "/")
        if not name or name.endswith("/"):
            return None
        if name.startswith("/") or re.match(r"^[A-Za-z]:/", name):
            self.skipped.append(f"{member}: absolute path")
            return None
        if ".." in Path(name).parts:
            self.skipped.append(f"{member}: '..' segment")
            return None
        target = (self.root / name).resolve()
        if not target.is_relative_to(self.root):
            self.skipped.append(f"{member}: escapes root (zip slip)")
            return None
        if self.budget["files"] >= _UNPACK_MAX_FILES:
            self.skipped.append(f"{member}: file budget {_UNPACK_MAX_FILES} reached")
            return None
        return target

    def write(self, target: Path, data: bytes) -> bool:
        if self.budget["bytes"] + len(data) > _UNPACK_MAX_BYTES:
            self.skipped.append(
                f"{target.name}: total budget {_UNPACK_MAX_BYTES // 1048576}MB reached"
            )
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self.budget["bytes"] += len(data)
        self.budget["files"] += 1
        return True


def _open_zip(path: Path):
    """Open a zip even when data is appended after the end-of-central-directory.

    Measured on a real misc attachment (``1.zip``, 145,914 B): the EOCD sits at
    offset 2,379 and 143,535 bytes of unrelated data follow it.  That is a
    polyglot/overlay, not corruption, and ``zipfile`` refuses it outright
    (``BadZipFile: File is not a zip file``) because it only scans the last
    64KB for the EOCD.

    Fallback: find the first EOCD, cut the file there, and open that.  The
    central-directory offsets are relative to the file start, so the prefix is
    still a valid archive.  Returns ``(archive, note)``; ``note`` explains the
    truncation so it is visible in the tool output instead of silent.
    """
    try:
        return zipfile.ZipFile(path), ""
    except zipfile.BadZipFile:
        raw = path.read_bytes()
        marker = raw.find(b"PK\x05\x06")
        if marker < 0:
            raise
        comment_len = int.from_bytes(raw[marker + 20 : marker + 22], "little")
        end = marker + 22 + comment_len
        if end > len(raw):
            raise
        note = (
            f"{len(raw) - end} bytes after the zip end-of-central-directory were "
            "ignored (overlay/polyglot); the archive itself is intact"
        )
        return zipfile.ZipFile(io.BytesIO(raw[:end])), note


def _from_zip(path: Path, sink: _Sink) -> None:
    archive, note = _open_zip(path)
    if note:
        sink.skipped.append(f"{path.name}: {note}")
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                # Encrypted entry: zipfile raises RuntimeError on read.  Report
                # "password-protected" (itself a misc-challenge hint) instead of
                # crashing the turn.
                sink.skipped.append(f"{info.filename}: encrypted entry")
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                sink.skipped.append(f"{info.filename}: symlink")
                continue
            if info.file_size > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{info.filename}: declared size over member limit")
                continue
            target = sink.accept(info.filename)
            if target is None:
                continue
            # Read one byte past the limit: a lying header then costs 64MB+1,
            # not the whole disk.
            with archive.open(info) as handle:
                data = handle.read(_UNPACK_MEMBER_MAX + 1)
            if len(data) > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{info.filename}: actual size over limit")
                continue
            sink.write(target, data)


def _from_tar(path: Path, sink: _Sink) -> None:
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                sink.skipped.append(f"{member.name}: link member")
                continue
            if not member.isfile():
                continue
            if member.size > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{member.name}: declared size over member limit")
                continue
            target = sink.accept(member.name)
            if target is None:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            data = handle.read(_UNPACK_MEMBER_MAX + 1)
            if len(data) > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{member.name}: actual size over limit")
                continue
            sink.write(target, data)


def _from_stream(path: Path, kind: str, sink: _Sink) -> None:
    opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
    name = path.stem if path.suffix in {".gz", ".bz2", ".xz"} else path.name + ".out"
    target = sink.accept(name)
    if target is None:
        return
    try:
        with opener(path, "rb") as handle:
            data = handle.read(_UNPACK_MEMBER_MAX + 1)
    except (OSError, EOFError, lzma.LZMAError):
        sink.skipped.append(f"{name}: decompression failed")
        return
    if len(data) > _UNPACK_MEMBER_MAX:
        sink.skipped.append(f"{name}: actual size over limit")
        return
    sink.write(target, data)


def _from_7z(path: Path, sub: Path, budget: dict[str, int]) -> list[str]:
    """Extract with the system 7z binary, then enforce the same gates.

    The binary writes files itself, so the pre-write checks in ``_Sink``
    cannot apply; instead everything it produced is validated post hoc and
    rule-breakers are deleted and reported, mirroring ``_Sink``'s refusals.
    ``-p`` pins an empty password so an encrypted archive fails fast instead
    of blocking on an interactive prompt.
    """
    sub.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["7z", "x", "-y", "-bd", "-p", f"-o{sub}", str(path.resolve())],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = tail[-1][:120] if tail else f"exit code {proc.returncode}"
        raise OSError(detail)
    skipped: list[str] = []
    for child in sorted(sub.rglob("*")):
        if child.is_symlink():
            child.unlink()
            skipped.append(f"{child.relative_to(sub).as_posix()}: symlink")
            continue
        if not child.is_file():
            continue
        rel = child.relative_to(sub).as_posix()
        if budget["files"] >= _UNPACK_MAX_FILES:
            child.unlink()
            skipped.append(f"{rel}: over file budget")
            continue
        size = child.stat().st_size
        if size > _UNPACK_MEMBER_MAX:
            child.unlink()
            skipped.append(f"{rel}: over member limit")
            continue
        if budget["bytes"] + size > _UNPACK_MAX_BYTES:
            child.unlink()
            skipped.append(f"{rel}: over byte budget")
            continue
        budget["files"] += 1
        budget["bytes"] += size
    return skipped


def _from_unar(path: Path, sub: Path, budget: dict[str, int]) -> list[str]:
    """Extract with the system unar binary, then enforce the same gates.

    unar handles RAR/RAR5/NSIS/ISO/CAB and other formats that neither
    the stdlib nor 7z can read.  The same post-hoc validation as
    ``_from_7z`` applies.
    """
    sub.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["unar", "-no-questions", "-output-directory", str(sub.resolve()),
         str(path.resolve())],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = tail[-1][:120] if tail else f"exit code {proc.returncode}"
        raise OSError(detail)
    skipped: list[str] = []
    for child in sorted(sub.rglob("*")):
        if child.is_symlink():
            child.unlink()
            skipped.append(f"{child.relative_to(sub).as_posix()}: symlink")
            continue
        if not child.is_file():
            continue
        rel = child.relative_to(sub).as_posix()
        if budget["files"] >= _UNPACK_MAX_FILES:
            child.unlink()
            skipped.append(f"{rel}: over file budget")
            continue
        size = child.stat().st_size
        if size > _UNPACK_MEMBER_MAX:
            child.unlink()
            skipped.append(f"{rel}: over member limit")
            continue
        if budget["bytes"] + size > _UNPACK_MAX_BYTES:
            child.unlink()
            skipped.append(f"{rel}: over byte budget")
            continue
        budget["files"] += 1
        budget["bytes"] += size
    return skipped

def _unique_dir(base: Path) -> Path:
    """Never mix this extraction into a previous run's output."""
    if not base.exists():
        return base
    index = 1
    while (base.parent / f"{base.name}-{index}").exists():
        index += 1
    return base.parent / f"{base.name}-{index}"


def _signature_offset(path: Path, kind: str) -> int:
    """Where the named-only signature actually starts (0 when it is the header).

    Reporting the offset keeps the message honest for polyglots: a PNG with an
    embedded 7z is not "a 7z file", but "a 7z signature at 0x1234" is true and
    tells the model to carve from there.
    """
    pattern = b"\x37\x7a\xbc\xaf\x27\x1c" if kind == "7z" else b"Rar!\x1a\x07"
    try:
        with path.open("rb") as handle:
            head = handle.read(64 * 1024)
    except OSError:
        return 0
    found = head.find(pattern)
    return found if found >= 0 else 0


def unpack_archive(path: str = "", max_depth: int = 3, out_dir: str = "extracted") -> str:
    """Extract an archive safely, then keep going into nested archives.

    Nested archives are the norm in misc (``outer.zip`` holding ``inner.tar.gz``
    holding one PNG).  Doing that by hand costs one turn per layer and is where
    models lose the plot.

    Args:
        path: Archive file path.
        max_depth: Recurse into nested archives up to this depth, 1-5, default 3.
        out_dir: Destination directory; a numeric suffix is added if it exists.

    Returns:
        The extracted tree with per-file depth and size, plus everything that
        was refused (path escape, symlink, encrypted, over budget) and why.
    """
    source = Path(path).expanduser()
    if not source.is_file():
        return (
            f"[unpack_archive] not a file: {path!r}\n"
            "next: list the directory first (`ls -la`) -- attachments are often "
            "given a name different from the one in the statement."
        )
    depth_cap = _to_int(max_depth, 3, 1, 5)
    root = _unique_dir(Path(out_dir or "extracted"))
    root.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    skipped: list[str] = []
    produced: list[Path] = []
    budget = {"bytes": 0, "files": 0}

    def walk(item: Path, depth: int, kind: str | None = None) -> None:
        if kind is None:
            kind = _sniff(item)
        if not kind or depth > depth_cap:
            return
        sub = root if depth == 1 else root / f"_d{depth}"
        if kind == "7z" and shutil.which("7z"):
            # The system binary reads formats the stdlib cannot; _from_7z
            # validates its output against the same gates as _Sink.
            try:
                skipped.extend(_from_7z(item, sub, budget))
            except (OSError, subprocess.SubprocessError) as exc:
                lines.append(f"! {item.name}: 7z failed ({type(exc).__name__})")
                return
        elif kind in _NAMES_ONLY and shutil.which("unar"):
            # unar reads formats the stdlib and 7z cannot: RAR/RAR5/NSIS/
            # ISO/CAB.  Validates output against the same gates as _Sink.
            try:
                skipped.extend(_from_unar(item, sub, budget))
            except (OSError, subprocess.SubprocessError) as exc:
                lines.append(f"! {item.name}: unar failed ({type(exc).__name__})")
                return
        elif kind in _NAMES_ONLY:
            # Neither 7z nor unar available for this format on this host.
            # Stop before the stdlib paths, which would otherwise raise
            # KeyError on the opener table -- the tail message explains.
            return
        else:
            sink = _Sink(sub, budget)
            try:
                if kind == "zip":
                    _from_zip(item, sink)
                elif kind == "tar":
                    _from_tar(item, sink)
                else:
                    _from_stream(item, kind, sink)
            except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
                lines.append(f"! {item.name}: {kind} failed ({type(exc).__name__})")
                return
            skipped.extend(sink.skipped)
        for child in sorted(sub.rglob("*")):
            if not child.is_file():
                continue
            produced.append(child)
            lines.append(
                f"  d{depth} {child.relative_to(root).as_posix()}  "
                f"({child.stat().st_size} B)"
            )
            walk(child, depth + 1)

    kind = _sniff(source)
    walk(source, 1, kind)

    body = [
        f"[unpack_archive] {source.name} -> {root.as_posix()} "
        f"(detected {kind or 'unknown'}, depth {depth_cap})"
    ]
    body.extend(lines or ["  nothing extracted"])
    if skipped:
        body.append(f"refused {len(skipped)}:")
        body.extend(f"  - {entry}" for entry in skipped[:20])
    body.append(f"total {len(produced)} file(s), {budget['bytes']} B")
    if not produced:
        body.append(
            "next: nothing came out -- check what the file really is with "
            "file; a wrong extension is common and the magic "
            "bytes are the authority."
        )
        if kind in _NAMES_ONLY and not (kind == "7z" and shutil.which("7z")):
            where = _signature_offset(source, kind)
            at = "this IS that archive" if where == 0 else "the archive starts there"
            body.append(
                f"matched a {kind} signature at offset 0x{where:x} -- {at}, and this "
                f"image ships no {kind} reader. Do not retry unpack_archive; it will "
                "return the same line. Next: carve from that offset and read the "
                "container by hand (xxd + the struct module), or check whether "
                "the statement/strings already leaks the content. If it is encrypted, "
                "the password has to come from the challenge -- brute force here is a "
                "different, much more expensive problem."
            )
        elif kind == "7z" and shutil.which("7z"):
            body.append(
                "next: the 7z binary ran and produced nothing usable -- the "
                "archive is empty, corrupt, truncated, or password-protected. "
                "Do not retry unpack_archive; it will fail the same way. If it "
                "is encrypted, the password has to come from the challenge."
            )
        elif kind in _NAMES_ONLY and shutil.which("unar"):
            body.append(
                "next: unar ran and produced nothing usable -- the archive "
                "is empty, corrupt, truncated, or password-protected. Do not "
                "retry unpack_archive; it will fail the same way. If it is "
                "encrypted, the password has to come from the challenge."
            )
    else:
        body.append(
            "next: inspect the largest extracted file with file; for text "
            "files grep is cheaper than opening each one."
        )
        # Wire _NEXT: sniff the largest produced file to decide
        # the next-step family, not the outer archive kind.
        if produced:
            largest = max(produced, key=lambda p: p.stat().st_size, default=None)
            if largest is not None:
                snif = _sniff(largest)
                if snif and snif in _NEXT:
                    hint = _NEXT[snif].format(p=largest.as_posix())
                    body.append("next: " + hint)
    # Separate next: hints from the file list so they survive _clip.
    next_hints = []
    body_without_next = []
    for line in body:
        if line.startswith("next:"):
            next_hints.append(line)
        else:
            body_without_next.append(line)
    result = _clip("\n".join(body_without_next))
    if next_hints:
        result += "\n" + "\n".join(next_hints)
    return result

# ---------------------------------------------------------------------------
# 2. tcp -- one round trip, and a batch that shares one connection
# ---------------------------------------------------------------------------


def _connect(host: str, port: int, timeout: float, tls: bool, sni: str) -> socket.socket:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except socket.gaierror as exc:
        hint = ""
        if host.lower().endswith(".internal"):
            hint = (
                " The host is *.internal: either the challenge VPN is not up, or "
                "you reused a stale node name. Use the URL the platform returned."
            )
        raise _NonWebError(f"[tcp] DNS failed for {host}: {exc}.{hint}") from None
    except OSError as exc:
        raise _NonWebError(
            f"[tcp] cannot connect to {host}:{port} ({type(exc).__name__}: {exc}). "
            "next: confirm the port from the task statement; a refused port on a "
            "running box usually means the wrong port, not a dead box."
        ) from None
    if not tls:
        return raw
    try:
        import ssl

        context = ssl.create_default_context()
        # CTF services routinely use self-signed certificates; the goal is the
        # protocol, not the PKI.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(raw, server_hostname=(sni or host))
    except Exception as exc:  # noqa: BLE001
        try:
            raw.close()
        except OSError:
            pass
        raise _NonWebError(
            f"[tcp] TLS handshake failed ({type(exc).__name__}: {exc}). "
            "next: retry with tls=false -- plain TCP on 443 is common in CTF."
        ) from None


def _drain(sock: socket.socket, expect: bytes | None, read_timeout: float, cap: int) -> bytes:
    """Read until ``expect`` appears, the peer closes, or the window expires."""
    buffer = b""
    sock.settimeout(read_timeout)
    deadline = time.monotonic() + read_timeout
    while len(buffer) < cap:
        try:
            chunk = sock.recv(min(4096, cap - len(buffer)))
        except (TimeoutError, socket.timeout):
            break
        except OSError:
            break
        if not chunk:
            break
        buffer += chunk
        if expect and expect in buffer:
            break
        if time.monotonic() > deadline:
            break
    return buffer


def _render(data: bytes, label: str, hex_limit: int = 256) -> str:
    if not data:
        return f"{label}: (empty)"
    text = "".join(
        chr(byte) if 32 <= byte < 127
        else ("\\n" if byte == 10 else ("\\r" if byte == 13 else "."))
        for byte in data[:600]
    )
    return f"{label} {len(data)} B\n  hex: {data[:hex_limit].hex()}\n  ascii: {text}"


def tcp(
    host: str = "",
    port: int = 0,
    payload: str = "",
    hex_mode: bool = False,
    expect: str = "",
    read_timeout: float = 3.0,
    max_recv: int = 4096,
    tls: bool = False,
    sni: str = "",
) -> str:
    """Connect once, optionally send a payload, and show the banner plus reply.

    This exists because ``nc`` and ``pwntools`` are not guaranteed in the image,
    and because a raw socket gives both the bytes and the banner in one call --
    the "interactive tool" gap EnIGMA identifies as the main blocker on
    remote-service challenges.

    Args:
        host: Target host.
        port: Target port.
        payload: Bytes to send. Text by default; hex when ``hex_mode`` is set.
        hex_mode: Interpret ``payload`` as hex (for binary protocols and
            exploit bytes).
        expect: Stop reading early once this substring arrives.
        read_timeout: Per-read window in seconds, default 3.
        max_recv: Cap on bytes read back, default 4096.
        tls: Wrap in TLS (accepts self-signed certificates).
        sni: SNI name when the vhost differs from ``host``.

    Returns:
        Connect timing, banner, reply (hex + ASCII) and whether ``expect`` hit.
    """
    if not host:
        return "[tcp] host is empty. Format: tcp(host='node1.ctfy.run', port=1337)"
    target_port = _to_int(port, 0, 0, 65535)
    if target_port <= 0:
        return f"[tcp] invalid port {port!r}. It must be 1-65535."
    if hex_mode:
        try:
            raw = bytes.fromhex(str(payload or "").strip())
        except ValueError as exc:
            return f"[tcp] hex_mode payload is not valid hex: {exc}"
    else:
        raw = str(payload or "").encode("utf-8", "surrogateescape")

    window = min(max(float(read_timeout or 3.0), 0.2), 30.0)
    cap = _to_int(max_recv, 4096, 16, 65536)
    started = time.time()
    try:
        sock = _connect(host, target_port, min(10.0, window + 7.0), bool(tls), sni)
        try:
            # Grab the banner first: many services print a prompt and then
            # wait, so sending immediately would bury the prompt in our echo.
            banner = b""
            try:
                sock.settimeout(0.4)
                banner = sock.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                banner = b""
            if raw:
                try:
                    sock.sendall(raw)
                except OSError as exc:
                    return f"[tcp] send failed: {exc}. The peer closed after the banner."
            expect_bytes = expect.encode("utf-8", "surrogateescape") if expect else None
            body = _drain(sock, expect_bytes, window, cap)
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except _NonWebError as exc:
        return str(exc)

    elapsed_ms = (time.time() - started) * 1000
    parts = [
        f"[tcp] {host}:{target_port} connected in {elapsed_ms:.0f} ms "
        f"(sent {len(raw)} B, tls={bool(tls)})"
    ]
    if banner:
        parts.append(_render(banner, "banner"))
    if body:
        parts.append(_render(body, "reply"))
    elif not banner:
        parts.append("no bytes received -- the service is waiting for input first.")
    if expect:
        parts.append("expect: MATCHED" if expect.encode() in body else "expect: not found")
    if not body and raw:
        parts.append(
            "next: nothing came back after the payload. For a line-based service "
            "the terminator is usually a newline; retry with payload='...\\n'."
        )
    return _clip("\n".join(parts))


def tcp_batch(
    host: str = "",
    port: int = 0,
    payloads: list[str] | None = None,
    hex_mode: bool = True,
    read_timeout: float = 2.0,
    max_recv: int = 1024,
    same_conn: bool = True,
    tls: bool = False,
    sni: str = "",
) -> str:
    """Send several payloads and report one compact line per response.

    The point is *comparison*: padding oracles and byte-by-byte leaks are
    decided by which response differs, and doing that in one call keeps the
    difference in one context window instead of 200 separate ones.

    Args:
        host: Target host.
        port: Target port.
        payloads: Candidate payloads, max 200.
        hex_mode: Payloads are hex (default true; false for text lines).
        read_timeout: Per-payload read window, default 2 seconds.
        max_recv: Cap per response, default 1024 bytes.
        same_conn: Reuse one connection (needed for per-connection state); set
            false only when the service rejects pipelining.
        tls: Wrap in TLS.
        sni: SNI name override.

    Returns:
        Header, then ``#i sent N B -> recv M B hex=... ascii=...`` per payload,
        so a differing response is visible without reading 200 bodies.
    """
    items = [item for item in (payloads or []) if isinstance(item, str)]
    if not items:
        return "[tcp_batch] payloads is empty. Pass a list of candidates."
    if len(items) > _BATCH_MAX:
        items = items[:_BATCH_MAX]
    target_port = _to_int(port, 0, 0, 65535)
    if not host or target_port <= 0:
        return f"[tcp_batch] need host and a port in 1-65535 (got {host!r}:{port!r})."

    window = min(max(float(read_timeout or 2.0), 0.2), 30.0)
    cap = _to_int(max_recv, 1024, 16, 65536)
    rows: list[str] = []
    started = time.time()
    try:
        sock = _connect(host, target_port, min(10.0, window + 7.0), bool(tls), sni)
        try:
            sock.settimeout(0.3)
            try:
                sock.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                pass
            for index, item in enumerate(items):
                if time.time() - started > 120:
                    rows.append(f"# stopped after {index}/{len(items)}: 120s wall")
                    break
                try:
                    raw = (
                        bytes.fromhex(item.strip())
                        if hex_mode
                        else item.encode("utf-8", "surrogateescape")
                    )
                except ValueError:
                    rows.append(f"#{index} skipped: not valid hex")
                    continue
                try:
                    sock.sendall(raw)
                except OSError as exc:
                    rows.append(f"#{index} send failed: {exc}")
                    break
                body = _drain(sock, None, window, cap)
                preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in body[:60])
                rows.append(
                    f"#{index} sent {len(raw)} B -> recv {len(body)} B "
                    f"hex={body[:48].hex()} ascii={preview!r}"
                )
                if not same_conn:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = _connect(host, target_port, min(10.0, window + 7.0), bool(tls), sni)
                    sock.settimeout(0.3)
                    try:
                        sock.recv(4096)
                    except (TimeoutError, socket.timeout, OSError):
                        pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except _NonWebError as exc:
        return str(exc)

    head = (
        f"[tcp_batch] {host}:{target_port} {len(items)} payload(s) "
        f"same_conn={same_conn} in {time.time() - started:.1f}s"
    )
    tail = (
        "next: compare the 'recv' column, not the hex. The candidate whose "
        "length or first bytes differ is the signal; if every line is identical, "
        "the hypothesis is wrong -- change the question, not the payload."
    )
    return _clip("\n".join([head] + rows + [tail]))

# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

def _as_async(func):
    """Run a blocking helper off the event loop, keeping its signature.

    ``function_tool(timeout=...)`` is rejected for sync handlers (the SDK
    raises at registration time, which would surface as "every non-web tool
    failed to register" rather than as a timeout).  A thin async wrapper fixes
    that and is also the correct behaviour: unpacking a 64MB archive must not
    freeze the agent's event loop.

    ``functools.wraps`` matters because the SDK derives the JSON schema from
    ``inspect.signature``, which follows ``__wrapped__`` -- without it every
    parameter would disappear from the schema.
    """
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner


#: Answers an attachment question.  Registered on ``kind == "file"``.
FILE_TOOLS: Final = (unpack_archive,)
#: Answers a remote-service question.  Registered on ``kind == "tcp"``.
TCP_TOOLS: Final = (tcp, tcp_batch)


def register(register_fn=None, kind: str = "file") -> list[str]:
    """Register the non-web primitives for one challenge kind.

    Args:
        register_fn: Injection point; defaults to
            ``factory.register_agent_tools``.
        kind: ``"file"`` (attachment primitives) or ``"tcp"`` (socket
            primitives).  Anything else registers nothing -- a web challenge
            must not pay for these schemas.

    Returns:
        Tool names registered by this call (empty when already present).
    """
    if kind == "file":
        tools = FILE_TOOLS
    elif kind == "tcp":
        tools = TCP_TOOLS
    else:
        return []

    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(tool, "name", "") for tool in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=180)(_as_async(func)) for func in tools]
    fresh = [tool for tool in wrapped if getattr(tool, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [tool.name for tool in fresh]
