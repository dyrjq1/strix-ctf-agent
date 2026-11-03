"""文件类题目的入口原语：一次调用回答"这是什么、下一步跑什么"。

设计依据（见 docs/14 第 1 节）：

- Cybench（arXiv:2408.08926）把任务拆成 subtask 后模型得分显著上升 —— 非 web
  题的瓶颈是**缺少可观察的中间步骤**，不是缺一个万能工具。
- Anthropic《Writing effective tools for agents》(2025)：工具返回要携带可判断的
  信号，而不是把原始日志整段吐给模型。

因此这里**不返回 strings 全量**：只给前 N 条可用串 + 家族判定 + 按家族内联的
决策表。模型拿到就能按 1→2→3 直接动手，不需要再"看一眼再说"。
"""

from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Final

#: 单次子进程上限。binwalk 对大文件会跑很久，超过就跳过。
_TIMEOUT: Final = 20
#: strings 只看前 4000 条，避免 100MB 二进制把返回撑爆。
_STRINGS_CAP: Final = 4000


def _run(argv: list[str], timeout: int = _TIMEOUT) -> str:
    """跑一条命令，失败返回空串。

    Args:
        argv: 参数列表（不经 shell，避免文件名里的空格/引号变成注入）。
        timeout: 秒。

    Returns:
        合并后的 stdout+stderr 文本。
    """
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    out = (proc.stdout or b"").decode("utf-8", "replace")
    err = (proc.stderr or b"").decode("utf-8", "replace")
    return (out + err).strip()


def _entropy(data: bytes) -> float:
    """香农熵（bit/byte）。>7.2 基本可判定为压缩或加密。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _family(magic: str, path: Path) -> str:
    """把 ``file`` 的输出压成一个家族标签。

    Args:
        magic: ``file -b`` 的原始输出。
        path: 文件路径，用于后缀兜底（pyc 的 magic 常被识别成 data）。

    Returns:
        ``elf`` / ``pe`` / ``macho`` / ``zip`` / ``gzip`` / ``png`` / ``jpeg`` /
        ``pdf`` / ``pcap`` / ``pyc`` / ``text`` / ``unknown``。
    """
    low = magic.lower()
    if "elf" in low:
        return "elf"
    if "pe32" in low or "ms-dos executable" in low:
        return "pe"
    if "mach-o" in low:
        return "macho"
    if "zip archive" in low:
        return "zip"
    if "gzip compressed" in low:
        return "gzip"
    if "png image" in low:
        return "png"
    if "jpeg image" in low:
        return "jpeg"
    if "pdf document" in low:
        return "pdf"
    if "pcap" in low or "tcpdump" in low:
        return "pcap"
    if "python script" in low:
        return "text"
    if "text" in low or "ascii" in low or "unicode" in low:
        return "text"
    if path.suffix == ".pyc" or (path.suffix == ".py" and path.exists()):
        return "pyc"
    return "unknown"


#: family → 决策表。每个家族直接给可执行动作，技能只作深读引用。
#:
#: ⚠️ 每一条命令都必须能在**本镜像里直接跑通**。旧版本给的是
#: ``checksec`` / ``r2`` / ``binwalk`` / ``zsteg`` / ``exiftool`` / ``tshark``——这六个
#: 在 ``docker/Dockerfile`` 里一个都没装。模型第一次调用就拿到一条
#: 跑不通的命令，这是 Misc 题的第一个致命断点（docs/27 C2）。
#:
#: 现在的写法分两类：
#:   * 镜像里有的工具（file / strings / xxd / unzip / binutils / python3）——直接给命令；
#:   * 镜像里没有的能力（图片隐写/pcap 重组/专用反编译器）——
#:     给**用 python3 手写**的具体入口，而不是一个不存在的命令。
#: 模型拿到 ``next:`` 就按 1→2→3 执行，不必先加载技能再决定方向；
#: 末尾的 ``深读`` 只是需要更多手法时的索引，不是第一步。
_NEXT: Final = {
    "elf": (
        "1) `readelf -h {p}` + `readelf -lW {p} | head -30` 看类型/段/入口；\n"
        "2) `elfpeek('{p}', view='info')` 拿 NX/PIE/canary，`elfpeek('{p}', view='symbols')` 找 main/win/system；\n"
        "3) 写利用前 `elffind('{p}', symbol='system')`、`elffind('{p}', search='/bin/sh')` 定位偏移；只有动态分析才 `gdb -batch -ex 'info functions' {p}`。别一上来跑它。\n"
        "深读: ctf-reverse/ctf-reverse；利用链再看 ctf-pwn/ctf-pwn。"
    ),
    "pe": (
        "1) `objdump -x {p} | head -60` 看节/导入表；`strings -n 8 {p} | grep -iE 'flag|http|password'` 找线索；\n"
        "2) `objdump -h {p}` 看节权限，`objdump -d {p} | head -40` 从入口反汇编；\n"
        "3) 镜像没有 PE 反编译器，控制流用 objdump 加 `hexpeek('{p}', length=512)` 手读。\n"
        "深读: ctf-reverse/ctf-reverse。"
    ),
    "macho": (
        "1) `hexpeek('{p}', length=64)` 认 0xfeedface/0xfeedfacf 与 CPU 类型；\n"
        "2) `strings -n 8 {p} | head -40` 找 ObjC 类名/URL/flag；\n"
        "3) 镜像没有 Mach-O 反编译器，用 `hexpeek('{p}', length=512)` 读头部后手切 load command。\n"
        "深读: ctf-reverse/ctf-reverse。"
    ),
    "zip": (
        "1) `unzip -l {p}` 先看清单与加密标记，别急着解；\n"
        "2) `unpack_archive('{p}')` 递归进嵌套，越界条目会被拒绝；\n"
        "3) 解出的最大文件再用 `file_triage('extracted')`，别逐个猜。\n"
        "深读: ctf-forensics/ctf-forensics；编码层看 ctf-misc/encodings。"
    ),
    "gzip": (
        "1) `python3 -c \"import gzip;d=gzip.open('{p}','rb').read();print(len(d),d[:64])\"` 看解压头；\n"
        "2) `unpack_archive('{p}')` 直接进嵌套层；\n"
        "3) `grep -arE 'FLAG|CTF|flag|ctf' extracted | head -20` 先扫文本。\n"
        "深读: ctf-misc/encodings。"
    ),
    "png": (
        "1) `hexpeek('{p}', length=64)` 认签名/IHDR；\n"
        "2) `python3 -c \"import zlib;d=open('{p}','rb').read();print(zlib.decompressobj().decompress(d[d.find(b'IDAT')+4:])[:64])\"` 抽 IDAT；多块时先拼再解；\n"
        "3) `python3 -c \"d=open('{p}','rb').read();print(d[8:33].hex())\"` 看宽高/位深，再查 alpha 低位与 tEXt。\n"
        "深读: ctf-forensics/stego-image。"
    ),
    "jpeg": (
        "1) `hexpeek('{p}', length=64)` 看 SOI/APP 段；\n"
        "2) `strings -n 8 {p} | head -40` 找 EXIF/注释/URL；\n"
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
        "1) `hexpeek('{p}', length=32)` 认 d4c3b2a1（小端）或 a1b2c3d4（大端）与链路类型；\n"
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
        "2) 像 base64/hex/URL 的串用 `decode_blob('<粘贴该串>')`，不要手写解码器；\n"
        "3) 认不出编码再 `file -bi {p}` 看字符集。\n"
        "深读: ctf-misc/encodings；纯谜题看 ctf-misc/ctf-misc。"
    ),
    "unknown": (
        "1) `hexpeek('{p}', length=64)` 先读前 64 字节魔数，别猜；\n"
        "2) `strings -n 6 {p} | head -40` 找容器/版本/路径特征；\n"
        "3) 仍认不出就只回报前两步结果，不要套用别的家族命令；`file -b {p}` 已是权威类型。\n"
        "深读: ctf-triage/ctf-triage。"
    ),
}

_FLAG_RE: Final = re.compile(r"(?:FLAG|CTF|flag|ctfy)\{[^}\s]{4,80}\}")


def file_triage(path: str = ".") -> str:
    """看一眼文件/目录，直接给出家族判定和该家族的决策表。

    Args:
        path: 文件或目录路径。相对路径按当前工作目录解析；默认 "."。
            目录只列一层，并标出每个文件的大小与家族。

    Returns:
        紧凑报告：类型、大小、熵、可打印串里的可疑项，以及**该家族的
        可执行决策表**。目录则返回清单 + 对最大文件的建议。
    """
    target = Path(path).expanduser()
    if not target.is_absolute():
        target = Path(os.getcwd()) / target
    if not target.exists():
        return f"[file_triage] 路径不存在：{target}。先 `ls -la` 确认附件的真实文件名。"

    if target.is_dir():
        entries = sorted(target.iterdir(), key=lambda p: (p.is_dir(), p.name))[:40]
        if not entries:
            return f"[file_triage] {target} 是空目录。"
        lines = [f"[file_triage] 目录 {target}（{len(entries)} 项）"]
        biggest: tuple[int, Path] | None = None
        for entry in entries:
            if entry.is_dir():
                lines.append(f"  d  {entry.name}/")
                continue
            size = entry.stat().st_size
            magic = _run(["file", "-b", str(entry)]).split(",")[0]
            lines.append(f"  f  {entry.name}  {size}B  {magic[:60]}")
            if biggest is None or size > biggest[0]:
                biggest = (size, entry)
        if biggest is not None:
            lines.append("")
            lines.append(f"next: 从最大的那个开始 → file_triage('{biggest[1].name}')")
        return "\n".join(lines)

    size = target.stat().st_size
    data = target.read_bytes()[: 1024 * 1024]
    magic = _run(["file", "-b", str(target)])
    family = _family(magic, target)
    ent = _entropy(data)

    strings_out = _run(["strings", "-n", "6", str(target)]).splitlines()[:_STRINGS_CAP]
    hits = [s.strip()[:120] for s in strings_out if _FLAG_RE.search(s)][:5]
    # 只挑"像路径/像 URL/像 base64"的串，普通英文单词对解题没用。
    clues = [
        s.strip()[:100] for s in strings_out
        if re.search(r"https?://|/flag|/app/|password|secret|token|BEGIN [A-Z ]*PRIVATE", s)
    ][:8]

    lines = [
        f"[file_triage] {target.name} | {size}B | entropy {ent:.2f} | {magic[:90]}",
        f"family: {family}",
    ]
    if ent > 7.2 and family in ("unknown", "text"):
        # 镜像里没有 binwalk（Dockerfile 也没装）。旧文案让模型去跑一个不存在
        # 的命令，这是 docs/27 C2 那条"提示与镜像不一致"的同类问题，只是藏在
        # 一行 note 里。改成能直接执行的做法。
        # Only commands that exist in the image: 当前镜像有 xxd / gzip / xz / zlib（python），
        # 7z 没装。把不存在的工具写进提示是 docs/27 C2 那条缺陷的同类。
        lines.append(
            "note: 熵 >7.2，多半是压缩/加密过的——先用 `xxd {p} | head -40` 看头部"
            "魔数，再用 python 的 zlib/gzip/lzma 或 `unpack_archive('{p}')` 逐个试，别硬读。"
            .format(p=target.name)
        )
    if hits:
        lines.append("flag-like strings:")
        lines.extend(f"  {h}" for h in hits)
    if clues:
        lines.append("clues:")
        lines.extend(f"  {c}" for c in clues)
    if family in ("zip", "gzip"):
        listing = _run(["unzip", "-l", str(target)]) if family == "zip" else ""
        if listing:
            lines.append("archive listing:")
            lines.extend("  " + line for line in listing.splitlines()[:12])
    if family not in ("zip", "gzip") and size < 8 * 1024 * 1024 and shutil.which("binwalk"):
        walk = _run(["binwalk", str(target)])
        if walk:
            lines.append("binwalk:")
            lines.extend("  " + line for line in walk.splitlines()[1:10])
    lines.append("next: " + _NEXT[family].format(p=str(target)))
    return "\n".join(lines)


TOOLS: Final = (file_triage,)


def register(register_fn=None) -> list[str]:
    """把 ``file_triage`` 注册进 strix 的扫描 agent。

    Args:
        register_fn: 注入点，默认取 ``factory.register_agent_tools``。

    Returns:
        本次新注册的工具名列表。
    """
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=120)(_as_async(fn)) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]


def _as_async(func):
    """Run a blocking helper off the event loop, keeping its signature.

    ⚠️ This is not cosmetic.  ``function_tool(timeout=...)`` rejects *sync*
    handlers (``ValueError: timeout_seconds is only supported for async
    @function_tool handlers``), and that error is raised *inside* ``register()``
    where both entrypoints wrap it in ``try/except`` and print one line.  The
    result: every attachment challenge ran without ``file_triage`` while the log
    said only "registration failed".  Same silent-shape as the guard-mount bug.

    ``functools.wraps`` is required because the SDK derives the JSON schema from
    ``inspect.signature``, which follows ``__wrapped__``; without it the tool
    would advertise zero parameters and the model could not call it at all.
    """
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner
