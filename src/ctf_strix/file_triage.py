"""文件类题目的入口原语：一次调用回答"这是什么、下一步跑什么"。

设计依据（见 docs/14 第 1 节）：

- Cybench（arXiv:2408.08926）把任务拆成 subtask 后模型得分显著上升 —— 非 web
  题的瓶颈是**缺少可观察的中间步骤**，不是缺一个万能工具。
- Anthropic《Writing effective tools for agents》(2025)：工具返回要携带可判断的
  信号，而不是把原始日志整段吐给模型。

因此这里**不返回 strings 全量**：只给前 N 条可用串 + 家族判定 + 一条具体命令。
模型拿到就能直接动手，不需要再"看一眼再说"。
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


#: family → 下一步。这句话是工具的主要价值，别删。
#:
#: ⚠️ 每一条都必须能在**本镜像里直接跑通**。旧版本给的是
#: ``checksec`` / ``r2`` / ``binwalk`` / ``zsteg`` / ``exiftool`` / ``tshark``——这六个
#: 在 ``docker/Dockerfile`` 里一个都没装。模型第一次调用就拿到一条
#: 跑不通的命令，这是 Misc 题的第一个致命断点（docs/27 C2）。
#:
#: 现在的写法分两类：
#:   * 镜像里有的工具（file / strings / xxd / unzip / binutils）——直接给命令；
#:   * 镜像里没有的能力（图片隐写/pcap 重组/binwalk 扫描）——
#:     给**用 python 手写**的具体入口，而不是一个不存在的命令。
#: 这也是本项目的一贯结论：把"我没有这个能力"伪装成"我该往这走"，
#: 比不给建议更糟。
_NEXT: Final = {
    "elf": (
        "readelf -h {p} && readelf -lW {p} | head -30；然后 elfpeek('{p}', what='all') 拿保护/符号/gadget。"
        "静态优先，别一上来跑它。"
    ),
    "pe": "objdump -x {p} | head -60；镜像没有 r2，PE 的分析用 objdump + strings 手工推。",
    "macho": "objdump -x {p} | head -40；镜像没有 r2。",
    "zip": "unzip -l {p}（先看清单再解，避免炸开一堆文件）；解包用 unpack_archive('{p}')，它会进嵌套层。",
    "gzip": "gunzip -c {p} | head -c 4000 | xxd | head -40；或 unpack_archive('{p}') 直接进嵌套。",
    "png": (
        "图像隐写要自己写（本镜像没装图像工具）："
        "`python3 -c \"import zlib,struct;d=open('{p}','rb').read();print(len(d),d[:32].hex())\"` 先看块结构，"
        "再抽 IDAT 解压看像素/alpha 低位。"
    ),
    "jpeg": "strings -n 8 {p} | head -40 看元数据可读段；结构用 xxd 手工读。",
    "pdf": "strings -n 8 {p} | head -60；再 xxd {p} | head -40 看对象结构。",
    "pcap": (
        "本镜像没装抓包工具，用 python 手写："
        "`python3 -c \"import struct;d=open('{p}','rb').read();print(d[:24].hex())\"` 先认魔数，"
        "再按 帧头/传输层 分解 —— 常见题目只需把 payload 拼回来。"
    ),
    "pyc": "xxd {p} | head -4 先看 magic（对应 Python 版本），再决定用哪个反编译器。",
    "text": "cat {p} | head -80；若是密文串，先 decode_blob('…') 而不是自己写解码器。",
    "unknown": "xxd {p} | head -20 看前 320 字节的魔数；仍然认不出就 strings -n 6 {p} | head -40。",
}

_FLAG_RE: Final = re.compile(r"(?:FLAG|CTF|flag|ctfy)\{[^}\s]{4,80}\}")


def file_triage(path: str = ".") -> str:
    """看一眼文件/目录，直接给出家族判定和下一条命令。

    Args:
        path: 文件或目录路径。相对路径按当前工作目录解析；默认 "."。
            目录只列一层，并标出每个文件的大小与家族。

    Returns:
        紧凑报告：类型、大小、熵、可打印串里的可疑项、以及**一条具体命令**。
        目录则返回清单 + 对最大文件的建议。
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
        lines.append("note: 熵 >7.2，多半是压缩/加密过的——先 binwalk 找内嵌格式，别硬读。")
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
