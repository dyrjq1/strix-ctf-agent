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
from typing import Any, Final

from ctf_strix.flag_extract import FLAG_RE

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
#: ⚠️ 每一条命令都必须能在**本镜像里直接跑通**。``docker/check_toolchain.sh``
#: 在构建期逐个探测这里点名的二进制（``tests/test_offline_index.py::IMAGE_TOOLS``
#: 与它等值），所以表里可以放心用 ``checksec`` / ``r2`` / ``rabin2`` / ``binwalk`` /
#: ``exiftool`` / ``tshark`` / ``7z`` / ``pngcheck`` / ``pdftotext`` / ``zbarimg``；
#: 反之，Python 层面的调用只能是我们自己的 ``elfpeek`` / ``elffind`` / ``hexpeek`` 等。
#: 旧版把这批已装工具全写成"没装"，模型只好拿 python3 手写解析器——一次一个
#: 白烧的轮次（REVIEW-20261112 REV-5 / FMT-2，docs/27 C2 同类）。
#:
#: 模型拿到 ``next:`` 就按 1→2→3 执行，不必先加载技能再决定方向；
#: 末尾的 ``深读`` 只是需要更多手法时的索引，不是第一步。
_NEXT: Final = {
    "elf": (
        "1) `checksec --file={p}` 拿 NX/PIE/canary；`readelf -h {p}` 看类型/入口；\n"
        "2) `rabin2 -I {p}` 看架构/加固，`rabin2 -z {p}` 找 flag 串，`rabin2 -qs {p}` 列符号，`r2 -A -q -c 'afl' {p}` 看函数；\n"
        "3) 写利用前 `elffind('{p}', symbol='system')`、`elffind('{p}', search='/bin/sh')` 定位偏移；只有动态分析才 `gdb -batch {p}`，别一上来跑它。\n"
        "深读: ctf-reverse/ctf-reverse；利用链再看 ctf-pwn/ctf-pwn。"
    ),
    "pe": (
        "1) `rabin2 -I {p}` 看架构/导入表；`strings -n 8 {p} | grep -iE 'flag|http|password'` 找线索；\n"
        "2) `r2 -A -q -c 'afl' {p}` 列函数，`objdump -h {p}` 看节权限，`objdump -d {p} | head -40` 从入口反汇编；\n"
        "3) 无 .NET 运行时；托管 PE 用 `strings -el {p}`（UTF-16）与 `hexpeek('{p}', length=512)` 手读。\n"
        "深读: ctf-reverse/ctf-reverse。"
    ),
    "macho": (
        "1) `rabin2 -I {p}` 认 cputype/load command，`rabin2 -qs {p}` 列符号；\n"
        "2) `r2 -A -q -c 'afl' {p}` 列函数，`strings -n 8 {p} | head -40` 找 ObjC 类名/URL/flag；\n"
        "3) 符号被剥时 `hexpeek('{p}', length=512)` 手切 load command。\n"
        "深读: ctf-reverse/ctf-reverse。"
    ),
    "zip": (
        "1) `7z l {p}` 看清单（加密条目会标），`unzip -l {p}` 交叉核对；\n"
        "2) `unpack_archive('{p}')` 递归进嵌套，越界条目会被拒绝；加密包换 `7z x -pPASS {p}`；\n"
        "3) 解出的最大文件再用 `file_triage('extracted')`，别逐个猜。\n"
        "深读: ctf-forensics/ctf-forensics；编码层看 ctf-misc/encodings。"
    ),
    "gzip": (
        "1) `7z l {p}` 看解压后大小与嵌套层，`binwalk {p}` 认内嵌容器；\n"
        "2) `unpack_archive('{p}')` 直接进嵌套层；\n"
        "3) `grep -arE 'FLAG|CTF|flag|ctf' extracted | head -20` 先扫文本。\n"
        "深读: ctf-misc/encodings。"
    ),
    "png": (
        "1) `pngcheck -v {p}` 验块结构，`exiftool {p}` 看 tEXt/comment，`zbarimg -q {p}` 扫二维码；\n"
        "2) `binwalk {p}` 找追加文件；像素/位平面用 Pillow：`python3 -c \"from PIL import Image;im=Image.open('{p}').convert('RGB');print(im.size,list(im.getdata())[:8])\"`；\n"
        "3) 仍无头绪查 alpha 低位与 IHDR：`python3 -c \"d=open('{p}','rb').read();print(d[8:33].hex())\"`。\n"
        "深读: ctf-forensics/stego-image。"
    ),
    "jpeg": (
        "1) `exiftool {p}` 看 EXIF/注释/GPS；`hexpeek('{p}', length=64)` 看 SOI/APP 段；\n"
        "2) `binwalk {p}` 找 EOI 后追加的文件，`strings -n 8 {p} | head -40` 找 URL/flag；\n"
        "3) 像素用 Pillow：`python3 -c \"from PIL import Image;im=Image.open('{p}');print(im.size,list(im.getdata())[:8])\"`\n"
        "深读: ctf-forensics/stego-image。"
    ),
    "pdf": (
        "1) `pdftotext {p} - | head -60` 先取正文，`exiftool {p}` 看元数据；\n"
        "2) `strings -n 8 {p} | grep -aE '/URI|/JS|/OpenAction|/FlateDecode' | head -20` 列可疑对象；\n"
        "3) 解 FlateDecode 流：`python3 -c \"import zlib;d=open('{p}','rb').read();i=d.find(b'stream')+7;print(zlib.decompressobj().decompress(d[i:d.find(b'endstream')])[:200])\"`\n"
        "深读: ctf-forensics/ctf-forensics。"
    ),
    "pcap": (
        "1) `tshark -r {p} -q -z conv,ip` 看会话，`tcpdump -r {p} -nn | head -20` 认协议/端口；\n"
        "2) `tshark -r {p} -Y http.request -T fields -e http.host -e http.request.uri | head -30` 列请求；`tshark -r {p} -z follow,tcp,ascii,0` 跟一条流；\n"
        "3) `strings -n 6 {p} | grep -iE 'GET|POST|flag|http'` 常直接见明文；导对象用 `tshark -r {p} --export-objects http,out`。\n"
        "深读: ctf-forensics/network。"
    ),
    "pyc": (
        "1) `xxd {p} | head -4` 读 magic，对照 `python3 -c \"import importlib.util;print(importlib.util.MAGIC_NUMBER.hex())\"`；\n"
        "2) 版本一致时 `python3 -c \"import marshal,dis;f=open('{p}','rb');f.read(16);dis.dis(marshal.load(f))\"`；\n"
        "3) 版本不同先找对应解释器；没有再把 `strings -n 6 {p} | head -40` 的常量当线索。\n"
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
        "2) `binwalk {p}` 让签名库认容器/内嵌文件，`exiftool {p}` 看元数据；\n"
        "3) 仍认不出就只回报前两步结果，不要套用别的家族命令；`file -b {p}` 已是权威类型。\n"
        "深读: ctf-triage/ctf-triage。"
    ),
}

#: 与 ``flag_extract.FLAG_RE`` 同一对象（标签式前缀）。体门槛随真值从
#: ``{4,80}`` 收到 ``{2,}``：只影响"这行是否算 flag-like hint"，调用方仍然
#: 只取前 5 条，不会把输出撑爆。
_FLAG_RE: Final = FLAG_RE

#: 延迟导入的 ``ctf_strix.local_backend``。Windows 上该模块 import 即依赖
#: POSIX，且测试里会用 ``types.ModuleType`` 整体替换它 —— 因此只探测一次，
#: 永远通过 ``getattr`` 取 ``workspace_root``，不在模块顶层 import。
_LOCAL_BACKEND: Any = None
_LOCAL_BACKEND_PROBED = False


def _sandbox_root() -> Path | None:
    """本次 run 的沙箱工作目录；拿不到（未跑题 / 测试桩 / 非 POSIX）时返回 ``None``。"""
    global _LOCAL_BACKEND, _LOCAL_BACKEND_PROBED
    if not _LOCAL_BACKEND_PROBED:
        _LOCAL_BACKEND_PROBED = True
        try:
            from ctf_strix import local_backend as module
        except Exception:  # noqa: BLE001 —— 真正的降级路径就是"没有沙箱"
            module = None
        _LOCAL_BACKEND = module
    getter = getattr(_LOCAL_BACKEND, "workspace_root", None)
    if not callable(getter):
        return None
    try:
        root = getter()
    except Exception:  # noqa: BLE001
        return None
    if not root:
        return None
    try:
        return Path(root)
    except TypeError:
        return None


def resolve_path(raw: str) -> Path:
    """把模型给的路径解析成**沙箱工作目录**里的真实位置（FMT-3）。

    三方路径口径原先互不相认：提示层写 ``/workspace/<rel>``（strix 的
    ``extra_files`` 约定），``file_triage`` / ``nonweb`` 按**进程 CWD** 解析
    （agent 从不 ``chdir``，那是启动目录），而 shell 的 CWD 是沙箱 root。
    于是同一个文件名，shell ``cat`` 得到、``file_triage`` 说"路径不存在"。

    规则：``/workspace/x`` → ``root/x``；相对路径 → ``root/x``；绝对路径原样
    （shell 不 jail，主机绝对路径是真能读到的）。没有沙箱时退回旧的 CWD 语义。
    """
    text = (raw or "").strip()
    root = _sandbox_root()
    if root is None:
        path = Path(text or ".").expanduser()
        if not path.is_absolute():
            path = Path(os.getcwd()) / path
        return path
    if text in ("", ".", "./", "/workspace", "/workspace/"):
        return root
    if text.startswith("/workspace/"):
        rel = text[len("/workspace/"):]
        return root / rel if rel else root
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = root / path
    return path


def file_triage(path: str = ".") -> str:
    """看一眼文件/目录，直接给出家族判定和该家族的决策表。

    Args:
        path: 文件或目录路径。相对路径与 ``/workspace/...`` 一律解析到沙箱
            工作目录（与 shell 的 CWD 一致，见 `resolve_path`）；默认 "."。
            目录只列一层，并标出每个文件的大小与家族。

    Returns:
        紧凑报告：类型、大小、熵、可打印串里的可疑项，以及**该家族的
        可执行决策表**。目录则返回清单 + 对最大文件的建议。
    """
    target = resolve_path(path)
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
        # 旧文案断言"镜像里没有 binwalk / 7z"，与 docker/Dockerfile 恰好相反——
        # docs/27 C2「提示与镜像不一致」的同类，只是藏在一行 note 里。现在两者都
        # 在镜像里，note 只在真跑得动时点名，否则退回 xxd + 标准库。
        trail = "`binwalk {p}` 让签名库认内嵌容器，" if shutil.which("binwalk") else ""
        lines.append(
            (
                "note: 熵 >7.2，多半是压缩/加密过的——先用 `xxd {p} | head -40` 看头部魔数，"
                + trail
                + "再用 python 的 zlib/gzip/lzma 或 `unpack_archive('{p}')` 逐个试，别硬读。"
            ).format(p=target.name)
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
