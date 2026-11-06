"""把仓库里"看得见的真实 flag"抹成占位符。

## 为什么需要这个脚本

技能包里 30+ 份 writeup 带着当年比赛的真 flag（形如 ``FLAG{`` + 一串十六进制 + ``}``），
``docs/`` 与 ``reports/`` 里的历史复盘同理。这些文件对解题没有任何作用，
但 agent 用 ``read_file`` 或 ``grep -r`` 就能读到——一旦读进日志，
``flag_extract.fallback_flag``（唯一候选兜底）会把它当成答案交上去。
CTFARENA-035 的账就是这么烂掉的：人工解过、agent 又"解"了一次。

``skillpack.mask_flags`` 只在 ``load_skill`` 装载索引时生效，管不住
``read_file`` 与 shell。所以需要一次性把磁盘上的内容也清掉。

## 用法

    python scripts/scrub_flags.py                        # 只统计，不改文件
    python scripts/scrub_flags.py --apply                # 真改
    python scripts/scrub_flags.py --check                # CI：有命中退 1，不写文件
    python scripts/scrub_flags.py --check docs reports   # 显式扫开发期台账

默认扫描面是 ``_DEFAULT_ROOTS``（``src`` + ``config``）——``docker/Dockerfile``
里 COPY 的就是这两个目录，agent 在容器里读得到下面任何文件。``docs/`` 与
``reports/`` **不在默认面**：它们不进镜像，要查就显式传路径。

扫描根不存在、或一个文件都没扫到，退出码都是 2。静默通过和"真的干净"在 CI
里长得一模一样，必须能区分。

替换规则：把 ``FLAG{`` 与 ``}`` 之间的真实内容抹成 ``...``，前缀大小写保留。
``FLAG{...}`` 同时命中 ``flag_extract`` 的占位符排除规则，不会再被当成候选。
代码里的模板（f-string / printf / ``${x}`` / 正则字符类）不抹，见
``flag_extract.is_code_template``。

``--apply`` 对 ``.py`` / ``.sh`` 只报告不改写：``flag{0x%x}`` 这类格式串的首字符
是字母数字，``is_code_template`` 判不出，改写会弄坏可执行示例。
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

#: 脚本允许直接 ``python scripts/scrub_flags.py`` 跑，不依赖 editable install。
_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "src"))

from ctf_strix.flag_extract import CANDIDATE_RE, is_code_template  # noqa: E402

_SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache", "vendor"}

#: 默认扫描范围：**镜像实际 COPY 的面**。``docker/Dockerfile`` 里是
#: ``COPY src /app/src`` + ``COPY config /app/config``，这两棵树里的任何文件
#: agent 都能用 ``exec_command cat`` 读到——包括源码与技能包里的 ``.py`` 脚本。
#:
#: ``docs/`` 与 ``reports/`` 是开发期台账，不进镜像，所以不在默认面——但
#: 那里面有历史真 flag，要查就显式传路径：
#: ``python scripts/scrub_flags.py --check docs reports``。
#:
#: ⚠️ 不要收窄回 ``src/ctf_strix/skills_strix``：那只是技能文本，而 agent
#: 还能读到 ``src/`` 里的源码。
_DEFAULT_ROOTS = ("src", "config")

#: ``--apply`` 只报告不改写的后缀：技能包里的可执行示例（``.py`` / ``.sh``）
#: 可能含 ``flag{0x%x}`` / ``FLAG{0:08x}`` 这类格式串，抹掉就不是能跑的代码了。
#: ``--check`` 对它们仍然算命中（fail-closed），闸门不会因此放行。
_REPORT_ONLY_SUFFIXES = frozenset({".py", ".sh"})

#: 会被当作文本扫描的后缀。``.py`` / ``.sh`` 必须在：技能包里有可被 agent
#: ``cat`` 的执行脚本；``.toml`` / ``.ini`` 是配置面常见的两种。
_TEXT_SUFFIXES = frozenset(
    {
        ".md",
        ".txt",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".log",
        ".html",
        ".py",
        ".sh",
        ".toml",
        ".ini",
    }
)

#: ``--check`` 只放过这四种**已知模板**：纯点、纯 x/X、尖括号包裹、纯星号。
#:
#: 不能复用 ``flag_extract.is_placeholder``：那是**提交层**的宽松口径
#: （体内一个字母数字都没有就算占位符），``FLAG{__..__}`` 这种在磁盘上
#: "看起来像答案"的残留会被它放过，于是 CI 闸门永远绿。
_TEMPLATE_RE = re.compile(
    r"(?:CTFY|FLAG|CTF)\{(?:\.{2,}|[xX]{2,}|<[^<>]*>|\*{3,})\}",
    re.IGNORECASE,
)


def _is_template(flag: str) -> bool:
    """磁盘上可以原样保留的模板形态（只有四种）。

    Args:
        flag: 一个候选答案。

    Returns:
        纯点 / 纯 x/X / 尖括号包裹 / 纯星号返回 True；其余一律 False。
    """
    return _TEMPLATE_RE.fullmatch((flag or "").strip()) is not None


def scrub_text(text: str) -> tuple[str, int]:
    """抹掉一段文本里的真实 flag；已是 ``FLAG{...}`` 的占位符原样保留。

    Args:
        text: 原文。

    Returns:
        ``(新文本, 替换次数)``。占位符不计入次数。
    """
    count = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        flag = m.group(0)
        if _is_template(flag) or is_code_template(flag):
            return flag
        count += 1
        return flag.split("{", 1)[0] + "{...}"

    return CANDIDATE_RE.sub(repl, text), count


def find_hits(text: str) -> list[tuple[int, str]]:
    """列出文本里尚未抹掉的候选答案。

    Args:
        text: 原文。

    Returns:
        ``(行号, 命中串)`` 列表；``FLAG{...}`` 这类占位符不算命中。
    """
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for match in CANDIDATE_RE.finditer(line):
            flag = match.group(0)
            if not (_is_template(flag) or is_code_template(flag)):
                hits.append((lineno, flag))
    return hits


def iter_files(root: pathlib.Path):
    """遍历 root 下的文本文件，跳过构建产物目录。

    Args:
        root: 起始目录（也可以是单个文件）。

    Yields:
        文件路径。
    """
    if root.is_file():
        if root.suffix.lower() in _TEXT_SUFFIXES:
            yield root
        return
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES:
            yield path


def _read_text(path: pathlib.Path) -> str | None:
    """按 UTF-8 读文本；读不了一律返回 None，由调用方计入 skipped。

    不用 ``read_text``：通用换行会把 CRLF 归一成 LF，``--apply`` 落盘时
    整份文件的换行就被改脏了。Windows 上的 ``.ini`` 常是 UTF-16LE，
    解码失败必须显式报告，不能静默从覆盖度里消失。
    """
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _warn_skipped(skipped: list[str]) -> None:
    """把解码失败的文件名打到 stderr：静默跳过等于虚报覆盖度。"""
    if not skipped:
        return
    print(
        f"警告：{len(skipped)} 个文件解码失败，已跳过（不计入 scanned）："
        + "、".join(skipped),
        file=sys.stderr,
    )


def _resolve(rel: str) -> pathlib.Path:
    """相对路径按仓库根解析；绝对路径原样使用（测试要能指向 tmp 目录）。"""
    path = pathlib.Path(rel)
    return path if path.is_absolute() else _REPO / path


def _display(path: pathlib.Path) -> str:
    """打印用路径：仓库内显示相对路径，仓库外显示绝对路径。"""
    try:
        return str(path.relative_to(_REPO))
    except ValueError:
        return str(path)


def _missing_roots(roots: list[str]) -> list[str]:
    """列出不存在的扫描根（相对路径按仓库根解析）。"""
    return [rel for rel in roots if not _resolve(rel).exists()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="抹掉仓库里可见的真实 flag")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="真的写回；默认只统计")
    mode.add_argument(
        "--check",
        action="store_true",
        help="只检查：有命中退 1，干净退 0；扫描根缺失或零文件退 2",
    )
    ap.add_argument("roots", nargs="*", default=list(_DEFAULT_ROOTS), help="扫描根目录")
    args = ap.parse_args(argv)

    missing = _missing_roots(args.roots)
    if missing:
        print("扫描根不存在：" + "、".join(missing), file=sys.stderr)
        return 2
    # 两种模式都回显扫了哪些根：漏传一个根和"真的干净"必须能分辨。
    print("扫描根：" + "、".join(args.roots))

    if args.check:
        total = 0
        scanned = 0
        skipped: list[str] = []
        for rel in args.roots:
            for path in iter_files(_resolve(rel)):
                text = _read_text(path)
                if text is None:
                    skipped.append(_display(path))
                    continue
                scanned += 1
                for lineno, flag in find_hits(text):
                    total += 1
                    print(f"{_display(path)}:{lineno}: {flag}")
        _warn_skipped(skipped)
        print(f"\n--check：{total} 处命中（scanned {scanned} files / {len(args.roots)} roots）")
        if scanned == 0:
            print("一个文件都没扫到：扫描根或后缀白名单不对", file=sys.stderr)
            return 2
        return 1 if total else 0

    total_files = 0
    total_hits = 0
    skipped_hits = 0
    skipped_files = 0
    scanned = 0
    skipped: list[str] = []
    for rel in args.roots:
        for path in iter_files(_resolve(rel)):
            # 用 bytes 读：``read_text`` 的通用换行会把 CRLF 归一成 LF。
            text = _read_text(path)
            if text is None:
                skipped.append(_display(path))
                continue
            scanned += 1
            if args.apply and path.suffix.lower() in _REPORT_ONLY_SUFFIXES:
                hits = find_hits(text)
                if not hits:
                    continue
                for lineno, flag in hits:
                    print(f"{_display(path)}:{lineno}: would scrub {flag}")
                skipped_files += 1
                skipped_hits += len(hits)
                continue
            new, hits = scrub_text(text)
            if not hits:
                continue
            total_files += 1
            total_hits += hits
            print(f"{_display(path)}  {hits}")
            if args.apply:
                # 用 bytes 落盘：``write_text`` 在 Windows 会把 \n 翻成 \r\n，
                # 一次清理就把整份 LF 文件改脏。
                path.write_bytes(new.encode("utf-8"))
    _warn_skipped(skipped)
    mode_text = "已改写" if args.apply else "仅统计（加 --apply 才写）"
    print(
        f"\n{mode_text}：{total_files} 个文件，{total_hits} 处 flag"
        f"（scanned {scanned} files / {len(args.roots)} roots）"
    )
    if skipped_hits:
        print(
            f"跳过 {skipped_hits} 处（可执行示例文件，{skipped_files} 个文件；"
            "--check 仍算命中，需人工确认）"
        )
    if scanned == 0:
        print("一个文件都没扫到：扫描根或后缀白名单不对", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
