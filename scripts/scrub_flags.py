"""把仓库里"看得见的真实 flag"抹成占位符。

## 为什么需要这个脚本

技能包里 30+ 份 writeup 带着当年比赛的真 flag（``FLAG{d9ed...}``），
``docs/`` 与 ``reports/`` 里的历史复盘同理。这些文件对解题没有任何作用，
但 agent 用 ``read_file`` 或 ``grep -r`` 就能读到——一旦读进日志，
``flag_extract.fallback_flag``（唯一候选兜底）会把它当成答案交上去。
CTFARENA-035 的账就是这么烂掉的：人工解过、agent 又"解"了一次。

``skillpack.mask_flags`` 只在 ``load_skill`` 装载索引时生效，管不住
``read_file`` 与 shell。所以需要一次性把磁盘上的内容也清掉。

## 用法

    python scripts/scrub_flags.py            # 只统计，不改文件
    python scripts/scrub_flags.py --apply    # 真改

替换规则：``FLAG{73ea73...}`` → ``FLAG{...}``，前缀大小写保留。
``FLAG{...}`` 同时命中 ``flag_extract`` 的占位符排除规则，不会再被当成候选。
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

#: 与 ``flag_extract.FLAG_RE`` 保持同源的前缀集合；这里多认 ``ctfy``。
_FLAGISH = re.compile(r"(?i)\b(FLAG|CTF|CTFY)\{[0-9A-Za-z_\-]{2,}\}")

_SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache", "vendor"}

#: 默认扫描范围：agent 真的读得到的目录。
_DEFAULT_ROOTS = ("src/ctf_strix/skills_strix", "docs", "reports", "config")


def scrub_text(text: str) -> tuple[str, int]:
    """抹掉一段文本里的真实 flag。

    Args:
        text: 原文。

    Returns:
        ``(新文本, 替换次数)``。
    """
    count = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return m.group(1) + "{...}"

    return _FLAGISH.sub(repl, text), count


def iter_files(root: pathlib.Path):
    """遍历 root 下的文本文件，跳过构建产物目录。

    Args:
        root: 起始目录（也可以是单个文件）。

    Yields:
        文件路径。
    """
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in {".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".log", ".html"}:
            yield path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="抹掉仓库里可见的真实 flag")
    ap.add_argument("--apply", action="store_true", help="真的写回；默认只统计")
    ap.add_argument("roots", nargs="*", default=list(_DEFAULT_ROOTS), help="扫描根目录")
    args = ap.parse_args(argv)

    repo = pathlib.Path(__file__).resolve().parent.parent
    total_files = 0
    total_hits = 0
    for rel in args.roots:
        root = repo / rel
        if not root.exists():
            continue
        for path in iter_files(root):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            new, hits = scrub_text(text)
            if not hits:
                continue
            total_files += 1
            total_hits += hits
            print(f"{path.relative_to(repo)}  {hits}")
            if args.apply:
                path.write_text(new, encoding="utf-8")
    mode = "已改写" if args.apply else "仅统计（加 --apply 才写）"
    print(f"\n{mode}：{total_files} 个文件，{total_hits} 处 flag")
    return 0


if __name__ == "__main__":
    sys.exit(main())
