"""A/B 开关的接线回归：机制模块读的每个 CTF_* 开关都必须能穿过 batch_eval。

2026-11-17 Q2 首跑的空臂事故（CTF_RECOVERY_NOTICE 已 export、子进程里却没装上）
根因就是 batch_eval 的子进程 env 是显式白名单。这里从源码扫描两侧：
机制模块（guard / mechanism 安装路径）读的开关集合，必须 ⊆ 白名单键集合。
新增 Q 项时只要机制代码落在这几个模块里，忘了白名单会当场红。
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: 机制/守卫安装路径上的模块。新增机制模块时把文件名加进来。
MECHANISM_MODULES = (
    "src/ctf_strix/tool_trim.py",
    "src/ctf_strix/enum_guard.py",
    "src/ctf_strix/discovery.py",
    "src/ctf_strix/recovery_notice.py",
)

BATCH_EVAL = ROOT / "scripts" / "batch_eval.py"
_SWITCH_RE = re.compile(r'os\.environ\.get\("((?:CTF|STRIX)_[A-Z_]+)"')
_ALLOWLIST_RE = re.compile(r'^\s*"((?:CTF|STRIX)_[A-Z_]+)":\s*os\.environ', re.M)


def _switches(path: Path) -> set[str]:
    return set(_SWITCH_RE.findall(path.read_text(encoding="utf-8")))


def test_every_mechanism_switch_reaches_the_batch_child_env():
    allow = set(_ALLOWLIST_RE.findall(BATCH_EVAL.read_text(encoding="utf-8")))
    assert allow, "batch_eval 白名单扫描失效（正则或文件位置变了）"
    missing: dict[str, set[str]] = {}
    for rel in MECHANISM_MODULES:
        src = ROOT / rel
        assert src.exists(), rel
        need = _switches(src)
        gap = need - allow
        if gap:
            missing[rel] = gap
    assert not missing, (
        "这些 A/B 开关进了机制模块却没进 batch_eval 子进程白名单，"
        f"ON 臂会是空臂：{missing}"
    )


def test_class_block_and_structural_are_in_the_allowlist():
    """已发生过事故/正在 A/B 的两个开关点名再验一次。"""
    allow = set(_ALLOWLIST_RE.findall(BATCH_EVAL.read_text(encoding="utf-8")))
    assert "CTF_STRUCTURAL" in allow
    assert "CTF_CLASS_BLOCK" in allow
    assert "CTF_RECOVERY_NOTICE" in allow