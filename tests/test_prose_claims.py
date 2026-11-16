"""常驻散文里的断言要有出处，不能凭印象写。

背景（台账 §4.243）：2026-11-16 复盘发现三处**无条件注入**的普适否定，它们
在若干真题上直接关掉了正确的机制类别：

* ``config/ctf_goal.txt`` 曾写「host-header tricks … have both been tried and
  return nothing」——而复盘的两道题（Host/origin 信任、按 Host 路由的边缘）
  机制正是 Host 头。
* 同一文件曾写「Wordlists and tools are already installed locally」——镜像里
  没有口令词表，一次登录爆破因此三次启动零完成。
* ``prompt.py`` 的 ``_targets_block`` 有同一句的简写版。

病根不是措辞，是**形式**：一句关于靶子或环境的普适断言写进常驻文本后，模型
没有任何办法反驳它，而它是否成立取决于下一道题。方法卡早就用 ``available``
过滤解决了同类问题（``skillpack.py``），常驻层一直没有对等约束。

这个测试是那条约束的最小实现：常驻散文里出现「no other / there is no」这类
断言式否定，必须在 ``ALLOW`` 里登记**理由**；反过来，``ALLOW`` 里登记的句子
如果已经从文件里消失，测试也会失败——理由过期和断言过期一样有害。
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: 无条件注入、每一道题都会看到的散文。
ALWAYS_ON = [
    *sorted((ROOT / "config").glob("*.txt")),
    ROOT / "src" / "ctf_strix" / "prompt.py",
    ROOT / "src" / "ctf_strix" / "catalogue.py",
]

#: 断言式否定的句式。命中即需要登记理由。
ASSERTIVE = re.compile(r"\b(no other|there is no|there are no)\b", re.I)

#: 曾经写错、被复盘证伪的句子。再写回来就直接失败，不看理由。
BANNED = (
    "no other port worth scanning",
    "have both been tried and return nothing",
    "subdomain guessing return nothing",
    "wordlists and tools are already installed",
    "there is no second host",
)

#: 允许保留的断言式否定：片段 -> 为什么它是安全的事实（而不是对靶子的预测）。
ALLOW: dict[str, str] = {
    "There is no single answer string": "engagement 交付形态，本文件即该 kind 的规格",
    "There is no single flag to find": "engagement 交付形态",
    "There is no flag for this challenge": "checker 类题目的判分规格",
    "there is no internet": "容器事实，构建期可验，且与 goal_preamble 一致",
    "There is no Docker": "容器事实，构建期可验",
    "no other direction": "对模型行为的约束，不是关于靶子的断言",
    "Nothing else counts": "计分口径，不是关于靶子的断言",
}


def _sentences(path: Path) -> list[tuple[int, str]]:
    """按段落合并后再切句。

    ⚠️ 必须跨行合并：``ctf_goal.txt`` 里那句错话原文是跨两行的
    （``Wordlists and tools are already`` / ``installed locally``），按行切句
    会**漏掉它**——审计脚本第一版就这么漏了一次。
    """
    text = path.read_text(encoding="utf-8")
    is_py = path.suffix == ".py"
    out: list[tuple[int, str]] = []
    para: list[str] = []
    start = 1
    for i, line in enumerate(text.splitlines(), 1):
        # Python 的注释不进上下文，扫它只会制造假警报（第一版就这么报了两条）。
        if is_py and line.lstrip().startswith("#"):
            continue
        if line.strip():
            if not para:
                start = i
            para.append(line.strip())
            continue
        if para:
            out.extend(_split(" ".join(para), start))
            para = []
    if para:
        out.extend(_split(" ".join(para), start))
    return out


def _split(block: str, start: int) -> list[tuple[int, str]]:
    return [(start, s.strip()) for s in re.split(r"(?<=[.!?])\s+", block) if s.strip()]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _hits():
    for path in ALWAYS_ON:
        if not path.exists():
            continue
        for ln, sent in _sentences(path):
            yield path, ln, sent


def test_banned_generalizations_are_gone():
    """被证伪过的那几句不许回来。"""
    found = []
    for path, ln, sent in _hits():
        low = _norm(sent).lower()
        for bad in BANNED:
            if bad in low:
                found.append(f"{path.relative_to(ROOT)}:{ln}: {sent[:120]}")
    assert not found, "被复盘证伪的普适否定又出现了：\n" + "\n".join(found)


def test_every_assertive_negative_has_a_reason():
    """每一句「no other / there is no」都必须登记理由。"""
    unregistered = []
    for path, ln, sent in _hits():
        if not ASSERTIVE.search(sent):
            continue
        if any(ok in sent for ok in ALLOW):
            continue
        unregistered.append(f"{path.relative_to(ROOT)}:{ln}: {sent[:160]}")
    assert not unregistered, (
        "这些断言式否定没有登记理由。它们会无条件注入每一道题，而模型无法反驳：\n"
        + "\n".join(unregistered)
        + "\n\n要么把它改成范围声明，要么在 ALLOW 里写清为什么它是可验证的事实。"
    )


def test_allowlist_entries_are_still_present():
    """理由过期和断言过期一样有害：登记过的句子 disappeared 也要报错。"""
    corpus = _norm(" ".join(s for _, _, s in _hits()))
    stale = [ok for ok in ALLOW if ok not in corpus]
    assert not stale, "ALLOW 里这些条目在文件中已不存在，应删除：\n" + "\n".join(stale)