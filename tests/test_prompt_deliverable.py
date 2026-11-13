"""核心提示必须按题型说对"交付物是什么、什么时候收工"。

BLOCKER 3（`ctfwork/codex-review-r6-out.md`）：`_CORE` 开头自称"唯一的分数是答案串，
没有报告要写"，`## Finish` 要求"答案串摆在眼前"才收工，代价最大失败模式段还要求放下
证据去读 flag。三句都对 engagement 反着说 —— 它的分数就是存下来的报告，没有答案串，
而且报告里每条结论都得带自己的请求/响应。goal 文件拼在核心提示下面，撤不回上面的话。

两条边界必须同时成立：

1. engagement 的渲染不得再出现那三句；
2. 其余四种题型的渲染与改动前逐字节相同（两处大小预算与既有行为都依赖它），
   这里用逐字字符串钉住被改的三个段落。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

FLAG_KINDS = ("web", "checker", "file", "tcp")

# 改动前 `_CORE` 的三段原文，逐字节抄下来。非 engagement 必须原样渲染出它们。
FLAG_DELIVERABLE = (
    "You are the solver for one CTF challenge on the CTFY platform. The only thing\n"
    "that scores is the answer string, graded exactly. There is no report to write.\n"
)
FLAG_FINISH = (
    "Call `finish_scan` only when the answer string is in front of you, quoted\n"
    "verbatim (case and braces matter). Before calling it, answer honestly: do I have\n"
    "execution/file/DB read, and did I actually read the secret — or only a schema?"
)
FLAG_PROOF = (
    "**Proof is not the deliverable.** If you have code execution, file read, or DB\n"
    "read, spend the same turn reading the answer: `find / -iname '*flag*'`,\n"
    "`cat /flag*`, `SELECT * FROM <table>`. A demonstrated vulnerability that you did\n"
    "not exploit is zero points."
)

# engagement 侧必须出现的判据短语（不钉全文，改措辞不必改测试）。
REPORT_MARKERS = (
    "what scores is the report you save",
    "an unsaved finding is worth zero",
    "An unwritten finding is not a finding",
    "when the report covers what you found",
)
PLACEHOLDERS = ("{deliverable}", "{finish}", "{proof}")


@pytest.fixture(autouse=True)
def _isolated_prompt(monkeypatch):
    """关掉环境变量覆盖，并在测试后恢复模块级 kind。"""
    from ctf_strix import prompt

    monkeypatch.delenv("CTF_PROMPT_OFF", raising=False)
    monkeypatch.delenv("CTF_PROMPT_OVERRIDE", raising=False)
    monkeypatch.setattr(prompt, "OVERRIDE", ROOT / "ctfwork" / ".bl3-no-override")
    before = prompt.active()
    yield
    prompt.activate(*before)


def _render(kind: str, **kwargs) -> str:
    from ctf_strix import prompt

    prompt.activate(kind, ("base", kind))
    return prompt.build({}, **kwargs)


def test_engagement_is_told_the_report_is_what_scores() -> None:
    text = _render("engagement", scan_mode="deep")
    assert "There is no report to write" not in text
    assert "answer string is in front of you" not in text
    assert "Proof is not the deliverable" not in text
    for marker in REPORT_MARKERS:
        assert marker in text, f"missing engagement marker: {marker}"


@pytest.mark.parametrize("kind", FLAG_KINDS)
def test_flag_challenges_keep_the_answer_string_deliverable(kind: str) -> None:
    text = _render(kind, scan_mode="deep")
    for block in (FLAG_DELIVERABLE, FLAG_FINISH, FLAG_PROOF):
        assert block in text, f"{kind} lost a pre-change paragraph"


def test_the_split_is_kind_based_not_mode_based() -> None:
    """quick 只该多注入收敛段；交付物那句仍按题型选，不该退回 flag 文案。"""
    from ctf_strix import prompt

    quick = _render("engagement", scan_mode="quick")
    assert "There is no report to write" not in quick
    assert "what scores is the report you save" in quick
    assert prompt._SCAN_QUICK.strip()[:20] in quick


def test_engagement_no_longer_renders_like_checker() -> None:
    """改前两者逐字节相同，说明题型信息在核心提示里完全没被用上。"""
    assert _render("engagement") != _render("checker")


def test_no_deliverable_placeholder_survives_rendering() -> None:
    for kind in ("web", "checker", "file", "tcp", "engagement"):
        for mode in ("deep", "quick"):
            text = _render(kind, scan_mode=mode)
            for placeholder in PLACEHOLDERS:
                assert placeholder not in text, f"{kind}/{mode} leaked {placeholder}"



def test_flag_finish_teaches_the_qid_answer_line() -> None:
    """带 question id 的任务要在收工条件里教 ``ANSWER[qid]=value`` 交付行。"""
    text = _render("web", scan_mode="deep")
    assert "ANSWER[<question_id>]=<value>" in text
