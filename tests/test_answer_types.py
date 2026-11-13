# -*- coding: utf-8 -*-
"""题型适配（2026-11-13 夜）：选择题 choices、checker 提示、重试失败路径。

平台 questions 实测（playground 2026-11-13）：``mode`` 字段确实返回
（dynamic/static/checker/single_select/multi_select），choice 题带
``choices``。选择题答案必须逐字落在 choices 里，多选允许 list 或
逗号/空白切分——这是 CTFY-0002 v2 的原文规则。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402
from ctf_strix.autosubmit import fits_choices  # noqa: E402


# ---------------------------------------------------------------- choices
def test_fits_choices_single_select_exact() -> None:
    assert fits_choices("A", "single_select", ["A", "B", "C", "D"])
    # 逐字、大小写敏感：平台按原值比对，不会替我们归一化。
    assert not fits_choices("a", "single_select", ["A", "B", "C", "D"])
    assert not fits_choices("AB", "single_select", ["A", "B"])
    assert not fits_choices("", "single_select", ["A", "B"])


def test_fits_choices_multi_select_accepts_list_and_split() -> None:
    choices = ["A", "B", "C", "D", "E"]
    assert fits_choices("A,C", "multi_select", choices)
    assert fits_choices("A C", "multi_select", choices)
    assert fits_choices(["A", "E"], "multi_select", choices)
    assert not fits_choices("A,F", "multi_select", choices)
    assert not fits_choices(["A", "F"], "multi_select", choices)


def test_fits_choices_without_choices_is_permissive() -> None:
    assert fits_choices("anything at all", "dynamic", [])
    assert fits_choices("3", "checker", [])


# ---------------------------------------------------------------- 题面提示
def _detail(**over) -> dict:
    base = {
        "name": "Quiz",
        "category": "misc",
        "difficulty": "easy",
        "description": "answer the questions",
        "tags": [],
        "questions": [],
    }
    base.update(over)
    return base


def test_brief_lists_choices_and_multi_hint() -> None:
    brief = batch_eval._challenge_brief(_detail(questions=[
        {"id": "flag_format", "mode": "single_select", "choices": ["A", "B", "C", "D"]},
        {"id": "channels", "mode": "multi_select", "choices": ["A", "B", "C", "D", "E"]},
        {"id": "gate_field", "mode": "static", "choices": None},
    ]))
    assert "选择题选项" in brief
    assert "A, B, C, D" in brief
    assert "全部" in brief  # multi_select 的「选出全部」提示
    assert "ANSWER[" in brief


def test_brief_warns_checker_verify_is_unreliable() -> None:
    brief = batch_eval._challenge_brief(_detail(questions=[
        {"id": "persist", "mode": "checker", "choices": None},
    ]))
    assert "checker" in brief
    assert "verify-answer" in brief


def test_brief_single_non_flag_teaches_answer_line() -> None:
    brief = batch_eval._challenge_brief(_detail(questions=[
        {"id": "counter", "mode": "checker", "choices": None},
    ]))
    # checker 单问题也要教 ANSWER 交付格式，否则答案只留在摘要里。
    assert "ANSWER[counter]" in brief


# ---------------------------------------------------------------- 重试注入
def test_retry_notes_brief_reads_and_caps(tmp_path) -> None:
    p = tmp_path / "notes.txt"
    p.write_text("## 上一轮失败路径\n- 收场：no_signal\n", encoding="utf-8")
    text = batch_eval._retry_notes_brief(str(p))
    assert "no_signal" in text
    assert batch_eval._retry_notes_brief(str(tmp_path / "missing.txt")) == ""


def test_failure_facts_capture_rejected_answer() -> None:
    facts = batch_eval._failure_facts(
        {"correct": False, "error": None, "stop_reason": "no_signal",
         "answers_rejected": {"counter": "7"}},
        None,
    )
    assert any("no_signal" in x for x in facts)
    assert any("counter=7" in x for x in facts)
    assert batch_eval._failure_facts({"correct": True}, None) == []


def test_answer_values_split_on_json_escaped_newline() -> None:
    """run.log 里 finish_scan 的参数是原始 JSON，换行是字面 ``\\n``。

    SAMPLE-007 实测：``ANSWER[outage]=true\\n\\nAn availability ...`` 被旧
    正则整段吞成答案提交，平台判否；正确答案只有 ``true``。
    """
    raw = (
        r'TOOL finish_scan {"executive_summary":"answer: true\n'
        r'ANSWER[outage]=true\n\nAn availability assessment of the app..."}'
    )
    assert batch_eval._answer_values(raw) == {"outage": "true"}


# ---------------------------------------------------------------- 裁决 sidecar
import json  # noqa: E402

from ctf_strix.autosubmit import AutoSubmitter  # noqa: E402


def test_persist_keeps_best_verdict(monkeypatch, tmp_path) -> None:
    """先 ACCEPTED、后一次候选全错时，sidecar 不能丢掉已经答对的那次。

    这是 SAMPLE-001 的实测形态：run 内先解出 slug+flag，收尾又试了一批
    错候选。若直接覆盖，父进程读到的就是"全错"，已解出的题被判 FAILED。
    """
    path = tmp_path / "submit.json"
    monkeypatch.setenv("CTF_SUBMIT_PATH", str(path))
    sub = AutoSubmitter.__new__(AutoSubmitter)
    sub._persist({
        "tried": [{"qid": "slug", "correct": True}],
        "correct": ["slug=abc"],
        "challenge_fully_solved": True,
        "unlocked": ["flag"],
    })
    sub._persist({
        "tried": [{"qid": "flag", "correct": False}],
        "correct": [],
        "challenge_fully_solved": False,
    })
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["challenge_fully_solved"] is True
    assert data["correct"] == ["slug=abc"]
    assert data["unlocked"] == ["flag"]
    assert len(data["tried"]) == 2


def test_persist_noops_without_env(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("CTF_SUBMIT_PATH", raising=False)
    sub = AutoSubmitter.__new__(AutoSubmitter)
    sub._persist({"correct": ["x=1"], "challenge_fully_solved": True})
    assert list(tmp_path.iterdir()) == []


def test_read_submit_sidecar_tolerates_missing(tmp_path) -> None:
    assert batch_eval._read_submit_sidecar(tmp_path / "nope.json") == {}
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert batch_eval._read_submit_sidecar(p) == {}


# ---------------------------------------------------------------- qa_only
import compete  # noqa: E402


def test_qa_only_enters_queue_and_plan() -> None:
    chal = {
        "id": "SAMPLE-020", "difficulty": "easy", "category": "misc",
        "solves_count": 0, "is_qa_only": True, "questions": [],
    }
    assert compete.challenge_score(chal, {}, set()) is not None
    assert compete.build_plan_item("SAMPLE-020", chal)["qa_only"] is True