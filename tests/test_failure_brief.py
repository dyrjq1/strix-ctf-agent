"""失败路径要能写进重试题面（用户要求）。

只测「该响的时候响」不够——这里同时覆盖：

- 计数够多时给出一行轨迹摘要；
- 计数太少时**不**硬编一行废话（避免重试提示被噪声占满）；
- 解出的题不产生失败事实；
- 不把任何目标字符串搬进提示（只用计数/布尔）。
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = REPO_ROOT / "scripts" / "batch_eval.py"
    spec = importlib.util.spec_from_file_location("batch_eval_fb", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["batch_eval_fb"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_activity_fact_summarises_a_wallclock_run() -> None:
    mod = _load()
    guard = {
        "reach": 92,
        "enum_keys": 23,
        "negative_groups": 17,
        "finish_refused": 2,
        "journey_authed": False,
        "journey_created": 1,
    }

    fact = mod._activity_fact(guard)

    assert fact.startswith("轨迹：")
    assert "92 次请求" in fact
    assert "23 个端点键" in fact
    assert "finish 被拒 2 次" in fact
    assert "未取得已认证会话" in fact
    assert len(fact) <= 140


def test_activity_fact_is_silent_when_there_is_nothing_to_say() -> None:
    mod = _load()

    assert mod._activity_fact({}) == ""
    assert mod._activity_fact({"reach": 3}) == ""  # 一个计数不构成轨迹
    assert mod._activity_fact({"reach": 3, "enum_keys": 0}) == ""


def test_activity_fact_does_not_claim_auth_failure_without_evidence() -> None:
    """没建过号/没用过旅程时不许断言「未取得已认证会话」。"""
    mod = _load()
    guard = {"reach": 10, "enum_keys": 4, "journey_authed": False}

    fact = mod._activity_fact(guard)

    assert "未取得已认证会话" not in fact
    assert "10 次请求" in fact


def test_failure_facts_put_the_activity_line_second() -> None:
    mod = _load()
    rec = {
        "correct": False,
        "stop_reason": "wallclock",
        "guard": {"reach": 40, "enum_keys": 9},
    }

    facts = mod._failure_facts(rec, None)

    assert facts[0] == "收场：wallclock"
    assert facts[1].startswith("轨迹：")
    assert len(facts) <= 3


def test_solved_runs_produce_no_failure_facts() -> None:
    mod = _load()

    assert mod._failure_facts({"correct": True, "guard": {"reach": 99}}, None) == []


def test_failure_facts_stay_short_with_rejections() -> None:
    mod = _load()
    rec = {
        "correct": False,
        "stop_reason": "no_progress",
        "answers_rejected": {"q1": "FLAG{nope}"},
        "guard": {"reach": 30, "enum_keys": 8},
    }

    facts = mod._failure_facts(rec, None)

    assert len(facts) == 3
    assert any(f.startswith("提交被判否") for f in facts)
    assert any(f.startswith("轨迹：") for f in facts)