"""task.json 解析：run_mode 之间形态差别很大，混用会让 agent 静默空转。"""

from __future__ import annotations

from typing import Any

import pytest

from ctf_strix.agent import (
    BRIEF_SCHEMA_VERSION,
    _attempt_count,
    _attempt_turns,
    _challenge_kind,
    _question_id,
    _scope_note,
    _target_endpoints,
    _target_specs,
    _targets_from,
    _truthy,
    _turn_budget,
)


def test_attempt_count_defaults_to_one(monkeypatch) -> None:
    monkeypatch.delenv("CTF_ATTEMPTS", raising=False)
    assert _attempt_count() == 1
    monkeypatch.setenv("CTF_ATTEMPTS", "9")
    assert _attempt_count() == 3
    monkeypatch.setenv("CTF_ATTEMPTS", "nope")
    assert _attempt_count() == 1


def test_attempt_turns_preserve_total() -> None:
    budgets = _attempt_turns(40, 2, 0.6)
    assert budgets == [24, 16]
    assert sum(budgets) == 40

    budgets = _attempt_turns(60, 3, 0.5)
    assert sum(budgets) == 60
    assert budgets[0] == 30
    assert all(value >= 1 for value in budgets)


def test_attempt_turns_single_attempt_is_unchanged() -> None:
    assert _attempt_turns(25, 1, 0.6) == [25]


def test_instance_scope_url() -> None:
    """instance 模式：scope 里是起好的实例 URL。"""
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": ["https://abc.node2.ctfy.run:443"],
        "questions": [{"id": "flag", "prompt": "the flag"}],
    }
    assert _targets_from(task) == ["https://abc.node2.ctfy.run:443"]
    assert _question_id(task) == "flag"


def test_engagement_scope_hosts() -> None:
    """engagement 模式：scope 是主机名，需要补 scheme 才能当 web 目标。"""
    task: dict[str, Any] = {
        "run_mode": "engagement",
        "scope": ["edge.meridian.test", "intranet.meridian.test"],
        "questions": [],
        "target_instance": "3f9c",
    }
    assert _targets_from(task) == [
        "https://edge.meridian.test",
        "https://intranet.meridian.test",
    ]


def test_engagement_cidr_not_turned_into_url() -> None:
    """网段不能拼成 https://10.20.0.0/16——那是个合法但无意义的 URL。"""
    task: dict[str, Any] = {
        "run_mode": "engagement",
        "scope": ["10.20.0.0/16", "edge.meridian.test"],
    }
    assert _targets_from(task) == ["https://edge.meridian.test"]


def test_instance_empty_scope_yields_nothing() -> None:
    """instance 模式 scope 为空 = 要自己起靶机，本层解析不出目标，如实返回空。"""
    task: dict[str, Any] = {"run_mode": "instance", "scope": [], "questions": []}
    assert _targets_from(task) == []


def test_question_id_falls_back() -> None:
    """没有 questions（engagement / awd）时退回 flag，而不是崩。"""
    assert _question_id({"questions": []}) == "flag"
    assert _question_id({}) == "flag"


@pytest.mark.parametrize(
    ("questions", "expected"),
    [
        ([{"id": "web", "prompt": "x"}], "web"),
        ([{"prompt": "no id"}], "flag"),
    ],
)
def test_question_id_variants(questions: list[dict[str, str]], expected: str) -> None:
    assert _question_id({"questions": questions}) == expected


def test_cidr_survives_into_scan_targets() -> None:
    """网段必须进 scope。

    旧实现只把主机名补成 URL，``10.20.0.0/16`` 直接丢掉——agent 看不到授权
    网段，只能扫题面里那一两个名字，engagement 的"一整套内网"就没了。
    """
    task: dict[str, Any] = {
        "run_mode": "engagement",
        "scope": ["edge.meridian.test", "10.20.0.0/16"],
    }
    specs = _target_specs(task)
    kinds = {s["type"] for s in specs}
    assert "web_application" in kinds
    assert "ip_address" in kinds
    assert any(s["details"].get("target_ip") == "10.20.0.0/16" for s in specs)


def test_tcp_host_port_is_not_truncated() -> None:
    """``host:port`` 原样进 scope，剥掉端口等于少给一条"服务在哪"。"""
    specs = _target_specs({"run_mode": "instance", "scope": ["10.0.0.5:1337"]})
    assert specs == [{"type": "ip_address", "details": {"target_ip": "10.0.0.5:1337"}}]


def test_scope_note_only_when_there_is_more_than_urls() -> None:
    """单 URL 题的指令不该多一段噪音；混合 scope 必须把原文给到 agent。"""
    single = {"run_mode": "instance", "scope": ["https://a.test"]}
    assert _scope_note(single) == ""

    mixed = {"run_mode": "engagement", "scope": ["edge.test", "10.20.0.0/16"]}
    note = _scope_note(mixed)
    assert "10.20.0.0/16" in note
    assert "authorized" in note


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), ("1", True), ("true", True), ("yes", True), ("0", False), ("false", False), (None, False)],
)
def test_truthy(value: object, expected: bool) -> None:
    assert _truthy(value) is expected


# ---------------------------------------------------------------- CTFY-0001 v3

def test_schema_version_matches_protocol_v3() -> None:
    """协议 v3（2026-10-30）把 schema_version 提到 3。

    写 2 不会立刻失败——平台忽略未知字段——但等于自报一个不认识
    ``target_endpoints`` 的客户端，而那条正是 v3 的唯一破坏性变更。
    """
    assert BRIEF_SCHEMA_VERSION == 3


def test_target_endpoints_only_instance_is_reachable() -> None:
    """v3 jeopardy：``scope`` 为空，靶址只在 ``target_endpoints``。

    回归的是最能致命的一种：只读 scope 的客户端会拿到空目标，把整题记成
    "无可扫描目标"——看着像题目坏了，其实一半的题都会这么被丢掉。
    """
    task: dict[str, Any] = {
        "schema_version": 3,
        "run_mode": "instance",
        "scope": [],
        "target_instance": "3f9c",
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://3f9c.ctfy.example:80"}
        ],
        "questions": [{"id": "flag", "prompt": "the flag"}],
    }
    assert _targets_from(task) == ["http://3f9c.ctfy.example:80"]
    assert _target_specs(task) == [
        {
            "type": "web_application",
            "details": {"target_url": "http://3f9c.ctfy.example:80"},
        }
    ]


def test_ctfy_target_url_env_is_a_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """台面只有一个 web 端点时平台改成环境变量，也要认。"""
    monkeypatch.setenv("CTFY_TARGET_URL", "https://only.ctfy.example")
    task: dict[str, Any] = {"run_mode": "instance", "scope": [], "questions": []}
    assert _targets_from(task) == ["https://only.ctfy.example"]


def test_ctfy_target_url_does_not_duplicate_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """同一个地址的两种写法不能变成两个目标，否则 agent 会当两台机器打。"""
    url = "http://3f9c.ctfy.example:80"
    monkeypatch.setenv("CTFY_TARGET_URL", url)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": [],
        "target_endpoints": [{"label": "web", "type": "http", "url": url}],
    }
    assert _targets_from(task) == [url]


def test_target_endpoints_keep_tcp_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """``type: tcp`` 的端点进 scope 时不能丢端口——TCP 题全靠它。"""
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": [],
        "target_endpoints": [{"label": "svc", "type": "tcp", "url": "10.0.0.5:1337"}],
    }
    assert _targets_from(task) == []
    assert _target_specs(task) == [
        {"type": "ip_address", "details": {"target_ip": "10.0.0.5:1337"}}
    ]


def test_challenge_kind_uses_endpoint_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """v3 明说了端点类型就别猜；scope 为空时这是唯一线索。"""
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    tcp = {
        "run_mode": "instance",
        "scope": [],
        "target_endpoints": [{"type": "tcp", "url": "10.0.0.5:1337"}],
    }
    assert _challenge_kind(tcp) == "tcp"

    web = {
        "run_mode": "instance",
        "scope": [],
        "target_endpoints": [{"type": "http", "url": "http://a.test"}],
    }
    assert _challenge_kind(web) == "web"


def test_scope_still_wins_when_both_are_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """老样本与本地 task.json 只有 scope；新增的来源不能把它们挤掉。"""
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": ["https://legacy.node2.ctfy.run:443"],
    }
    assert _targets_from(task) == ["https://legacy.node2.ctfy.run:443"]
    assert _target_endpoints(task) == []


def test_turn_budget_absent_means_no_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """协议是 absent means no budget；退回 25 会提前砍掉难题。

    这里断言的是"退回上游默认值"，不是某个具体数字——上游升级时数字可以变，
    但绝不能回到一个凭空的 25。
    """
    monkeypatch.delenv("CTFY_EVAL_MAX_TURNS", raising=False)
    monkeypatch.delenv("CTF_MAX_TURNS", raising=False)
    budget = _turn_budget({})
    assert budget >= 100


def test_turn_budget_prefers_task_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTFY_EVAL_MAX_TURNS", "42")
    assert _turn_budget({"max_turns": 7}) == 7


def test_turn_budget_ignores_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """0 表示"平台没给"，不是"零轮"；后者会让 run 立刻结束。"""
    monkeypatch.setenv("CTFY_EVAL_MAX_TURNS", "0")
    assert _turn_budget({"max_turns": 0}) >= 100
