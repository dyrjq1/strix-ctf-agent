"""task.json 解析：run_mode 之间形态差别很大，混用会让 agent 静默空转。"""

from __future__ import annotations

from typing import Any

import pytest

from ctf_strix.agent import (
    _question_id,
    _scope_note,
    _target_specs,
    _targets_from,
    _truthy,
    _turn_budget,
)


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
