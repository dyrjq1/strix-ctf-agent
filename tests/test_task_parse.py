"""task.json 解析：run_mode 之间形态差别很大，混用会让 agent 静默空转。"""

from __future__ import annotations

from typing import Any

import pytest

from ctf_strix.agent import (
    BRIEF_SCHEMA_VERSION,
    _attempt_count,
    _attempt_turns,
    _challenge_kind,
    _needs_value,
    _question_id,
    _question_ids,
    _record_answer,
    _round_note,
    _scope_note,
    _submittable_answers,
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


def test_question_ids_lists_every_visible_question() -> None:
    """Multiple visible questions each need their own key in ``answers``.

    Ledger 4.9: CTFARENA-001 kept ``my_fully_solved=false`` after a correct
    flag because only ``questions[0]`` was ever written.
    """
    task = {
        "questions": [
            {"id": "flag", "prompt": "the secret"},
            {"id": "xhr_token", "prompt": "the token"},
            {"id": "flag", "prompt": "duplicate must not repeat"},
        ]
    }
    assert _question_ids(task) == ["flag", "xhr_token"]
    assert _question_id(task) == "flag"


def test_record_answer_writes_every_visible_id() -> None:
    """One recovered value lands under every visible id, primary first."""
    answers: dict[str, str] = {}
    derived: set[str] = set()
    written = _record_answer(
        answers, ["flag", "xhr_token"], "CTFY{x}", "flag", derived=derived
    )
    assert written == ["flag", "xhr_token"]
    assert answers == {"flag": "CTFY{x}", "xhr_token": "CTFY{x}"}
    # Only the primary is evidence; the sibling is a guess.
    assert derived == {"xhr_token"}


def test_a_real_answer_replaces_an_earlier_guess() -> None:
    """Mirroring must not make the guess look like a known answer.

    Without the ``derived`` bookkeeping, the flag mirrored onto ``xhr_token``
    would block the real token found later in the same run -- strictly worse
    than never mirroring.
    """
    answers: dict[str, str] = {}
    derived: set[str] = set()
    _record_answer(answers, ["flag", "xhr_token"], "CTFY{flag}", "flag", derived=derived)
    _record_answer(answers, ["flag", "xhr_token"], "tok-real", "xhr_token", derived=derived)

    assert answers == {"flag": "CTFY{flag}", "xhr_token": "tok-real"}
    assert derived == set()


def test_a_second_finding_is_attributed_to_the_open_question() -> None:
    """The first hit must not mask the second one.

    With ``flag`` answered for real, a later finding is not "another flag" --
    the primary is closed, so the value belongs to the sibling id that is still
    only holding a mirror.
    """
    answers: dict[str, str] = {}
    derived: set[str] = set()
    _record_answer(answers, ["flag", "xhr_token"], "CTFY{first}", "flag", derived=derived)
    assert derived == {"xhr_token"}

    written = _record_answer(
        answers, ["flag", "xhr_token"], "tok-real", "flag", derived=derived
    )
    assert written[0] == "xhr_token"
    assert answers == {"flag": "CTFY{first}", "xhr_token": "tok-real"}
    assert derived == set()


def test_nothing_is_written_once_every_id_has_evidence() -> None:
    """A third finding must not clobber two real answers."""
    answers = {"flag": "CTFY{first}", "xhr_token": "tok-real"}
    derived: set[str] = set()
    assert _record_answer(answers, ["flag", "xhr_token"], "CTFY{third}", "flag",
                          derived=derived) == []
    assert answers == {"flag": "CTFY{first}", "xhr_token": "tok-real"}


def test_needs_value_treats_a_mirror_as_open() -> None:
    """A guessed key must keep the question open for real evidence."""
    answers = {"flag": "CTFY{x}", "xhr_token": "CTFY{x}"}
    derived = {"xhr_token"}
    assert _needs_value(answers, ["flag", "xhr_token"], derived) is True
    assert _needs_value(answers, ["flag"], derived) is False


def test_only_a_platform_confirmed_mirror_reaches_the_payload() -> None:
    """A mirror is submitted only when the platform accepted that exact value.

    Ledger 4.9 needs the second id to carry the same flag; P0-0 item 2 needs
    the platform not to spend an attempt on a guess.  Both hold together only
    for ``value == confirmed``.
    """
    answers: dict[str, str] = {}
    derived: set[str] = set()
    _record_answer(
        answers, ["flag", "xhr_token"], "CTFY{confirmed}", "flag", derived=derived
    )
    assert _submittable_answers(answers, derived, "CTFY{confirmed}") == {
        "flag": "CTFY{confirmed}",
        "xhr_token": "CTFY{confirmed}",
    }


def test_a_mirror_the_platform_never_confirmed_is_dropped() -> None:
    """Six candidates, one accepted: only the evidence value is submitted.

    The platform charges one wrong-answer attempt per key it finds in
    ``payload["answers"]``.  The mirror was the run's own guess, and the
    platform accepted a different string (or none), so it must not ship.
    """
    answers = {"flag": "CTFY{evidence}", "xhr_token": "CTFY{guess}"}
    derived = {"xhr_token"}
    assert _submittable_answers(answers, derived, "CTFY{evidence}") == {
        "flag": "CTFY{evidence}"
    }


def test_without_any_platform_verdict_no_mirror_is_submitted() -> None:
    """An offline run still reports its real answer, but not its guess."""
    answers = {"flag": "CTFY{x}", "xhr_token": "CTFY{x}"}
    derived = {"xhr_token"}
    assert _submittable_answers(answers, derived, "") == {"flag": "CTFY{x}"}
    # No mirrors at all: the map must survive untouched (single-id challenges,
    # and the qa/file kinds, all take this path).
    assert _submittable_answers(answers, set(), "") == answers


def test_a_later_guess_does_not_overwrite_an_earlier_real_answer() -> None:
    """A guess on ``flag`` must not overwrite a real ``xhr_token``."""
    answers = {"xhr_token": "tok-real"}
    derived: set[str] = set()
    _record_answer(answers, ["flag", "xhr_token"], "CTFY{guess}", "flag", derived=derived)
    assert answers["xhr_token"] == "tok-real"
    assert answers["flag"] == "CTFY{guess}"


def test_round_note_is_empty_without_a_readme(tmp_path: Path) -> None:
    """No briefing file at all (local run): nothing to point at."""
    assert _round_note(tmp_path) == ""


def test_first_round_briefing_is_pointed_at_but_not_quoted(tmp_path: Path) -> None:
    """``README.md`` exists from round one -- it is task.json as prose.

    Calling that "not the first round" would be a false statement about the
    platform's own file, so the first-round form only tells the model to read
    it.
    """
    (tmp_path / "README.md").write_text(
        "# Challenge\n\nRecover the flag from the target.\n", encoding="utf-8"
    )
    note = _round_note(tmp_path)
    assert "Read the platform briefing first" in note
    assert "not the first round" not in note
    assert "Recover the flag" not in note


def test_later_round_briefing_is_quoted_with_its_verdicts(tmp_path: Path) -> None:
    """From round two the briefing is the only record of what was already tried."""
    (tmp_path / "README.md").write_text(
        "# Round 2\n\nflag: wrong\nxhr_token: correct\n", encoding="utf-8"
    )
    note = _round_note(tmp_path)
    assert "not" in note and "first round" in note
    assert "newly unlocked" in note
    assert "xhr_token: correct" in note


def test_verdict_without_a_round_number_still_counts_as_later(tmp_path: Path) -> None:
    """The protocol's wording is the marker, not a specific header format."""
    (tmp_path / "README.md").write_text(
        "Questions\n- flag: not answered\n", encoding="utf-8"
    )
    note = _round_note(tmp_path)
    assert "first round" in note
    assert "not answered" in note


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


def test_web_endpoint_without_scheme_is_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WEB-8：type 说 http 而 url 缺 scheme 时按 type 补，不是原样塞进目标。"""
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": [],
        "target_endpoints": [{"label": "web", "type": "http", "url": "box.ctfy.example:80"}],
    }
    assert _targets_from(task) == ["http://box.ctfy.example:80"]


def test_web_endpoint_https_type_gets_https_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WEB-8：type=https 的裸地址补 https://，别一律按 http 打。"""
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": [],
        "target_endpoints": [{"label": "web", "type": "https", "url": "box.ctfy.example:443"}],
    }
    assert _targets_from(task) == ["https://box.ctfy.example:443"]


def test_schemeless_env_url_dedups_against_schemed_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WEB-8：环境变量裸地址归一后与端点去重——一个地址不当两台机器打。"""
    monkeypatch.setenv("CTFY_TARGET_URL", "box.ctfy.example:80")
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": [],
        "target_endpoints": [{"label": "web", "type": "http", "url": "http://box.ctfy.example:80"}],
    }
    assert _targets_from(task) == ["http://box.ctfy.example:80"]


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


def test_bare_attachment_at_work_root_is_a_file_challenge(monkeypatch, tmp_path) -> None:
    """2026-11-06：附件直接放在工作目录根上时，不能判成 no_target。

    有些投递方式既不给 ``attachments/`` 子目录，也不写 ``task.json.attachments``。
    SAMPLE-011 实测就是这么变成「0 回合、no_target」的。
    """
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {"run_mode": "instance", "scope": [], "target_endpoints": []}
    (tmp_path / "task.json").write_text("{}", encoding="utf-8")
    (tmp_path / "result.json").write_text("{}", encoding="utf-8")
    # 只有平台控制文件 → 仍是 web，不能把普通空目录误判成附件题。
    assert _challenge_kind(task, tmp_path) == "web"

    (tmp_path / "vaultsvc").write_bytes(b"\x7fELF")
    assert _challenge_kind(task, tmp_path) == "file"


def test_declared_attachments_still_win(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": [],
        "attachments": ["vaultsvc"],
    }
    assert _challenge_kind(task, tmp_path) == "file"


def test_checker_kind_needs_every_question_to_say_so(monkeypatch) -> None:
    """一个 checker 题 + 一个没写 mode 的题：后者可能是真要交 flag 的那道。

    旧实现把没有 ``mode`` 的 question 直接丢掉，于是集合只剩 ``{checker}``，
    整题判成 checker → ``require_flag=False`` → 真 flag 题可以无 flag 收工
    （报告 WEB-11）。缺省 mode 是"未知"，未知不能替它放弃 flag。
    """
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": ["https://a.test"],
        "questions": [{"id": "a", "mode": "checker"}, {"id": "b"}],
    }
    assert _challenge_kind(task) == "web"


def test_a_blank_mode_is_not_a_checker_declaration(monkeypatch) -> None:
    """``mode: " "`` 与没写 mode 一样是未知，不是"我是 checker"。"""
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": ["https://a.test"],
        "questions": [{"id": "a", "mode": "checker"}, {"id": "b", "mode": " "}],
    }
    assert _challenge_kind(task) == "web"


def test_all_checker_questions_still_short_circuit_the_flag_guard(monkeypatch) -> None:
    """收紧不能过头：每个 question 都声明 checker 时仍然让收工守卫让路。"""
    monkeypatch.delenv("CTFY_TARGET_URL", raising=False)
    task: dict[str, Any] = {
        "run_mode": "instance",
        "scope": ["https://a.test"],
        "questions": [{"id": "a", "mode": "checker"}, {"id": "b", "mode": "Checker"}],
    }
    assert _challenge_kind(task) == "checker"