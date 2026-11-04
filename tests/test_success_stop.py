"""Success-stop discipline: a solved run must end, not restart.

The bug this file pins is not "the agent failed to solve": it is "the agent
solved, said so in prose, and the runner restarted it from turn one because
the ending carried no lifecycle tool call".  Every positive signal below is
structured -- a validated flag or a direct platform verdict.  The negative
tests exist so a page body or a chat message containing ``passed:true`` can
never be mistaken for one.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from ctf_strix import agent as agent_mod
from ctf_strix.autosubmit import AutoSubmitter
from ctf_strix.finish_guard import FinishGuard
from ctf_strix.success_stop import (
    RECOVERY_LIMIT,
    RecoveryExhausted,
    SolvedStop,
    SuccessLedger,
    install_recovery_guard,
    uninstall_recovery_guard,
)


def _task(tmp_path) -> dict:
    return {
        "run_mode": "instance",
        "challenge": {"id": "X", "name": "x", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }


def _write_task(tmp_path, task: dict) -> None:
    (tmp_path / "task.json").write_text(json.dumps(task), encoding="utf-8")


@pytest.fixture
def guard():
    """Install the recovery guard and always restore the vendored method."""
    uninstall_recovery_guard()
    yield
    uninstall_recovery_guard()


# --------------------------------------------------------------------------
# structured-only ledger
# --------------------------------------------------------------------------


def test_ledger_accepts_only_top_level_json_true() -> None:
    ledger = SuccessLedger()
    assert ledger.observe_structured({"passed": True}, source="checker")
    assert ledger.solved and ledger.source == "checker"


@pytest.mark.parametrize(
    "response",
    [
        "passed: true",
        '{"passed": true}',
        {"body": "passed:true"},
        {"detail": "challenge_fully_solved: true"},
        {"passed": "true"},
        {"passed": 1},
        {"correct": False},
        None,
        ["passed", True],
    ],
)
def test_ledger_rejects_text_nested_and_non_boolean(response) -> None:
    """A page body or prose mentioning "passed" is not a verdict."""
    ledger = SuccessLedger()
    assert not ledger.observe_structured(response, source="checker")
    assert not ledger.solved


def test_ledger_records_only_the_first_source() -> None:
    ledger = SuccessLedger()
    ledger.observe_answer("FLAG{first}", source="flag_extract")
    ledger.observe_structured({"passed": True}, source="checker")
    assert ledger.source == "flag_extract"
    assert ledger.answer == "FLAG{first}"


def test_solved_stop_is_not_an_exception_subclass() -> None:
    """It has to pass through every ``except Exception`` in the runner."""
    with pytest.raises(SolvedStop):
        try:
            raise SolvedStop("solved")
        except Exception:
            pytest.fail("SolvedStop must derive from BaseException")


# --------------------------------------------------------------------------
# finish_guard: record only a flag it already accepted
# --------------------------------------------------------------------------


def test_finish_guard_marks_ledger_for_a_real_flag() -> None:
    ledger = SuccessLedger()
    guard = FinishGuard(success=ledger)
    assert guard.check('{"summary": "answer FLAG{abc123}"}') is None
    assert ledger.solved and ledger.source == "finish_guard"
    assert ledger.answer == "FLAG{abc123}"


def test_finish_guard_does_not_mark_on_placeholder_or_prose() -> None:
    ledger = SuccessLedger()
    guard = FinishGuard(success=ledger)
    assert guard.check('{"summary": "still looking, answer is FLAG{...}"}') is not None
    assert guard.check('{"summary": "passed:true on the results page"}') is not None
    assert not ledger.solved


def test_engagement_guard_never_claims_success() -> None:
    ledger = SuccessLedger()
    guard = FinishGuard(require_flag=False, success=ledger)
    assert guard.check('{"summary": "report saved"}') is None
    assert not ledger.solved


# --------------------------------------------------------------------------
# autosubmit: only direct response mappings
# --------------------------------------------------------------------------


def _submitter(ledger: SuccessLedger, response: dict) -> AutoSubmitter:
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok", success=ledger)
    sub._questions = lambda: [{"id": "flag", "mode": "dynamic"}]  # type: ignore[method-assign]
    calls: list[str] = []

    def fake_post(path: str, body: dict) -> dict:
        calls.append(path)
        if path.endswith("/verify-answer"):
            return {"error": "HTTP 404"}
        return response

    sub._post = fake_post  # type: ignore[method-assign]
    return sub


def test_autosubmit_marks_on_direct_submission_verdict() -> None:
    ledger = SuccessLedger()
    sub = _submitter(ledger, {"correct": True, "solve_rank": 20})
    verdict = sub.submit("FLAG{right}")
    assert verdict["correct"] == ["flag=FLAG{right}"]
    assert ledger.solved and ledger.answer == "FLAG{right}"
    assert ledger.source == "platform_submit"


def test_autosubmit_ignores_a_page_body_that_mentions_passed() -> None:
    ledger = SuccessLedger()
    sub = _submitter(ledger, {"body": "passed:true", "detail": "correct: true"})
    sub.submit("FLAG{candidate}")
    assert not ledger.solved, "free text in a response body is not a verdict"


def test_verify_answer_verdict_marks_ledger() -> None:
    ledger = SuccessLedger()
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok", success=ledger)

    def fake_post(path: str, body: dict) -> dict:
        if path.endswith("/verify-answer"):
            return {"correct": True, "question_id": "flag"}
        return {"correct": False}

    sub._post = fake_post  # type: ignore[method-assign]
    assert sub._verify("flag", "FLAG{ok}")["correct"] is True
    assert ledger.solved and ledger.source == "platform_verify"


def test_probe_checkers_uses_the_direct_check_response() -> None:
    ledger = SuccessLedger()
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok", success=ledger)
    sub._questions = lambda: [  # type: ignore[method-assign]
        {"id": "outage", "mode": "checker"},
        {"id": "flag", "mode": "dynamic"},
    ]
    posted: list[tuple[str, dict]] = []

    def fake_post(path: str, body: dict) -> dict:
        posted.append((path, body))
        return {"passed": True, "challenge_fully_solved": True}

    sub._post = fake_post  # type: ignore[method-assign]
    assert sub.probe_checkers() is True
    assert posted == [("/api/v1/instances/inst-1/check", {"question_id": "outage"})]
    assert ledger.source == "checker"


def test_probe_checkers_does_not_trust_the_page() -> None:
    ledger = SuccessLedger()
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok", success=ledger)
    sub._questions = lambda: [{"id": "outage", "mode": "checker"}]  # type: ignore[method-assign]
    sub._post = lambda path, body: {"body": "passed:true"}  # type: ignore[method-assign]
    assert sub.probe_checkers() is False
    assert not ledger.solved


# --------------------------------------------------------------------------
# recovery budget: bound the restart loop
# --------------------------------------------------------------------------


def _coordinator():
    from strix.core.agents import AgentCoordinator

    return AgentCoordinator()


def test_recovery_guard_stops_after_limit(guard) -> None:
    coord = _coordinator()
    install_recovery_guard(limit=3)

    async def run() -> list[int]:
        seen = []
        for _ in range(2):
            seen.append(await coord.record_recovery("root"))
        return seen

    assert asyncio.run(run()) == [1, 2]
    with pytest.raises(RecoveryExhausted):
        asyncio.run(coord.record_recovery("root"))


def test_recovery_guard_default_matches_runner_interactive_limit(guard) -> None:
    """The bound mirrors the vendored constant instead of inventing a budget."""
    from strix.core.execution import _INTERACTIVE_TOOL_RECOVERY_LIMIT

    assert RECOVERY_LIMIT == _INTERACTIVE_TOOL_RECOVERY_LIMIT == 3


def test_ablation_without_guard_restores_the_loop(guard) -> None:
    """Removing the change returns to an unbounded recovery count."""
    coord = _coordinator()
    uninstall_recovery_guard()

    async def old_behaviour() -> list[int]:
        return [await coord.record_recovery("root") for _ in range(5)]

    assert asyncio.run(old_behaviour()) == [1, 2, 3, 4, 5]


def test_recovery_guard_does_not_touch_subagents(guard) -> None:
    coord = _coordinator()
    coord.parent_of["child"] = "root"
    install_recovery_guard(limit=2)

    async def run() -> list[int]:
        return [await coord.record_recovery("child") for _ in range(4)]

    assert asyncio.run(run()) == [1, 2, 3, 4]


def test_recovery_guard_prefers_a_recorded_solve(guard) -> None:
    ledger = SuccessLedger()
    coord = _coordinator()
    install_recovery_guard(limit=3, ledger=ledger)
    ledger.observe_answer("FLAG{found}", source="flag_extract")
    with pytest.raises(SolvedStop):
        asyncio.run(coord.record_recovery("root"))


def test_recovery_guard_asks_the_checker_before_restarting(guard) -> None:
    ledger = SuccessLedger()
    coord = _coordinator()
    calls = {"n": 0}

    def checker() -> bool:
        calls["n"] += 1
        return True

    install_recovery_guard(limit=3, checker=checker, ledger=ledger)
    with pytest.raises(SolvedStop):
        asyncio.run(coord.record_recovery("root"))
    assert calls["n"] == 1
    assert ledger.solved and ledger.source == "checker"


def test_recovery_guard_checker_failure_is_not_a_solve(guard) -> None:
    coord = _coordinator()

    def checker() -> bool:
        raise RuntimeError("platform down")

    install_recovery_guard(limit=2, checker=checker)
    assert asyncio.run(coord.record_recovery("root")) == 1
    with pytest.raises(RecoveryExhausted):
        asyncio.run(coord.record_recovery("root"))


# --------------------------------------------------------------------------
# main: write result.json and exit 0
# --------------------------------------------------------------------------


def _prepare_main(tmp_path, monkeypatch) -> None:
    _write_task(tmp_path, _task(tmp_path))
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)


def test_main_turns_solved_stop_into_a_result_file(tmp_path, monkeypatch) -> None:
    _prepare_main(tmp_path, monkeypatch)

    def _solved(*args, **kwargs):
        raise SolvedStop("checker confirmed")

    monkeypatch.setattr(agent_mod, "_run_agent", _solved)
    try:
        assert agent_mod.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "solved"
        assert payload["writeup"].splitlines()[0].startswith("challenge:")
    finally:
        import os

        os.environ.pop("CTFY_SOFT_DEADLINE", None)


def test_main_normal_return_with_a_solved_ledger_is_spelled_solved(
    tmp_path, monkeypatch
) -> None:
    _prepare_main(tmp_path, monkeypatch)
    monkeypatch.setattr(
        agent_mod,
        "_run_agent",
        lambda *a, **k: (7, {"success": {"solved": True, "source": "checker"}}),
    )
    try:
        assert agent_mod.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "solved"
        assert payload["turns"] == 7
    finally:
        import os

        os.environ.pop("CTFY_SOFT_DEADLINE", None)


def test_main_reports_recovery_exhaustion_distinctly(tmp_path, monkeypatch) -> None:
    _prepare_main(tmp_path, monkeypatch)

    def _bounded(*args, **kwargs):
        raise RecoveryExhausted("agent ended 3 turns without a lifecycle tool call")

    monkeypatch.setattr(agent_mod, "_run_agent", _bounded)
    try:
        assert agent_mod.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "recovery_exhausted"
        assert "lifecycle" in payload["writeup"]
    finally:
        import os

        os.environ.pop("CTFY_SOFT_DEADLINE", None)


def test_main_without_a_success_signal_still_completes(tmp_path, monkeypatch) -> None:
    """The no-signal path must behave exactly as before."""
    _prepare_main(tmp_path, monkeypatch)
    monkeypatch.setattr(agent_mod, "_run_agent", lambda *a, **k: (9, {"success": {"solved": False}}))
    try:
        assert agent_mod.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "completed"
    finally:
        import os

        os.environ.pop("CTFY_SOFT_DEADLINE", None)


# --------------------------------------------------------------------------
# LiteLLM wiring fix
# --------------------------------------------------------------------------


def test_local_cost_map_is_enabled_before_litellm_import(monkeypatch) -> None:
    monkeypatch.delenv("LITELLM_LOCAL_MODEL_COST_MAP", raising=False)
    agent_mod._enable_local_cost_map()
    assert os_environ("LITELLM_LOCAL_MODEL_COST_MAP") == "True"


def test_local_cost_map_does_not_override_an_operator_value(monkeypatch) -> None:
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "False")
    agent_mod._enable_local_cost_map()
    assert os_environ("LITELLM_LOCAL_MODEL_COST_MAP") == "False"


def os_environ(name: str) -> str | None:
    import os

    return os.environ.get(name)
