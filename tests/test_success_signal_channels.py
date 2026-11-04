"""Structured success signal from shell output and one-shot PoE probe.

Both paths exist because the platform can grade a challenge without handing
back a flag: the only correct evidence is the platform's own JSON boolean.
The negative cases below are the anti-forgery anchors -- a model must not be
able to manufacture a stop by printing JSON from a file it read locally.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types

import pytest

from ctf_strix.autosubmit import AutoSubmitter
from ctf_strix.finish_guard import FinishGuard, _MAX_REFUSALS
from ctf_strix.finish_guard import install as install_finish_guard
from ctf_strix.success_stop import (
    SolvedStop,
    SuccessLedger,
    install_exec_observer,
)

PLATFORM = "https://ctfy.example.test"
INSTANCE = "inst-1"
CHECK_URL = f"{PLATFORM}/api/v1/instances/{INSTANCE}/check"
#: Shell-quoted exactly as a real curl invocation has to be; shlex removes the
#: outer single quotes and leaves the JSON intact.
POST_BODY = '{"question_id":"q1"}'
VERDICT = (
    '{"passed":true,"question_id":"q1","exit_code":0,"timed_out":false,'
    '"already_solved":false,"solve_rank":34,"challenge_fully_solved":true}'
)


@pytest.fixture
def fake_factory(monkeypatch):
    """Stand-in for strix's factory, matching the real install seam."""
    from agents.tool import FunctionTool

    factory = types.ModuleType("strix.agents.factory")

    def _with_bounded_result(tool):
        return tool

    factory._with_bounded_result = _with_bounded_result
    strix_pkg = types.ModuleType("strix")
    agents_pkg = types.ModuleType("strix.agents")
    agents_pkg.factory = factory
    strix_pkg.agents = agents_pkg
    monkeypatch.setitem(sys.modules, "strix", strix_pkg)
    monkeypatch.setitem(sys.modules, "strix.agents", agents_pkg)
    monkeypatch.setitem(sys.modules, "strix.agents.factory", factory)
    return factory, FunctionTool


def _tool(FunctionTool, name: str, output: str):
    async def invoke(ctx, raw):
        return output

    return FunctionTool(
        name=name,
        description="probe",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


def _command(cmd: str) -> str:
    return json.dumps({"cmd": cmd})


def _observe(fake_factory, ledger: SuccessLedger, command: str, output: str, *, name="exec_command"):
    factory, FunctionTool = fake_factory
    assert install_exec_observer(
        ledger, platform_url=PLATFORM, instance=INSTANCE, question_ids=("q1",)
    ) is True
    wrapped = factory._with_bounded_result(_tool(FunctionTool, name, output))
    return factory, wrapped, command


def _curl(*extra: str) -> str:
    """Build the same curl shape the platform probe uses (inline JSON body)."""
    body = "'" + POST_BODY + "'"
    return " ".join(("curl", "-s", "-X", "POST", *extra, "-d", body, CHECK_URL))


# --------------------------------------------------------------------------
# A. exec verdict capture
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["exec_command", "write_stdin"])
def test_exec_output_with_platform_verdict_marks_the_ledger(fake_factory, name) -> None:
    ledger = SuccessLedger()
    _factory, tool, command = _observe(
        fake_factory, ledger, _command(_curl()), VERDICT, name=name
    )
    with pytest.raises(SolvedStop):
        asyncio.run(tool.on_invoke_tool(None, command))
    assert ledger.solved
    assert ledger.source == "exec_verdict"
    assert ledger.detail == "passed=true"


def test_exec_real_shell_envelope_is_parsed(fake_factory) -> None:
    """The SDK prefixes the body with headers; the verdict is still top-level."""
    ledger = SuccessLedger()
    envelope = (
        "Chunk ID: abc123\nWall time: 0.1234 seconds\n"
        "Process exited with code 0\nOutput:\n" + VERDICT + "\n"
    )
    _factory, tool, command = _observe(
        fake_factory, ledger, _command(_curl()), envelope
    )
    with pytest.raises(SolvedStop):
        asyncio.run(tool.on_invoke_tool(None, command))
    assert ledger.solved and ledger.source == "exec_verdict"


def test_typed_input_cannot_borrow_the_opening_command(fake_factory) -> None:
    """Opening a legit curl session then typing `cat forged` must not count."""
    factory, FunctionTool = fake_factory
    ledger = SuccessLedger()
    assert install_exec_observer(
        ledger, platform_url=PLATFORM, instance=INSTANCE, question_ids=("q1",)
    ) is True
    start = _tool(FunctionTool, "exec_command", "Process running with session ID 4242")
    asyncio.run(
        factory._with_bounded_result(start).on_invoke_tool(
            None, _command(_curl())
        )
    )
    typed = _tool(FunctionTool, "write_stdin", VERDICT)
    wrapped = factory._with_bounded_result(typed)
    assert asyncio.run(
        wrapped.on_invoke_tool(
            None, json.dumps({"session_id": 4242, "chars": "cat forged.json\n"})
        )
    ) == VERDICT
    assert not ledger.solved


def test_write_stdin_uses_the_command_that_opened_the_session(fake_factory) -> None:
    """A real poll carries only session_id; the opening command is the anchor."""
    factory, FunctionTool = fake_factory
    ledger = SuccessLedger()
    assert install_exec_observer(
        ledger, platform_url=PLATFORM, instance=INSTANCE, question_ids=("q1",)
    ) is True
    start = _tool(
        FunctionTool,
        "exec_command",
        "Chunk ID: abc123\nProcess running with session ID 4242\nOutput:\nwaiting",
    )
    started = factory._with_bounded_result(start)
    asyncio.run(started.on_invoke_tool(None, _command(_curl())))
    assert not ledger.solved

    poll = _tool(FunctionTool, "write_stdin", VERDICT)
    polled = factory._with_bounded_result(poll)
    with pytest.raises(SolvedStop):
        asyncio.run(
            polled.on_invoke_tool(
                None, json.dumps({"session_id": 4242, "chars": ""})
            )
        )
    assert ledger.solved and ledger.source == "exec_verdict"


def test_exec_without_platform_host_does_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    _factory, tool, command = _observe(
        fake_factory, ledger, _command("cat /tmp/verdict.json"), VERDICT
    )
    assert asyncio.run(tool.on_invoke_tool(None, command)) == VERDICT
    assert not ledger.solved


def test_exec_without_verdict_path_does_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    _factory, tool, command = _observe(
        fake_factory, ledger, _command(f"curl -s {PLATFORM}/api/v1/instances/inst-1"), VERDICT
    )
    assert asyncio.run(tool.on_invoke_tool(None, command)) == VERDICT
    assert not ledger.solved


def test_exec_command_field_is_the_only_command_anchor(fake_factory) -> None:
    """An unrelated JSON field must not supply the platform host."""
    ledger = SuccessLedger()
    raw = json.dumps(
        {
            "cmd": "cat forged.json",
            "workdir": f"{PLATFORM}/api/v1/instances/inst-1/check",
        }
    )
    _factory, tool, command = _observe(fake_factory, ledger, raw, VERDICT)
    assert asyncio.run(tool.on_invoke_tool(None, command)) == VERDICT
    assert not ledger.solved


def test_exec_platform_host_must_be_a_host_token(fake_factory) -> None:
    """A lookalike hostname is not the platform host."""
    ledger = SuccessLedger()
    lookalike = f"https://x{PLATFORM.split('://', 1)[1]}/api/v1/instances/inst-1/check"
    _factory, tool, command = _observe(
        fake_factory, ledger, _command(_curl().replace(CHECK_URL, lookalike)), VERDICT
    )
    assert asyncio.run(tool.on_invoke_tool(None, command)) == VERDICT
    assert not ledger.solved


def test_exec_prose_mentioning_passed_does_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    _factory, tool, command = _observe(
        fake_factory,
        ledger,
        _command(_curl()),
        "the checker said passed:true, but this is prose",
    )
    assert asyncio.run(tool.on_invoke_tool(None, command)).startswith("the checker")
    assert not ledger.solved


def test_exec_json_with_false_verdict_does_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    _factory, tool, command = _observe(
        fake_factory, ledger, _command(_curl()), '{"passed":false}'
    )
    assert asyncio.run(tool.on_invoke_tool(None, command)) == '{"passed":false}'
    assert not ledger.solved


def test_exec_nested_verdict_does_not_mark(fake_factory) -> None:
    """A page body nested under another key is not a platform envelope."""
    ledger = SuccessLedger()
    _factory, tool, command = _observe(
        fake_factory,
        ledger,
        _command(_curl()),
        '{"body":{"passed":true}}',
    )
    assert asyncio.run(tool.on_invoke_tool(None, command)) == '{"body":{"passed":true}}'
    assert not ledger.solved


def test_exec_array_wrapped_verdict_does_not_mark(fake_factory) -> None:
    """The platform returns envelopes, not a list of envelopes."""
    ledger = SuccessLedger()
    output = f"[{VERDICT}]"
    _factory, tool, command = _observe(
        fake_factory,
        ledger,
        _command(_curl()),
        output,
    )
    assert asyncio.run(tool.on_invoke_tool(None, command)) == output
    assert not ledger.solved




# --------------------------------------------------------------------------
# C. forged-anchor counterexamples (review #4-9)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        # /check.json is a file name, not the check endpoint.
        f"curl -s -X POST -d '{POST_BODY}' {PLATFORM}/api/v1/instances/{INSTANCE}/check.json",
        # Writing the URL to a file and cat-ing it back must not qualify.
        f"echo 'https://{PLATFORM.split('://', 1)[1]}/api/v1/instances/{INSTANCE}/check' "
        f"> /tmp/check.json; cat /tmp/check.json",
        # Shell concatenation hides the program from shlex.
        f"printf x | curl -s -X POST -d '{POST_BODY}' {CHECK_URL}",
        # A different host that merely contains the platform name.
        f"curl -s -X POST -d '{POST_BODY}' "
        f"https://evil{PLATFORM.split('://', 1)[1]}/api/v1/instances/{INSTANCE}/check",
    ],
)
def test_exec_forged_anchor_does_not_mark(fake_factory, command) -> None:
    ledger = SuccessLedger()
    _factory, tool, raw = _observe(fake_factory, ledger, _command(command), VERDICT)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == VERDICT
    assert not ledger.solved


def test_exec_echo_and_cat_with_a_legit_url_does_not_mark(fake_factory) -> None:
    """The exact review bypass: a real URL in the command, forged JSON in a file."""
    ledger = SuccessLedger()
    command = f"echo {CHECK_URL} > /tmp/check.json; cat /tmp/check.json"
    _factory, tool, raw = _observe(fake_factory, ledger, _command(command), VERDICT)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == VERDICT
    assert not ledger.solved


def test_exec_two_concatenated_json_objects_do_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    _factory, tool, raw = _observe(
        fake_factory, ledger, _command(_curl()), VERDICT + VERDICT
    )
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == VERDICT + VERDICT
    assert not ledger.solved


def test_exec_question_id_mismatch_does_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    mismatch = VERDICT.replace('"question_id":"q1"', '"question_id":"other"')
    _factory, tool, raw = _observe(fake_factory, ledger, _command(_curl()), mismatch)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == mismatch
    assert not ledger.solved


def test_exec_request_body_must_name_the_same_question(fake_factory) -> None:
    ledger = SuccessLedger()
    command = _curl().replace(POST_BODY, '{"question_id":"other"}')
    _factory, tool, raw = _observe(fake_factory, ledger, _command(command), VERDICT)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == VERDICT
    assert not ledger.solved


def test_exec_timed_out_verdict_does_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    timed_out = VERDICT.replace('"timed_out":false', '"timed_out":true')
    _factory, tool, raw = _observe(fake_factory, ledger, _command(_curl()), timed_out)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == timed_out
    assert not ledger.solved


def test_exec_get_is_not_a_check_post(fake_factory) -> None:
    ledger = SuccessLedger()
    get = f"curl -s {CHECK_URL}"
    _factory, tool, raw = _observe(fake_factory, ledger, _command(get), VERDICT)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == VERDICT
    assert not ledger.solved


def test_exec_resolve_override_does_not_mark(fake_factory) -> None:
    ledger = SuccessLedger()
    command = _curl("--resolve", "ctfy.example.test:443:127.0.0.1")
    _factory, tool, raw = _observe(fake_factory, ledger, _command(command), VERDICT)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == VERDICT
    assert not ledger.solved


@pytest.mark.parametrize(
    "option",
    [
        "--resolve=ctfy.example.test:443:127.0.0.1",
        "--connect-to=ctfy.example.test:443:127.0.0.1:443",
        "--proxy=http://127.0.0.1:8080",
        "--unix-socket=/tmp/forged.sock",
    ],
)
def test_exec_equals_form_of_a_redirect_option_does_not_mark(
    fake_factory, option
) -> None:
    """``--resolve=...`` is the same redirection as ``--resolve ...``."""
    ledger = SuccessLedger()
    command = _curl(option)
    _factory, tool, raw = _observe(fake_factory, ledger, _command(command), VERDICT)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == VERDICT
    assert not ledger.solved

def test_exec_host_only_in_the_output_does_not_mark(fake_factory) -> None:
    """The request went elsewhere; a platform URL inside the body proves nothing."""
    ledger = SuccessLedger()
    command = _curl().replace(
        CHECK_URL, f"https://attacker.invalid/api/v1/instances/{INSTANCE}/check"
    )
    output = VERDICT.replace('"passed":true', f'"passed":true,"url":"{CHECK_URL}"')
    _factory, tool, raw = _observe(fake_factory, ledger, _command(command), output)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == output
    assert not ledger.solved

def test_exec_truncated_verdict_does_not_mark(fake_factory) -> None:
    """A verdict cut by the output bound is not a complete JSON object."""
    ledger = SuccessLedger()
    truncated = VERDICT[:40] + "\n...[truncated 120 chars]"
    _factory, tool, raw = _observe(fake_factory, ledger, _command(_curl()), truncated)
    assert asyncio.run(tool.on_invoke_tool(None, raw)) == truncated
    assert not ledger.solved


# --------------------------------------------------------------------------
# D. multi-question and already-solved policy
# --------------------------------------------------------------------------


def test_multi_question_check_requires_fully_solved() -> None:
    ledger = SuccessLedger()
    sub, _posted = _poe_submitter(
        {"passed": True, "question_id": "q1", "timed_out": False,
         "challenge_fully_solved": False},
        ledger,
    )
    assert sub.probe_checkers(
        question_ids=["q1", "q2"], known_question_ids=["q1", "q2"]
    ) is False
    assert not ledger.solved


def test_multi_question_check_passes_when_fully_solved() -> None:
    ledger = SuccessLedger()
    sub, _posted = _poe_submitter(
        {"passed": True, "question_id": "q1", "timed_out": False,
         "challenge_fully_solved": True},
        ledger,
    )
    assert sub.probe_checkers(
        question_ids=["q1", "q2"], known_question_ids=["q1", "q2"]
    ) is True
    assert ledger.solved


def test_multi_question_submission_requires_fully_solved() -> None:
    """A single correct answer on a two-question challenge is not a solve."""
    ledger = SuccessLedger()
    sub = AutoSubmitter(PLATFORM, INSTANCE, "tok", success=ledger)
    sub._questions = lambda: [  # type: ignore[method-assign]
        {"id": "q1", "mode": "dynamic"},
        {"id": "q2", "mode": "dynamic"},
    ]

    def fake_post(path: str, body: dict) -> dict:
        if path.endswith("/verify-answer"):
            return {"error": "HTTP 404"}
        if body["question_id"] == "q1" and body["answer"] == "FLAG{one}":
            return {"correct": True, "question_id": "q1",
                    "challenge_fully_solved": False}
        return {"correct": False, "question_id": body["question_id"]}

    sub._post = fake_post  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{one}")
    assert verdict["correct"] == ["q1=FLAG{one}"]
    assert verdict["challenge_fully_solved"] is False
    assert not ledger.solved


def test_finish_guard_does_not_probe_after_a_platform_solve() -> None:
    """A recorded solve wins before the flag check; no second HTTP call."""
    ledger = SuccessLedger()
    ledger.mark("checker", "passed=true")
    calls: list[int] = []

    def checker() -> bool:
        calls.append(1)
        return False

    guard = FinishGuard(success=ledger, checker=checker)
    assert guard.check('{"summary": "no flag, platform already said solved"}') is None
    assert calls == []
    assert guard.allowed == 1


def test_check_async_does_not_block_the_event_loop() -> None:
    """A slow synchronous checker must run off the loop, not freeze it."""
    import time

    def checker() -> bool:
        time.sleep(0.25)
        return False

    guard = FinishGuard(checker=checker)

    async def scenario() -> list[int]:
        ticks: list[int] = []

        async def ticker() -> None:
            while True:
                ticks.append(1)
                await asyncio.sleep(0.02)

        task = asyncio.create_task(ticker())
        refusal = await guard.check_async('{"summary": "no flag"}')
        task.cancel()
        assert refusal is not None
        return ticks

    ticks = asyncio.run(scenario())
    assert len(ticks) >= 3, f"event loop was blocked: {len(ticks)} ticks"


def test_sync_check_never_performs_the_probe() -> None:
    """The legacy sync path must not issue HTTP from inside an event loop."""
    calls: list[int] = []

    def checker() -> bool:
        calls.append(1)
        return False

    guard = FinishGuard(checker=checker)
    assert guard.check('{"summary": "no flag"}') is not None
    assert calls == []
    # The probe is still available to the async wrapper.
    assert asyncio.run(guard.check_async('{"summary": "no flag"}')) is not None
    assert calls == [1]


def test_finish_guard_negative_probe_is_cached_for_the_run() -> None:
    """Documents the cost of caching a miss: a later solve is not re-probed.

    The first finish is refused; the platform then reports solved, but the
    cached negative result keeps refusing.  A later channel (exec verdict,
    autosubmit) or the refusal budget is the escape hatch, as documented on
    ``CheckerProbe``.
    """
    from ctf_strix.autosubmit import CheckerProbe

    ledger = SuccessLedger()
    sub, posted = _poe_submitter(
        {"passed": False, "question_id": "q1", "timed_out": False}, ledger
    )
    probe = CheckerProbe(sub, question_ids=["q1"], known_question_ids=["q1"])
    guard = FinishGuard(success=ledger, checker=probe.check)
    assert asyncio.run(guard.check_async('{"summary": "no flag"}')) is not None

    sub._post = lambda path, body: {  # type: ignore[method-assign]
        "passed": True,
        "question_id": "q1",
        "timed_out": False,
        "challenge_fully_solved": True,
    }
    assert asyncio.run(guard.check_async('{"summary": "solved now"}')) is not None
    assert len(posted) == 1
    assert not ledger.solved


def test_checker_probe_shares_one_cache_between_guards() -> None:
    """Finish and recovery guards must not each issue their own HTTP call."""
    from ctf_strix.autosubmit import CheckerProbe

    ledger = SuccessLedger()
    sub, posted = _poe_submitter(
        {"passed": False, "question_id": "q1", "timed_out": False}, ledger
    )
    probe = CheckerProbe(sub, question_ids=["q1"], known_question_ids=["q1"])
    finish = FinishGuard(success=ledger, checker=probe.check)
    recovery = FinishGuard(success=ledger, checker=probe.check)

    assert asyncio.run(finish.check_async('{"summary": "no flag"}')) is not None
    assert asyncio.run(recovery.check_async('{"summary": "still no flag"}')) is not None
    assert len(posted) == 1


def test_install_exec_observer_disarms_without_every_anchor() -> None:
    ledger = SuccessLedger()
    assert install_exec_observer(ledger, platform_url=PLATFORM) is False
    assert install_exec_observer(
        ledger, platform_url=PLATFORM, instance=INSTANCE
    ) is False
    assert install_exec_observer(
        ledger, platform_url="", instance=INSTANCE, question_ids=("q1",)
    ) is False


# --------------------------------------------------------------------------
# B. finish guard PoE probe
# --------------------------------------------------------------------------


def _poe_submitter(
    response: dict, success: SuccessLedger | None = None
) -> tuple[AutoSubmitter, list[tuple[str, dict]]]:
    sub = AutoSubmitter(PLATFORM, "inst-1", "tok", success=success)
    posted: list[tuple[str, dict]] = []

    def fake_post(path: str, body: dict) -> dict:
        posted.append((path, body))
        return response

    sub._post = fake_post  # type: ignore[method-assign]
    return sub, posted


def test_finish_guard_probe_allows_a_solved_poe_without_a_flag() -> None:
    ledger = SuccessLedger()
    sub, posted = _poe_submitter(
        {"passed": True, "question_id": "q1", "timed_out": False,
         "challenge_fully_solved": True}
    )
    guard = FinishGuard(
        success=ledger,
        checker=lambda: sub.probe_checkers(all_questions=True, question_ids=["q1"]),
    )
    assert asyncio.run(
        guard.check_async('{"summary": "side effect confirmed, no flag exists"}')
    ) is None
    assert posted == [("/api/v1/instances/inst-1/check", {"question_id": "q1"})]
    assert ledger.solved and ledger.source == "checker"


def test_finish_guard_probe_false_still_refuses() -> None:
    ledger = SuccessLedger()
    sub, _posted = _poe_submitter({"passed": False, "question_id": "q1"})
    guard = FinishGuard(
        success=ledger,
        checker=lambda: sub.probe_checkers(all_questions=True, question_ids=["q1"]),
    )
    assert asyncio.run(guard.check_async('{"summary": "no flag yet"}')) is not None
    assert not ledger.solved


def test_finish_guard_probe_runs_at_most_once_per_run() -> None:
    calls: list[int] = []

    def checker() -> bool:
        calls.append(1)
        return False

    guard = FinishGuard(checker=checker)
    assert asyncio.run(guard.check_async('{"summary": "no flag"}')) is not None
    assert asyncio.run(guard.check_async('{"summary": "still no flag"}')) is not None
    assert len(calls) == 1


def test_finish_guard_probe_http_failure_keeps_existing_policy() -> None:
    ledger = SuccessLedger()
    sub, _posted = _poe_submitter({"error": "HTTP 403: forbidden"})
    guard = FinishGuard(
        success=ledger,
        checker=lambda: sub.probe_checkers(all_questions=True, question_ids=["q1"]),
    )
    assert guard.refusals == 0
    for _ in range(_MAX_REFUSALS):
        assert asyncio.run(guard.check_async('{"summary": "no flag"}')) is not None
    assert asyncio.run(guard.check_async('{"summary": "no flag"}')) is None
    assert not ledger.solved
    assert guard.refusals == _MAX_REFUSALS


def test_finish_guard_probe_raising_is_silent() -> None:
    def checker() -> bool:
        raise TimeoutError("platform down")

    guard = FinishGuard(checker=checker)
    assert asyncio.run(guard.check_async('{"summary": "no flag"}')) is not None
    assert guard.refusals == 1


def test_installed_finish_guard_probe_allows_without_a_flag(fake_factory) -> None:
    factory, FunctionTool = fake_factory
    ledger = SuccessLedger()
    calls: list[int] = []

    def checker() -> bool:
        calls.append(1)
        return True

    guard = install_finish_guard(require_flag=True, success=ledger, checker=checker)
    assert guard is not None
    tool = _tool(FunctionTool, "finish_scan", "ok")
    wrapped = factory._with_bounded_result(tool)
    assert asyncio.run(wrapped.on_invoke_tool(None, '{"summary": "poe done"}')) == "ok"
    assert calls == [1]
    assert ledger.solved and ledger.source == "checker"


def test_probe_with_explicit_ids_does_not_need_a_metadata_get() -> None:
    """An empty question mode must not disable the PoE probe."""
    ledger = SuccessLedger()
    sub, posted = _poe_submitter(
        {"passed": True, "question_id": "q1", "timed_out": False}, ledger
    )

    def no_metadata() -> list[dict]:
        raise AssertionError("question_ids must bypass the metadata GET")

    sub._questions = no_metadata  # type: ignore[method-assign]
    assert sub.probe_checkers(all_questions=True, question_ids=["q1"]) is True
    assert posted == [("/api/v1/instances/inst-1/check", {"question_id": "q1"})]
    assert ledger.solved


def test_questions_403_falls_back_to_task_ids() -> None:
    """A forbidden metadata GET must not disable the probe."""
    import urllib.error

    sub = AutoSubmitter(
        PLATFORM, INSTANCE, "tok", fallback_question_ids=["q1", "q2"]
    )

    def denied(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://x", 403, "Forbidden", {}, None
        )

    orig = __import__("urllib.request", fromlist=["urlopen"]).urlopen
    import urllib.request

    urllib.request.urlopen = denied
    try:
        questions = sub._questions()
    finally:
        urllib.request.urlopen = orig
    assert [q["id"] for q in questions] == ["q1", "q2"]
    assert "403" in (sub.last_error or "")


def test_questions_403_falls_back_with_declared_modes() -> None:
    """A 403 fallback must not relabel dynamic questions as checker questions."""
    import urllib.error
    import urllib.request

    sub = AutoSubmitter(
        PLATFORM,
        INSTANCE,
        "tok",
        fallback_question_ids=["flag", "outage"],
        fallback_question_modes={"flag": "dynamic", "outage": ""},
    )
    orig = urllib.request.urlopen

    def denied(*_args, **_kwargs):
        raise urllib.error.HTTPError("https://x", 403, "Forbidden", {}, None)

    urllib.request.urlopen = denied
    try:
        questions = sub._questions()
    finally:
        urllib.request.urlopen = orig
    assert [(q["id"], q["mode"]) for q in questions] == [
        ("flag", "dynamic"),
        ("outage", ""),
    ]


def test_questions_403_without_ids_stays_empty() -> None:
    import urllib.error
    import urllib.request

    sub = AutoSubmitter(PLATFORM, INSTANCE, "tok")
    orig = urllib.request.urlopen

    def denied(*_args, **_kwargs):
        raise urllib.error.HTTPError("https://x", 403, "Forbidden", {}, None)

    urllib.request.urlopen = denied
    try:
        assert sub._questions() == []
    finally:
        urllib.request.urlopen = orig


def test_probe_skips_dynamic_questions_with_explicit_modes() -> None:
    """Dynamic/static/seeded ids must not be sent to /check."""
    ledger = SuccessLedger()
    sub, posted = _poe_submitter(
        {"passed": True, "question_id": "flag", "timed_out": False}, ledger
    )
    assert sub.probe_checkers(
        question_ids=["flag"],
        known_question_ids=["flag", "outage"],
        question_modes={"flag": "dynamic", "outage": "checker"},
    ) is False
    assert posted == []
    assert not ledger.solved


def test_probe_uses_a_checker_question_from_the_same_run() -> None:
    ledger = SuccessLedger()
    sub, posted = _poe_submitter(
        {"passed": True, "question_id": "outage", "timed_out": False,
         "challenge_fully_solved": True},
        ledger,
    )
    assert sub.probe_checkers(
        question_ids=["flag", "outage"],
        known_question_ids=["flag", "outage"],
        question_modes={"flag": "dynamic", "outage": "checker"},
    ) is True
    assert posted == [
        ("/api/v1/instances/inst-1/check", {"question_id": "outage"})
    ]


def test_platform_fully_solved_flag_beats_local_count() -> None:
    """Two local correct answers are not a solve if the platform says no."""
    ledger = SuccessLedger()
    sub = AutoSubmitter(PLATFORM, INSTANCE, "tok", success=ledger)
    sub._questions = lambda: [  # type: ignore[method-assign]
        {"id": "q1", "mode": "dynamic"},
        {"id": "q2", "mode": "dynamic"},
    ]

    def fake_post(path: str, body: dict) -> dict:
        if path.endswith("/verify-answer"):
            return {"error": "HTTP 404"}
        return {
            "correct": True,
            "question_id": body["question_id"],
            "challenge_fully_solved": False,
        }

    sub._post = fake_post  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{shared}")
    assert verdict["correct"] == ["q1=FLAG{shared}", "q2=FLAG{shared}"]
    assert verdict["challenge_fully_solved"] is False
    assert not ledger.solved


def test_platform_fully_solved_true_marks_a_multi_question_submission() -> None:
    ledger = SuccessLedger()
    sub = AutoSubmitter(PLATFORM, INSTANCE, "tok", success=ledger)
    sub._questions = lambda: [  # type: ignore[method-assign]
        {"id": "q1", "mode": "dynamic"},
        {"id": "q2", "mode": "dynamic"},
    ]

    def fake_post(path: str, body: dict) -> dict:
        if path.endswith("/verify-answer"):
            return {"error": "HTTP 404"}
        return {
            "correct": True,
            "question_id": body["question_id"],
            "challenge_fully_solved": True,
        }

    sub._post = fake_post  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{shared}")
    assert verdict["challenge_fully_solved"] is True
    assert ledger.solved and ledger.source == "platform_submit"


def test_submit_wrapper_runs_before_the_flag_guard(fake_factory) -> None:
    """A 32-hex slug must be submitted even though it is not FLAG-shaped.

    The last installed wrapper runs first, so autosubmit must be installed
    after finish_guard.  Otherwise the guard refuses and the only submission
    never happens.
    """
    factory, FunctionTool = fake_factory
    ledger = SuccessLedger()
    order: list[str] = []

    def checker() -> bool:
        order.append("probe")
        return False

    install_finish_guard(require_flag=True, success=ledger, checker=checker)

    from ctf_strix.autosubmit import install as install_autosubmit

    sub = AutoSubmitter(PLATFORM, INSTANCE, "tok", success=ledger)
    sub._questions = lambda: [  # type: ignore[method-assign]
        {"id": "slug", "mode": "dynamic"}
    ]

    def fake_post(path: str, body: dict) -> dict:
        if path.endswith("/verify-answer"):
            return {"error": "HTTP 404"}
        order.append("submit")
        return {
            "correct": body["answer"] == "0123456789abcdef0123456789abcdef",
            "question_id": body["question_id"],
        }

    sub._post = fake_post  # type: ignore[method-assign]
    install_autosubmit(
        PLATFORM, INSTANCE, "tok", success=ledger, submitter=sub
    )

    tool = _tool(FunctionTool, "finish_scan", "ok")
    wrapped = factory._with_bounded_result(tool)
    result = asyncio.run(
        wrapped.on_invoke_tool(
            None, '{"summary": "slug 0123456789abcdef0123456789abcdef"}'
        )
    )
    assert result.startswith("ok")
    assert order == ["submit"], order
    assert ledger.solved and ledger.source == "platform_submit"
