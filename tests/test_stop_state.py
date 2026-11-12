"""Stop-path accounting: a run stopped by ``BaseException`` still reports turns.

``SolvedStop`` / ``RecoveryExhausted`` / ``WallclockExceeded`` /
``OutputBudgetExceeded`` all inherit ``BaseException``, so they cross
``turns_used, diag = _run_agent(...)`` without that assignment ever running.
``result.json`` then said ``"turns": 0`` with no diagnostics, which makes
"stopped early after real work" indistinguishable from "never started" -- the
shape all three solved runs and the SAMPLE-007 wallclock run actually had.

The clean path and the four stop paths now share one snapshot, so the two are
directly comparable.  The real runner needs an LLM key and a sandbox backend,
neither of which this file is about; the fake below drives the same event sink
the vendor runner does.
"""

from __future__ import annotations

import json
import sys
import types

import pytest

import strix.core.runner as runner_mod

from ctf_strix import agent as agent_mod
from ctf_strix.success_stop import RecoveryExhausted, SolvedStop
from ctf_strix.usage_meter import OutputBudgetExceeded

#: Tool calls the fake runner emits before it stops the run.
CALLS = 3

#: A flag string no other test or skill file uses.
FLAG = "FLAG{stop_state_probe_4321}"


def _event(kind: str, *, call_id: str, output: str = "") -> object:
    return types.SimpleNamespace(
        item=types.SimpleNamespace(
            type=kind,
            output=output,
            call_id=call_id,
            raw_item=types.SimpleNamespace(
                name="exec_command", arguments="{}", call_id=call_id
            ),
        )
    )


def _emit(sink, count: int) -> None:
    for index in range(count):
        call_id = f"call-{index}"
        sink("root", _event("tool_call_item", call_id=call_id))
        sink(
            "root",
            _event("tool_call_output_item", call_id=call_id, output=f"output {index}"),
        )


def _fake_runner(exc: BaseException | None):
    """Emit ``CALLS`` tool calls through the sink, then stop the run."""

    async def _run(**kwargs):  # noqa: ANN003 - mirrors run_strix_scan's kwargs
        _emit(kwargs["event_sink"], CALLS)
        if exc is not None:
            raise exc
        return types.SimpleNamespace()

    return _run


@pytest.fixture()
def run_env(tmp_path, monkeypatch):
    """Point ``main`` at an isolated work dir and neutralize the watchdogs."""
    # ``ctf_strix.local_backend`` refuses to import on Windows; the stub keeps
    # the test platform-independent and never touches a real sandbox.
    stub = types.ModuleType("ctf_strix.local_backend")
    stub.install = lambda: None
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    return stub


def _task(tmp_path) -> dict:
    return {
        "run_mode": "instance",
        "challenge": {
            "id": "STOP",
            "name": "stop-state",
            "description": "",
            "difficulty": "easy",
        },
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }


def _write_task(tmp_path) -> None:
    (tmp_path / "task.json").write_text(json.dumps(_task(tmp_path)), encoding="utf-8")


def _payload(tmp_path) -> dict:
    return json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))


def test_solved_stop_keeps_turns_and_diagnostics(tmp_path, run_env, monkeypatch) -> None:
    """SolvedStop is raised from the sink; the run behind it must still be counted."""

    async def _run(**kwargs):
        sink = kwargs["event_sink"]
        sink("root", _event("tool_call_item", call_id="hit"))
        # The output names the target host, which is what the extractor needs
        # to accept a flag printed by a command rather than a leftover file.
        sink(
            "root",
            _event(
                "tool_call_output_item",
                call_id="hit",
                output=f"http://127.0.0.1:9 -> {FLAG}",
            ),
        )
        # The next event is where the sink raises: the answer is already in.
        sink("root", _event("tool_call_item", call_id="next"))

    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "solved"
    assert payload["turns"] >= 1
    assert payload["answers"] == {"flag": FLAG}
    assert payload["success"]["solved"] is True
    assert "error:" not in payload["writeup"]


@pytest.mark.parametrize(
    "reason, exc",
    [
        (
            "recovery_exhausted",
            RecoveryExhausted("agent ended 3 turns without a lifecycle tool call"),
        ),
        ("wallclock", agent_mod.WallclockExceeded("wall budget 600s spent")),
        (
            "output_budget",
            OutputBudgetExceeded("output cap", output_tokens=90000, cap=32000),
        ),
    ],
    ids=["recovery_exhausted", "wallclock", "output_budget"],
)
def test_stop_reasons_keep_turns_and_diagnostics(
    tmp_path, run_env, monkeypatch, reason, exc
) -> None:
    """The remaining stop paths report the work that actually happened."""
    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _fake_runner(exc))

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == reason
    assert payload["turns"] == CALLS
    assert payload["success"]["solved"] is False
    if reason == "output_budget":
        assert payload["output_budget"]["output_tokens"] == 90000


def test_clean_return_still_reports_turns(tmp_path, run_env, monkeypatch) -> None:
    """The shared snapshot must not change the normal, no-exception path."""
    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _fake_runner(None))

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "completed"
    assert payload["turns"] == CALLS
    assert payload["success"]["solved"] is False
    assert "turns_exhausted" not in payload
    assert "no_attempt_ran" not in payload


def test_attached_diagnostics_land_at_top_level(tmp_path, monkeypatch) -> None:
    """Evidence / parallel / llm_errors travel with the exception, not just turns."""
    exc = agent_mod.WallclockExceeded("wall budget 60s spent")
    evidence = {"flags_observed": 2, "retrieved_flags": []}
    parallel = {"children": 1, "usage": {"turns": 12}}
    llm_errors = [{"reason": "boom", "status_code": 500}]
    agent_mod._attach_stop_state(
        exc,
        12,
        {"evidence": evidence, "parallel": parallel, "llm_errors": llm_errors},
    )

    def _stopped(*args, **kwargs):  # noqa: ANN002, ANN003 - drop-in stub
        raise exc

    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    monkeypatch.setattr(agent_mod, "_run_agent", _stopped)
    _write_task(tmp_path)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "wallclock"
    assert payload["turns"] == 12
    assert payload["parallel"] == parallel
    assert payload["llm_errors"] == llm_errors
    assert "evidence:" in payload["writeup"]


def test_stop_state_round_trip_tolerates_missing_and_bad_values() -> None:
    """An exception without a snapshot, or with a junk one, must not break main."""
    exc = RecoveryExhausted("plain")
    assert agent_mod._take_stop_state(exc) == (0, {})

    agent_mod._attach_stop_state(exc, -5, {"a": 1})
    assert agent_mod._take_stop_state(exc) == (0, {"a": 1})

    exc.stop_turns = "oops"  # type: ignore[attr-defined]
    exc.stop_diag = ["not", "a", "dict"]  # type: ignore[attr-defined]
    assert agent_mod._take_stop_state(exc) == (0, {})


def test_stop_in_second_attempt_counts_both(tmp_path, run_env, monkeypatch) -> None:
    """A stop mid-attempt must count its calls on top of the earlier attempts.

    The stop types are ``BaseException``: they skip the per-attempt
    ``turns_total`` update and land in the snapshot with only the previous
    attempts counted.  With one attempt the fallback masked this; with two it
    reported attempt 1 only.
    """
    _write_task(tmp_path)
    monkeypatch.setenv("CTF_ATTEMPTS", "2")
    first_calls = 2
    second_calls = 3
    seen = {"n": 0}

    async def _run(**kwargs):
        seen["n"] += 1
        sink = kwargs["event_sink"]
        count = first_calls if seen["n"] == 1 else second_calls
        for index in range(count):
            call_id = f"attempt{seen['n']}-call-{index}"
            sink("root", _event("tool_call_item", call_id=call_id))
            sink(
                "root",
                _event("tool_call_output_item", call_id=call_id, output=f"out {index}"),
            )
        if seen["n"] == 2:
            raise RecoveryExhausted("agent ended 3 turns without a lifecycle tool call")
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert seen["n"] == 2
    assert payload["stop_reason"] == "recovery_exhausted"
    assert payload["turns"] == first_calls + second_calls


def test_silent_stop_is_marked_when_a_run_ends_without_finish(
    tmp_path, run_env, monkeypatch
) -> None:
    """纯文本收尾：正常返回、没调 finish_scan、没有答案。

    jsonl 里这种收尾和真失败同形（都有工具调用、都没有异常），只能靠一个
    显式标记把它们分开。
    """
    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _fake_runner(None))

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "completed"
    assert payload["silent_stop"] is True
    assert payload["finish_guard"] == {"refusals": 0, "allowed": 0, "gave_up": 0}


def test_silent_stop_absent_when_the_run_captured_a_flag(
    tmp_path, run_env, monkeypatch
) -> None:
    """正常解出的 run 不能被打上静默自停的标记。"""

    async def _run(**kwargs):
        sink = kwargs["event_sink"]
        sink("root", _event("tool_call_item", call_id="hit"))
        sink(
            "root",
            _event(
                "tool_call_output_item",
                call_id="hit",
                output=f"http://127.0.0.1:9 -> {FLAG}",
            ),
        )
        return types.SimpleNamespace()

    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["answers"] == {"flag": FLAG}
    assert "silent_stop" not in payload
