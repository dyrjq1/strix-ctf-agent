"""Idle-watchdog coverage: pure arithmetic plus the event-sink stop path.

Evidence (CTFARENA-010, 2026-11-06): 121 turns / 120 LLM requests but only 6
tool calls.  The model decided the target was dead, wrote "I'll wait for the
hard stop", and idled ~20 minutes until the 1380s wall clock expired.  These
tests pin the rule that a long stretch without a tool call ends the run with
``stop_reason="agent_idle"`` instead of burning the remaining wall clock.

No test sleeps: the unit tests pass explicit timestamps, and the integration
tests use a short ``CTF_IDLE_SECONDS`` with a fake runner that either keeps
calling tools (must finish) or emits prose only (must stop).
"""

from __future__ import annotations

import asyncio
import json
import sys
import types

import pytest

import strix.core.runner as runner_mod

from ctf_strix import agent as agent_mod

#: A flag string no other test or skill file uses.
FLAG = "FLAG{idle_watchdog_probe_9876}"


def _round_end() -> object:
    """The event the vendor emits when one model round finishes.

    ``openai-agents`` wraps every provider chunk in a ``RawResponsesStreamEvent``;
    ``ResponseCompletedEvent`` (``data.type == "response.completed"``) is the
    terminal one.  The idle check is allowed to fire only there and on tool
    events -- never on a streaming delta.
    """
    return types.SimpleNamespace(
        type="raw_response_event",
        data=types.SimpleNamespace(type="response.completed"),
    )


class _FakeClock:
    """Deterministic stand-in for the ``time`` module (no real sleeping)."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.value = start

    def time(self) -> float:
        return self.value

    def monotonic(self) -> float:
        return self.value

    def advance(self, delta: float) -> None:
        self.value += delta


def _event(kind: str, *, call_id: str = "", output: str = "") -> object:
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


@pytest.fixture()
def run_env(tmp_path, monkeypatch):
    """Point ``main`` at an isolated work dir and neutralize other watchdogs."""
    stub = types.ModuleType("ctf_strix.local_backend")
    stub.install = lambda: None
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    monkeypatch.delenv("CTF_IDLE_SECONDS", raising=False)
    return stub


def _task(tmp_path) -> dict:
    return {
        "run_mode": "instance",
        "challenge": {
            "id": "IDLE",
            "name": "idle-watchdog",
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


def test_no_activity_expires_after_limit() -> None:
    watchdog = agent_mod.IdleWatchdog(150, now=1000.0)
    assert not watchdog.expired(1149.9)
    assert watchdog.expired(1150.0)
    assert watchdog.expired(1200.0)


def test_unarmed_watchdog_never_expires_until_the_first_event() -> None:
    """A clock that has not started cannot expire (cold start is not idle)."""
    watchdog = agent_mod.IdleWatchdog(150)
    assert not watchdog.armed
    assert not watchdog.expired(10**9)
    watchdog.arm(1000.0)
    assert watchdog.armed
    assert not watchdog.expired(1149.0)
    assert watchdog.expired(1150.0)
    watchdog.reset()
    assert not watchdog.armed
    assert not watchdog.expired(10**9)


def test_arm_is_idempotent_and_does_not_refresh() -> None:
    """Arming starts the clock once; a later arm must not move it forward."""
    watchdog = agent_mod.IdleWatchdog(150)
    watchdog.arm(1000.0)
    watchdog.arm(1400.0)
    assert not watchdog.expired(1149.0)
    assert watchdog.expired(1150.0)


def test_tool_call_resets_the_deadline() -> None:
    watchdog = agent_mod.IdleWatchdog(150, now=1000.0)
    watchdog.note_activity(1100.0)
    assert not watchdog.expired(1200.0)
    assert watchdog.expired(1250.0)


@pytest.mark.parametrize("limit", [0, -1, -150.5])
def test_disabled_when_limit_is_non_positive(limit: float) -> None:
    watchdog = agent_mod.IdleWatchdog(limit, now=0.0)
    watchdog.note_activity(1.0)
    assert not watchdog.expired(10**9)


def test_env_override_and_default(monkeypatch) -> None:
    monkeypatch.delenv("CTF_IDLE_SECONDS", raising=False)
    assert agent_mod._idle_limit_seconds() == 150
    monkeypatch.setenv("CTF_IDLE_SECONDS", "7")
    assert agent_mod._idle_limit_seconds() == 7
    monkeypatch.setenv("CTF_IDLE_SECONDS", "0")
    assert agent_mod._idle_limit_seconds() == 0
    monkeypatch.setenv("CTF_IDLE_SECONDS", "not-a-number")
    assert agent_mod._idle_limit_seconds() == 150


def test_idle_timeout_is_a_registered_stop_type() -> None:
    assert agent_mod.IdleTimeout in agent_mod._STOP_TYPES
    assert not issubclass(agent_mod.IdleTimeout, Exception)


def test_run_that_stops_calling_tools_reports_agent_idle(
    tmp_path, run_env, monkeypatch
) -> None:
    """Tool calls early, then prose-only turns: stop with ``agent_idle``."""
    monkeypatch.setenv("CTF_IDLE_SECONDS", "0.15")
    _write_task(tmp_path)

    async def _run(**kwargs) -> types.SimpleNamespace:
        sink = kwargs["event_sink"]
        for index in range(2):
            call_id = f"call-{index}"
            sink("root", _event("tool_call_item", call_id=call_id))
            sink(
                "root",
                _event(
                    "tool_call_output_item",
                    call_id=call_id,
                    output=f"output {index}",
                ),
            )
        # From here on the model only writes prose.  Without the watchdog this
        # loop would run until max_turns or the wall clock.  Each turn ends
        # with a round-boundary event: the check is only allowed there.
        for _ in range(20):
            await asyncio.sleep(0.02)
            sink("root", _event("message_output_item"))
            sink("root", _round_end())
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "agent_idle"
    assert payload["turns"] >= 1
    assert payload["success"]["solved"] is False


def test_run_that_keeps_calling_tools_is_not_stopped(
    tmp_path, run_env, monkeypatch
) -> None:
    """Repeated tool activity keeps the clock fresh well past the limit.

    The old version slept ``0`` between ten calls against a 5s limit: it
    could never fail, so it pinned nothing.  Here the whole loop runs for
    longer than the limit while every gap stays below it -- an implementation
    that only arms the clock and never refreshes it fails this test.
    """
    limit = 0.15
    monkeypatch.setenv("CTF_IDLE_SECONDS", str(limit))
    _write_task(tmp_path)
    calls = 10
    gap = limit / 3

    async def _run(**kwargs) -> types.SimpleNamespace:
        sink = kwargs["event_sink"]
        for index in range(calls):
            call_id = f"call-{index}"
            sink("root", _event("tool_call_item", call_id=call_id))
            await asyncio.sleep(gap)
            sink(
                "root",
                _event(
                    "tool_call_output_item",
                    call_id=call_id,
                    output=f"output {index}",
                ),
            )
            await asyncio.sleep(gap)
            sink("root", _round_end())
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "completed"
    assert payload["turns"] == calls


def test_solved_stop_wins_over_idle(tmp_path, run_env, monkeypatch) -> None:
    """A confirmed success recorded before the idle limit stays solved.

    The clock is driven explicitly instead of sleeping 0.2s: a real sleep made
    this test flaky on loaded CI boxes, where the gap could land under the
    limit.
    """
    monkeypatch.setenv("CTF_IDLE_SECONDS", "0.15")
    _write_task(tmp_path)
    clock = _FakeClock()
    monkeypatch.setattr(agent_mod, "time", clock)

    async def _run(**kwargs) -> types.SimpleNamespace:
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
        # Far past the idle limit at the next round boundary, but success is
        # already recorded.
        clock.advance(10.0)
        sink("root", _round_end())
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "solved"
    assert payload["answers"] == {"flag": FLAG}
    assert payload["success"]["solved"] is True


# ---------------------------------------------------------------------------
# BLOCKER regressions: a slow tool keeps its output; a cold start is not idle
# ---------------------------------------------------------------------------


def test_slow_tool_output_after_limit_is_still_captured(
    tmp_path, run_env, monkeypatch
) -> None:
    """B1: a tool that runs past the limit must not lose its output.

    The old sink checked expiry before it captured the output, so any tool
    slower than 150s (nmap, sqlmap, a large download) had its result -- and any
    flag in it -- thrown away with an ``IdleTimeout``.
    """
    monkeypatch.setenv("CTF_IDLE_SECONDS", "0.15")
    _write_task(tmp_path)

    async def _run(**kwargs) -> types.SimpleNamespace:
        sink = kwargs["event_sink"]
        sink("root", _event("tool_call_item", call_id="slow"))
        await asyncio.sleep(0.4)  # well past the 0.15s limit
        sink(
            "root",
            _event(
                "tool_call_output_item",
                call_id="slow",
                output=f"http://127.0.0.1:9 -> {FLAG}",
            ),
        )
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "solved"
    assert payload["answers"] == {"flag": FLAG}


def test_silence_before_the_first_event_is_not_idle(
    tmp_path, run_env, monkeypatch
) -> None:
    """B2: sandbox boot + first LLM response must not count as idling.

    The watchdog used to be seeded with ``now`` before ``run_strix_scan``, so a
    cold start longer than the limit reported ``agent_idle`` at ``turns=0``.
    """
    monkeypatch.setenv("CTF_IDLE_SECONDS", "0.15")
    _write_task(tmp_path)

    async def _run(**kwargs) -> types.SimpleNamespace:
        # Setup silence: longer than the limit, and no event at all.
        await asyncio.sleep(0.4)
        sink = kwargs["event_sink"]
        sink("root", _event("tool_call_item", call_id="first"))
        sink(
            "root",
            _event("tool_call_output_item", call_id="first", output="ok"),
        )
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "completed"
    assert payload["turns"] == 1


def test_long_single_turn_with_streamed_message_is_not_killed(
    tmp_path, run_env, monkeypatch
) -> None:
    """B2: a >limit generation is checked only after it ends.

    During one LLM round the sink sees nothing but streaming message items.
    Expiring on those killed the model mid-generation; the round that ends in
    a tool call must survive.
    """
    monkeypatch.setenv("CTF_IDLE_SECONDS", "0.15")
    _write_task(tmp_path)

    async def _run(**kwargs) -> types.SimpleNamespace:
        sink = kwargs["event_sink"]
        for _ in range(10):
            await asyncio.sleep(0.03)  # 0.3s of streaming, past the limit
            sink("root", _event("message_output_item"))
        sink("root", _event("tool_call_item", call_id="late"))
        sink("root", _round_end())
        sink("root", _event("tool_call_output_item", call_id="late", output="ok"))
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "completed"
    assert payload["turns"] == 1
