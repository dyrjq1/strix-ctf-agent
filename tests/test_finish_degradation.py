"""finish_scan degradation path tests.

finish_scan is strix's own local tool (``@function_tool(timeout=60)``), not a
platform MCP tool, so the agent side can bound each invocation and count
consecutive timeouts.  After two, the known answers are persisted and a later
finish call exits through ``SolvedStop`` instead of letting the platform
restart the run.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from ctf_strix import agent
from ctf_strix.success_stop import SolvedStop
from strix.agents import factory


class _FakeTool:
    def __init__(self, invoke):
        self.name = "finish_scan"
        self.on_invoke_tool = invoke
        self._ctf_finish_degraded = False


def _install(monkeypatch, tmp_path, answers, invoke, **kwargs):
    monkeypatch.setattr(factory, "_with_bounded_result", lambda tool: tool)
    monkeypatch.setattr(agent, "_FINISH_DEGRADE_TIMEOUT_SECONDS", 0.01)
    result = tmp_path / "result.json"
    state = agent.install_finish_degradation(
        answers,
        result,
        diag=kwargs.get("diag"),
    )
    wrapped = factory._with_bounded_result(_FakeTool(invoke))
    return state, wrapped, result


async def _hung(ctx, raw):
    await asyncio.sleep(5)
    return "should not be reached"


def test_two_consecutive_timeouts_persist_then_third_call_exits(monkeypatch, tmp_path):
    answers = {"foothold": "FLAG{a}", "deploy": "FLAG{b}"}
    state, wrapped, result = _install(monkeypatch, tmp_path, answers, _hung)

    first = asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    assert "attempt 1 of 2" in first
    assert not result.exists()
    assert state.consecutive_timeouts == 1

    second = asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    assert "FINISH_SCAN IS UNAVAILABLE" in second
    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["answers"] == answers
    assert payload["stop_reason"] == "solved"
    assert state.degraded is True

    with pytest.raises(SolvedStop):
        asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    assert json.loads(result.read_text(encoding="utf-8"))["answers"] == answers


def test_degraded_write_merges_with_previous_run(monkeypatch, tmp_path):
    result = tmp_path / "result.json"
    result.write_text(
        json.dumps({"answers": {"foothold": "FLAG{old}"}, "stop_reason": "solved"}),
        encoding="utf-8",
    )
    state, wrapped, result = _install(monkeypatch, tmp_path, {"deploy": "FLAG{new}"}, _hung)
    assert result.exists()

    asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    asyncio.run(wrapped.on_invoke_tool(None, "{}"))

    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["answers"] == {"foothold": "FLAG{old}", "deploy": "FLAG{new}"}


def test_empty_answers_never_fake_a_solved_exit(monkeypatch, tmp_path):
    state, wrapped, result = _install(monkeypatch, tmp_path, {}, _hung)

    asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    message = asyncio.run(wrapped.on_invoke_tool(None, "{}"))

    assert "FINISH_SCAN IS UNAVAILABLE" in message
    assert json.loads(result.read_text(encoding="utf-8"))["stop_reason"] == "completed"
    again = asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    assert "Keep working" in again


def test_success_resets_the_consecutive_counter(monkeypatch, tmp_path):
    calls = {"n": 0}

    async def flaky(ctx, raw):
        calls["n"] += 1
        if calls["n"] == 1:
            await asyncio.sleep(5)
        return "ok"

    state, wrapped, _ = _install(monkeypatch, tmp_path, {"flag": "FLAG{x}"}, flaky)

    asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    assert state.consecutive_timeouts == 1
    assert asyncio.run(wrapped.on_invoke_tool(None, "{}")) == "ok"
    assert state.consecutive_timeouts == 0


def test_sdk_cancellation_also_counts(monkeypatch, tmp_path):
    async def cancelled(ctx, raw):
        raise asyncio.CancelledError()

    state, wrapped, _ = _install(monkeypatch, tmp_path, {"flag": "FLAG{x}"}, cancelled)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    assert state.consecutive_timeouts == 1
