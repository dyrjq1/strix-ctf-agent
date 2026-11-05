# -*- coding: utf-8 -*-
"""Single-call output stop-loss (review Q7 / runaway 151k-token run).

The guard is deliberately scoped to **one LLM call**, not the run total:
successful challenges legitimately spend 281k-1.25M input+output tokens, so a
cumulative ceiling would kill hard-but-healthy runs.  A single call producing
tens of thousands of output tokens is the runaway shape.

Scenarios a-g mirror the task acceptance list.  All fixtures are synthetic:
no challenge ids, target addresses, or real answers.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import agent  # noqa: E402
from ctf_strix import usage_meter  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_meter(monkeypatch):
    """Each test starts and ends with no installed hook and no trip state."""
    monkeypatch.delenv(usage_meter._CAP_ENV, raising=False)
    monkeypatch.delenv("CTF_USAGE_PATH", raising=False)
    usage_meter.reset_for_tests()
    try:
        yield
    finally:
        usage_meter.reset_for_tests()
        os.environ.pop("CTFY_SOFT_DEADLINE", None)


def _response(output_tokens: int, *, input_tokens: int = 11):
    usage = types.SimpleNamespace(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )
    return types.SimpleNamespace(usage=usage)


def _context(agent_id: str = "root", coordinator=None):
    ctx = {"agent_id": agent_id}
    if coordinator is not None:
        ctx["coordinator"] = coordinator
    return types.SimpleNamespace(context=ctx)


def _hooks():
    from strix.core import hooks as strix_hooks

    return strix_hooks


def _call_end(output_tokens: int, *, context=None) -> None:
    strix_hooks = _hooks()
    hook_obj = strix_hooks.ReportUsageHooks(model="test")
    asyncio.run(
        strix_hooks.ReportUsageHooks.on_llm_end(
            hook_obj, context or _context(), None, _response(output_tokens)
        )
    )


def _call_start(context=None) -> None:
    strix_hooks = _hooks()
    hook_obj = strix_hooks.ReportUsageHooks(model="test")
    asyncio.run(
        strix_hooks.ReportUsageHooks.on_llm_start(
            hook_obj, context or _context(), None, "system", []
        )
    )


def _prepare_main(tmp_path: Path, monkeypatch) -> Path:
    task = {
        "run_mode": "instance",
        "challenge": {"id": "X", "name": "x", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }
    (tmp_path / "task.json").write_text(json.dumps(task), encoding="utf-8")
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    return tmp_path / "result.json"


def _drive_real_sdk(output_tokens: int):
    """Run the real SDK turn once with a fake model.

    ``Runner.run`` invokes ``hooks.on_llm_end`` through ``gather_with_cancel``,
    the same seam strix uses.  This proves the stop exception is not swallowed.
    """
    from agents import Agent, RunConfig, Runner
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage

    class FakeModel(Model):
        async def get_response(self, *args, **kwargs):
            return ModelResponse(
                output=[],
                usage=Usage(
                    requests=1,
                    input_tokens=10,
                    output_tokens=output_tokens,
                    total_tokens=output_tokens + 10,
                ),
                response_id="resp-test",
            )

        def stream_response(self, *args, **kwargs):
            raise NotImplementedError("Runner.run uses get_response")

    strix_hooks = _hooks()
    agent_obj = Agent(name="test", instructions="noop", model="test-model")
    run_config = RunConfig(model=FakeModel(), tracing_disabled=True)
    return asyncio.run(
        Runner.run(
            agent_obj,
            input="hi",
            run_config=run_config,
            hooks=strix_hooks.ReportUsageHooks(model="test-model"),
            context={"agent_id": "root"},
        )
    )


# a. A normal call stays well below the cap and the run completes.
def test_a_normal_call_does_not_trip(tmp_path, monkeypatch):
    usage_meter.install()
    _call_end(4_000)
    assert usage_meter.trip_info() is None
    assert usage_meter.snapshot()["output_tokens"] == 4_000

    result = _prepare_main(tmp_path, monkeypatch)

    def fake_run(_task, answers, *_args, **_kwargs):
        _call_end(4_000)
        return 1, {}

    monkeypatch.setattr(agent, "_run_agent", fake_run)
    assert agent.main() == 0
    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "completed"
    assert "output_budget" not in payload


# b. A single over-cap call raises, main writes output_budget, error names both numbers.
def test_b_over_cap_stops_with_output_budget(tmp_path, monkeypatch):
    usage_meter.install()
    result = _prepare_main(tmp_path, monkeypatch)
    cap = usage_meter.DEFAULT_MAX_OUTPUT_PER_CALL
    over = cap + 1

    def fake_run(_task, _answers, *_args, **_kwargs):
        _call_end(over)
        return 1, {}

    monkeypatch.setattr(agent, "_run_agent", fake_run)
    assert agent.main() == 0
    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "output_budget"
    assert f"single-call output {over} > cap {cap}" in payload["writeup"]
    assert payload["output_budget"]["output_tokens"] == over
    assert payload["output_budget"]["cap"] == cap
    assert payload["output_budget"]["call"] == 1


# c. Answers recorded before the trip still land in result.json.
def test_c_answers_survive_the_output_budget_stop(tmp_path, monkeypatch):
    usage_meter.install()
    result = _prepare_main(tmp_path, monkeypatch)
    cap = usage_meter.DEFAULT_MAX_OUTPUT_PER_CALL

    def fake_run(_task, answers, *_args, **_kwargs):
        answers["flag"] = "REAL_BEFORE_TRIP"
        _call_end(cap + 1)
        return 1, {}

    monkeypatch.setattr(agent, "_run_agent", fake_run)
    assert agent.main() == 0
    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "output_budget"
    assert payload["answers"] == {"flag": "REAL_BEFORE_TRIP"}


# d. Env override is effective; the default does not kill a 4k call.
def test_d_env_override_and_default_are_both_proven(monkeypatch):
    monkeypatch.setenv(usage_meter._CAP_ENV, "2048")
    assert usage_meter.max_output_per_call() == 2048
    usage_meter.install()
    with pytest.raises(usage_meter.OutputBudgetExceeded) as caught:
        _call_end(4_000)
    assert caught.value.cap == 2048
    assert caught.value.output_tokens == 4_000

    usage_meter.reset_for_tests()
    monkeypatch.delenv(usage_meter._CAP_ENV, raising=False)
    assert usage_meter.max_output_per_call() == usage_meter.DEFAULT_MAX_OUTPUT_PER_CALL
    usage_meter.install()
    _call_end(4_000)
    assert usage_meter.trip_info() is None


# e. The real SDK hook chain propagates the exception to main; result.json lands.
def test_e_sdk_hook_exception_reaches_main(tmp_path, monkeypatch):
    usage_meter.install()
    result = _prepare_main(tmp_path, monkeypatch)
    over = usage_meter.DEFAULT_MAX_OUTPUT_PER_CALL + 1

    def fake_run(_task, answers, *_args, **_kwargs):
        answers["flag"] = "REAL_FROM_SDK_PATH"
        _drive_real_sdk(over)
        return 1, {}

    monkeypatch.setattr(agent, "_run_agent", fake_run)
    assert agent.main() == 0
    payload = json.loads(result.read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "output_budget"
    assert payload["answers"] == {"flag": "REAL_FROM_SDK_PATH"}
    assert payload["output_budget"]["output_tokens"] == over
    assert usage_meter.trip_info()["call"] == 1


# f. A child agent's trip stops the whole scan (root + siblings), and a later
#    on_llm_start on any agent is refused.
def test_f_child_trip_stops_the_whole_run():
    class FakeCoordinator:
        def __init__(self):
            self.stopped: list[str] = []

        async def active_agents_except(self, agent_id):
            return [
                {"agent_id": aid}
                for aid in ("root", "child", "sibling")
                if aid != agent_id
            ]

        async def request_stop(self, agent_id):
            self.stopped.append(agent_id)

    coordinator = FakeCoordinator()
    usage_meter.install()
    with pytest.raises(usage_meter.OutputBudgetExceeded):
        _call_end(
            usage_meter.DEFAULT_MAX_OUTPUT_PER_CALL + 1,
            context=_context("child", coordinator),
        )
    assert coordinator.stopped == ["root", "sibling"]
    assert usage_meter.trip_info()["agent_id"] == "child"

    # The root's next LLM call is refused before it can spend anything.
    with pytest.raises(usage_meter.OutputBudgetExceeded):
        _call_start(_context("root", coordinator))

    # Exactly what _run_agent does after a child-only trip: the root may have
    # returned normally, but the run must still be re-raised as output_budget.
    with pytest.raises(usage_meter.OutputBudgetExceeded):
        agent.raise_if_tripped()


# g. install() is idempotent: one wrapper, one raise, one trip record.
def test_g_install_is_idempotent():
    strix_hooks = _hooks()
    usage_meter.install()
    first_end = strix_hooks.ReportUsageHooks.on_llm_end
    first_start = strix_hooks.ReportUsageHooks.on_llm_start

    usage_meter.install()
    assert strix_hooks.ReportUsageHooks.on_llm_end is first_end
    assert strix_hooks.ReportUsageHooks.on_llm_start is first_start

    cap = usage_meter.DEFAULT_MAX_OUTPUT_PER_CALL
    with pytest.raises(usage_meter.OutputBudgetExceeded):
        _call_end(cap + 1)
    assert usage_meter.snapshot()["llm_calls"] == 1
    assert usage_meter.trip_info()["call"] == 1

    # A second call is a new call, not a duplicate raise for the first one.
    with pytest.raises(usage_meter.OutputBudgetExceeded):
        _call_end(cap + 2)
    assert usage_meter.snapshot()["llm_calls"] == 2
    assert usage_meter.trip_info()["call"] == 1
    assert usage_meter.trip_info()["output_tokens"] == cap + 1


def test_exception_is_not_an_exception_subclass():
    """Same contract as WallclockExceeded: strix's ``except Exception`` must miss it."""
    assert not issubclass(usage_meter.OutputBudgetExceeded, Exception)
    with pytest.raises(usage_meter.OutputBudgetExceeded):
        try:
            raise usage_meter.OutputBudgetExceeded("boom", output_tokens=1, cap=0)
        except Exception:  # pragma: no cover - this is the failure we guard against
            pytest.fail("OutputBudgetExceeded must not be an Exception subclass")


# Embedded callers can run main() more than once per process.  A previous
# run's trip must not refuse the next run's first paid call.
def test_begin_run_clears_a_previous_trip():
    usage_meter.install()
    with pytest.raises(usage_meter.OutputBudgetExceeded):
        _call_end(usage_meter.DEFAULT_MAX_OUTPUT_PER_CALL + 1)
    assert usage_meter.trip_info() is not None

    usage_meter.begin_run()
    assert usage_meter.trip_info() is None
    _call_end(4_000)
    assert usage_meter.trip_info() is None
