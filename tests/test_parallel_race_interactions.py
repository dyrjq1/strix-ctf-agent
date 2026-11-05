"""Parallel racing crossed with the structured success channels.

The #3 race protocol was written against a text-only flag extractor.  #4b then
added an exec observer that validates a platform verdict and raises
``SolvedStop``, on the same ``factory._with_bounded_result`` seam.  These tests
pin the seam order and the forwarding contract:

* a child's validated ``exec_verdict`` is a race win, exactly like a retrieved
  flag;
* the root keeps its original ``SolvedStop`` exit path;
* a placeholder or unsupported flag still starts no race;
* a child win still ends the run with a ``result.json``.

All fixtures are synthetic.  No challenge ids, targets, or real answers.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import parallel  # noqa: E402
from ctf_strix.evidence import EvidenceLedger  # noqa: E402
from ctf_strix.success_stop import (  # noqa: E402
    SolvedStop,
    SuccessLedger,
    install_exec_observer,
    uninstall_exec_observer,
)

DEMO_FLAG = "FLAG{demo_value_1234}"
PLATFORM = "https://ctfy.example.test"
INSTANCE = "inst-1"
CHECK_URL = f"{PLATFORM}/api/v1/instances/{INSTANCE}/check"
POST_BODY = '{"question_id":"q1"}'
VERDICT = (
    '{"passed":true,"question_id":"q1","exit_code":0,"timed_out":false,'
    '"already_solved":false,"solve_rank":34,"challenge_fully_solved":true}'
)


class _Context:
    def __init__(self, **context):
        self.context = context


class _Coordinator:
    """Minimal stand-in for vendor's AgentCoordinator."""

    def __init__(self, parent_of=None):
        self.parent_of = dict(parent_of or {})
        self.sent = []
        self.stopped = []
        self.active = [
            {"agent_id": aid, "name": aid, "status": "running", "parent_id": parent}
            for aid, parent in self.parent_of.items()
            if parent is not None
        ]

    async def send(self, target, message, *, interrupt=True):
        self.sent.append((target, message, interrupt))
        return True

    async def request_stop(self, agent_id):
        self.stopped.append(agent_id)

    async def active_agents_except(self, agent_id):
        return [info for info in self.active if info["agent_id"] != agent_id]


@pytest.fixture(autouse=True)
def _clean_race(monkeypatch):
    monkeypatch.delenv("CTF_ALLOW_SUBAGENTS", raising=False)
    # Uninstall in reverse install order: bridge, observer, parallel.  The
    # observer's restore would otherwise discard the bridge wrapper without
    # clearing its bookkeeping.
    parallel.uninstall_exec_bridge()
    uninstall_exec_observer()
    parallel.uninstall()
    parallel.reset_run()
    yield
    parallel.uninstall_exec_bridge()
    uninstall_exec_observer()
    parallel.uninstall()
    parallel.reset_run()


@pytest.fixture
def fake_factory(monkeypatch):
    """Stand-in factory matching the real install seam."""
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


def _curl() -> str:
    body = "'" + POST_BODY + "'"
    return " ".join(("curl", "-s", "-X", "POST", "-d", body, CHECK_URL))


def _tool(FunctionTool, name: str, invoke):
    return FunctionTool(
        name=name,
        description="test seam",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


def _install_chain(fake_factory, monkeypatch, *, success, coordinator):
    """Install the guards in the shipped order: parallel, observer, bridge."""
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    factory, FunctionTool = fake_factory
    evidence = EvidenceLedger()
    parallel.configure(success=success, evidence=evidence, coordinator=coordinator)
    assert parallel.install() is True
    assert (
        install_exec_observer(
            success,
            platform_url=PLATFORM,
            instance=INSTANCE,
            question_ids=("q1",),
        )
        is True
    )
    assert parallel.install_exec_bridge() is True
    return factory, FunctionTool


def test_child_structured_check_verdict_wins_the_race(fake_factory, monkeypatch) -> None:
    """A validated /check verdict is a win even with no flag string."""
    coordinator = _Coordinator({"root": None, "child-a": "root", "child-b": "root"})
    success = SuccessLedger()
    factory, FunctionTool = _install_chain(
        fake_factory, monkeypatch, success=success, coordinator=coordinator
    )

    async def _answer(_ctx, _raw):
        return VERDICT

    mounted = factory._with_bounded_result(_tool(FunctionTool, "exec_command", _answer))
    assert getattr(mounted, "_ctf_exec_observer", False) is True
    assert getattr(mounted, "_ctf_parallel_bridge", False) is True

    child = _Context(agent_id="child-a", parent_id="root", coordinator=coordinator)

    async def run():
        out = await mounted.on_invoke_tool(child, json.dumps({"cmd": _curl()}))
        for _ in range(4):
            await asyncio.sleep(0)
        return out

    out = asyncio.run(run())

    assert success.solved is True
    assert success.source == "exec_verdict"
    assert success.detail == "passed=true"
    assert coordinator.sent[0][0] == "root"
    assert coordinator.sent[0][1]["type"] == "success"
    assert coordinator.sent[0][2] is True
    assert set(coordinator.stopped) == {"child-a", "child-b"}
    assert parallel.stats()["race_announced"] is True
    assert parallel.stats()["race_stopped"] is True
    assert parallel.stats()["exec_bridge"] is True
    # The child task must not receive a BaseException from the observer: it is
    # detached from the runner's handler, so the bridge consumes it after
    # recording the win.
    assert "race stop requested" in out


def test_root_structured_verdict_keeps_its_solved_stop(fake_factory, monkeypatch) -> None:
    """On the root the observer's exception still unwinds the run."""
    coordinator = _Coordinator({"root": None, "child-a": "root"})
    success = SuccessLedger()
    factory, FunctionTool = _install_chain(
        fake_factory, monkeypatch, success=success, coordinator=coordinator
    )

    async def _answer(_ctx, _raw):
        return VERDICT

    mounted = factory._with_bounded_result(_tool(FunctionTool, "exec_command", _answer))
    root = _Context(agent_id="root", parent_id=None, coordinator=coordinator)

    with pytest.raises(SolvedStop):
        asyncio.run(mounted.on_invoke_tool(root, json.dumps({"cmd": _curl()})))

    assert success.solved and success.source == "exec_verdict"
    assert coordinator.sent == [], "the root does not message itself"


def test_child_solved_stop_is_consumed_not_left_on_the_task(
    fake_factory, monkeypatch
) -> None:
    """A child must never surface SolvedStop as an unretrieved task exception.

    The flag path can record the solve first and a later shell call can raise
    the observer's SolvedStop.  The child task is detached from the runner's
    handler, so the bridge consumes it and wakes the root exactly once.
    """
    coordinator = _Coordinator({"root": None, "child-a": "root"})
    success = SuccessLedger()
    factory, FunctionTool = _install_chain(
        fake_factory, monkeypatch, success=success, coordinator=coordinator
    )
    success.observe_answer(DEMO_FLAG, source="flag_extract")

    async def _raises(_ctx, _raw):
        raise SolvedStop("solved via finish_guard: flag accepted")

    mounted = factory._with_bounded_result(_tool(FunctionTool, "exec_command", _raises))
    child = _Context(agent_id="child-a", parent_id="root", coordinator=coordinator)

    async def run():
        out = await mounted.on_invoke_tool(child, json.dumps({"cmd": "true"}))
        for _ in range(3):
            await asyncio.sleep(0)
        return out

    out = asyncio.run(run())
    assert "race stop requested" in out
    assert success.source == "flag_extract"
    assert coordinator.sent[0][0] == "root"


def test_bridge_does_not_swallow_an_unsolved_stop(fake_factory, monkeypatch) -> None:
    """A SolvedStop with no recorded solve is a wiring error, not a race win."""
    coordinator = _Coordinator({"root": None, "child-a": "root"})
    success = SuccessLedger()
    factory, FunctionTool = _install_chain(
        fake_factory, monkeypatch, success=success, coordinator=coordinator
    )

    async def _raises(_ctx, _raw):
        raise SolvedStop("solved via nobody")

    mounted = factory._with_bounded_result(_tool(FunctionTool, "exec_command", _raises))
    child = _Context(agent_id="child-a", parent_id="root", coordinator=coordinator)

    with pytest.raises(SolvedStop):
        asyncio.run(mounted.on_invoke_tool(child, json.dumps({"cmd": "true"})))
    assert coordinator.sent == []


@pytest.mark.parametrize("summary", ["FLAG{xxx}", DEMO_FLAG])
def test_placeholder_or_unsupported_flag_does_not_start_a_race(
    summary, monkeypatch
) -> None:
    """Text flags still need the extractor and the evidence ledger."""
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    coordinator = _Coordinator({"root": None, "child-a": "root"})
    success = SuccessLedger()
    evidence = EvidenceLedger()  # deliberately empty: nothing was read
    parallel.configure(success=success, evidence=evidence, coordinator=coordinator)

    async def inner(_ctx, _raw):
        return json.dumps({"success": True, "agent_completed": True})

    from agents.tool import FunctionTool

    tool = parallel.wrap_tool(_tool(FunctionTool, "agent_finish", inner))
    child = _Context(agent_id="child-a", parent_id="root", coordinator=coordinator)

    asyncio.run(tool.on_invoke_tool(child, json.dumps({"result_summary": summary})))
    assert success.solved is False
    assert coordinator.sent == []
    assert parallel.stats()["race_announced"] is False


def test_child_win_stop_lands_in_result_json(tmp_path, monkeypatch) -> None:
    """The race win raises the root stop and the result file records it."""
    from ctf_strix import agent as agent_mod

    task = {
        "run_mode": "instance",
        "challenge": {"id": "X", "name": "demo", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }
    (tmp_path / "task.json").write_text(json.dumps(task), encoding="utf-8")
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.setenv("CTFY_SOFT_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    for key in ("CTFY_PLATFORM_URL", "CTFY_TOKEN", "CTFY_EVAL_TARGET_INSTANCE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")

    def fake_run_agent(_task, answers, qid, **_kwargs):
        coordinator = _Coordinator({"root": None, "child": "root"})
        success = SuccessLedger()
        evidence = EvidenceLedger()
        evidence.observe_output(f"dump -> {DEMO_FLAG}")
        parallel.configure(success=success, evidence=evidence, coordinator=coordinator)

        async def race():
            parallel.note_success("child", DEMO_FLAG, root_id="root")
            for _ in range(3):
                await asyncio.sleep(0)

        asyncio.run(race())
        agent_mod._record_answer(answers, [qid], DEMO_FLAG, qid, derived=set())
        # This is what the root's sink raises on its next event.
        raise SolvedStop(f"solved via {success.source}: {success.detail}")

    monkeypatch.setattr(agent_mod, "_run_agent", fake_run_agent)
    assert agent_mod.main() == 0

    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "solved"
    assert payload["answers"] == {"flag": DEMO_FLAG}
