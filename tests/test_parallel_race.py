"""Opt-in parallel hypothesis race: switch, ceiling, guards, and stop chain.

The vendored runner already knows how to run child agents; its default prompt
told the root to delegate everything, which measured 22% coordination overhead.
This suite pins the narrow replacement: tools appear only under
``CTF_ALLOW_SUBAGENTS``, the root may spawn at most two children, children
cannot nest, a retrieved flag wakes the root and stops the siblings, and the
same mount seam covers the shell tools a child actually uses.

All fixtures below are synthetic.  No challenge ids, targets, or real answers.
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
from ctf_strix.success_stop import SuccessLedger  # noqa: E402

DEMO_FLAG = "FLAG{demo_value_1234}"


def _tool(name: str, invoke):
    from agents.tool import FunctionTool

    return FunctionTool(
        name=name,
        description="test seam",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
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
def _clean_parallel(monkeypatch):
    """Every test starts and ends with the opt-in path uninstalled."""
    monkeypatch.delenv("CTF_ALLOW_SUBAGENTS", raising=False)
    parallel.uninstall()
    parallel.reset_run()
    yield
    parallel.uninstall()
    parallel.reset_run()


@pytest.fixture
def base_tools_restored():
    """Mutating the vendor tuple is process-wide; restore it afterwards."""
    from strix.agents import factory

    from ctf_strix import tool_trim

    tool_trim.restore_base_tools()
    before = tuple(factory._BASE_TOOLS)
    yield factory
    factory._BASE_TOOLS = before  # type: ignore[attr-defined]
    tool_trim._CTF_STUBBED_TOOLS[:] = []


def test_agent_graph_tools_are_absent_by_default(
    monkeypatch, base_tools_restored
) -> None:
    from ctf_strix.tool_trim import install_ctf_toolset

    factory = base_tools_restored
    monkeypatch.delenv("CTF_ALLOW_SUBAGENTS", raising=False)
    install_ctf_toolset()

    names = {tool.name for tool in factory._BASE_TOOLS}
    for name in ("create_agent", "wait_for_agents"):
        assert name not in names, f"{name} must stay out of the default surface"


def test_agent_graph_tools_are_registered_when_enabled(
    monkeypatch, base_tools_restored
) -> None:
    from ctf_strix.tool_trim import install_ctf_toolset

    factory = base_tools_restored
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    install_ctf_toolset()

    names = {tool.name for tool in factory._BASE_TOOLS}
    for name in ("create_agent", "send_message_to_agent", "wait_for_agents"):
        assert name in names, f"{name} must be reachable when the switch is on"


def test_enabling_restores_the_graph_after_a_default_trim(
    monkeypatch, base_tools_restored
) -> None:
    """The switch must not depend on the order of install calls."""
    from ctf_strix.tool_trim import install_ctf_toolset

    factory = base_tools_restored
    monkeypatch.delenv("CTF_ALLOW_SUBAGENTS", raising=False)
    install_ctf_toolset()
    assert "create_agent" not in {tool.name for tool in factory._BASE_TOOLS}

    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    install_ctf_toolset()
    assert "create_agent" in {tool.name for tool in factory._BASE_TOOLS}


def test_keeping_the_graph_tools_also_installs_the_limit_guard(
    monkeypatch, base_tools_restored
) -> None:
    """Exposing create_agent without the 2-child ceiling is a memory risk.

    The official entrypoint installs the guard itself, but the eval harness
    only calls ``install_ctf_toolset``.  With the switch on, that call must
    also install the ceiling; the third spawn is refused without any manual
    wrapping here.
    """
    from strix.agents import factory

    from ctf_strix.tool_trim import install_ctf_toolset

    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    install_ctf_toolset()

    async def inner(_ctx, _raw):
        return json.dumps({"success": True})

    guarded = factory._with_bounded_result(_tool("create_agent", inner))
    root = _Context(agent_id="root", parent_id=None, coordinator=_Coordinator())

    async def run():
        return [
            json.loads(await guarded.on_invoke_tool(root, "{}"))
            for _ in range(parallel.MAX_SUBAGENTS + 1)
        ]

    results = asyncio.run(run())
    assert [r["success"] for r in results] == [True, True, False], results


def test_prompt_carries_the_race_protocol_only_when_enabled(monkeypatch) -> None:
    from ctf_strix import prompt

    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    enabled_text = prompt.build({})
    assert "Parallel hypothesis race" in enabled_text
    assert "list the candidate directions in `think`" in enabled_text
    assert "at most **two**" in enabled_text
    assert "platform verdict" in enabled_text

    monkeypatch.delenv("CTF_ALLOW_SUBAGENTS")
    assert "Parallel hypothesis race" not in prompt.build({})


def test_child_prompt_never_carries_the_spawn_protocol(monkeypatch) -> None:
    """Children share the renderer; only the root is allowed to spawn."""
    from ctf_strix import prompt

    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    assert "Parallel hypothesis race" in prompt.build({}, is_root=True)
    assert "Parallel hypothesis race" not in prompt.build({}, is_root=False)


def test_enabled_accepts_every_documented_spelling(monkeypatch) -> None:
    for value in ("1", "true", "TRUE", "yes", "on", " On "):
        monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", value)
        assert parallel.enabled() is True, value
    for value in ("", "0", "false", "no", "off", "2"):
        monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", value)
        assert parallel.enabled() is False, value


def test_third_create_agent_is_refused() -> None:
    calls = []

    async def inner(_ctx, _raw):
        calls.append("spawn")
        return json.dumps({"success": True, "agent_id": f"child-{len(calls)}"})

    tool = parallel.wrap_tool(_tool("create_agent", inner))
    root = _Context(agent_id="root", parent_id=None, coordinator=_Coordinator())

    async def run():
        return [
            json.loads(await tool.on_invoke_tool(root, "{}"))
            for _ in range(parallel.MAX_SUBAGENTS + 1)
        ]

    results = asyncio.run(run())
    assert [r["success"] for r in results] == [True, True, False]
    assert results[2]["subagent_limit"] == 2
    assert "at most 2" in results[2]["error"]
    assert len(calls) == parallel.MAX_SUBAGENTS, "refusal must not reach the spawner"
    assert parallel.stats()["spawned"] == 2


def test_max_subagents_is_a_hard_constant() -> None:
    """The ceiling is memory protection, not a tunable budget."""
    assert parallel.MAX_SUBAGENTS == 2


def test_child_cannot_spawn_a_grandchild() -> None:
    calls = []

    async def inner(_ctx, _raw):
        calls.append("spawn")
        return json.dumps({"success": True})

    tool = parallel.wrap_tool(_tool("create_agent", inner))
    child = _Context(agent_id="child", parent_id="root", coordinator=_Coordinator())

    out = json.loads(asyncio.run(tool.on_invoke_tool(child, "{}")))
    assert out["success"] is False
    assert "nested" in out["error"].lower()
    assert calls == []


def test_failed_spawn_does_not_consume_a_slot() -> None:
    async def inner(_ctx, _raw):
        return json.dumps({"success": False, "error": "spawner unavailable"})

    tool = parallel.wrap_tool(_tool("create_agent", inner))
    root = _Context(agent_id="root", parent_id=None, coordinator=_Coordinator())

    async def run():
        for _ in range(3):
            await tool.on_invoke_tool(root, "{}")
        return parallel.stats()

    stats = asyncio.run(run())
    assert stats["spawned"] == 0


def test_child_tool_paths_get_the_same_guards(monkeypatch) -> None:
    """A child uses the base, shell and filesystem paths; all carry the guards.

    The mount hook must be installed before the guards (that is the order in
    ``agent.py``), and the shell/filesystem hooks must read the *current*
    ``_with_bounded_result`` -- otherwise the parallel wrapper and the three
    guards miss the only paths that reach the target.
    """
    from agents.tool import FunctionTool

    from ctf_strix import enum_guard, guard_mount, journey_guard, sweep_guard

    factory = types.ModuleType("strix_fake_factory_parallel")

    async def _answer(ctx, raw):  # noqa: ANN001, ARG001
        return "ok"

    def _probe(name):
        return FunctionTool(
            name=name,
            description="probe",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=_answer,
        )

    def _with_bounded_result(tool):
        return tool

    def _configure_shell_tools(toolset, **_kwargs):
        toolset.exec_command = _probe("exec_command")

    def _configure_filesystem_tools(toolset, **_kwargs):
        toolset.read_file = _probe("read_file")

    factory._with_bounded_result = _with_bounded_result
    factory._configure_shell_tools = _configure_shell_tools
    factory._configure_filesystem_tools = _configure_filesystem_tools

    strix_pkg = types.ModuleType("strix")
    agents_pkg = types.ModuleType("strix.agents")
    agents_pkg.factory = factory
    strix_pkg.agents = agents_pkg

    monkeypatch.setitem(sys.modules, "strix", strix_pkg)
    monkeypatch.setitem(sys.modules, "strix.agents", agents_pkg)
    monkeypatch.setitem(sys.modules, "strix.agents.factory", factory)
    monkeypatch.setattr(guard_mount, "_MARK", "_ctf_mounted_parallel", raising=False)

    # Same order as the shipped entrypoint: hook first, guards after.
    guard_mount.install_mount_hook()
    enum_guard.install()
    journey_guard.install()
    sweep_guard.install()
    assert parallel.install() is True

    expected = {"_ctf_guarded", "_ctf_journey_guarded", "_ctf_sweep_guarded"}

    for hook, attr in (
        (factory._configure_shell_tools, "exec_command"),
        (factory._configure_filesystem_tools, "read_file"),
    ):
        toolset = types.SimpleNamespace()
        hook(toolset, chat_completions=False, strict_schemas=False)
        tool = getattr(toolset, attr)
        marks = {name for name in vars(tool) if name.startswith("_ctf_")}
        assert expected <= marks, f"{attr} missing guards: {marks}"

    create = _probe("create_agent")
    mounted = factory._with_bounded_result(create)
    marks = {name for name in vars(mounted) if name.startswith("_ctf_")}
    assert expected <= marks, f"base path missing guards: {marks}"
    assert getattr(mounted, "_ctf_parallel_create", False) is True

    # A child's tools are built by the same factory, so the guards must also
    # run for a child context (parent_id set).  Invoke the full chain with one.
    child_ctx = _Context(
        agent_id="child",
        parent_id="root",
        coordinator=_Coordinator({"root": None, "child": "root"}),
    )
    guarded = types.SimpleNamespace()
    factory._configure_shell_tools(guarded, chat_completions=False, strict_schemas=False)
    result = asyncio.run(guarded.exec_command.on_invoke_tool(child_ctx, "{}"))
    assert "ok" in str(result)


def test_child_success_marks_the_ledger_and_stops_siblings(monkeypatch) -> None:
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    coordinator = _Coordinator({"root": None, "child-a": "root", "child-b": "root"})
    success = SuccessLedger()
    evidence = EvidenceLedger()
    evidence.observe_output(f"retrieved {DEMO_FLAG}")
    parallel.configure(success=success, evidence=evidence, coordinator=coordinator)

    async def run():
        parallel.note_success("child-a", DEMO_FLAG, root_id="root")
        for _ in range(3):
            await asyncio.sleep(0)
        return parallel.stats()

    stats = asyncio.run(run())

    assert success.solved is True
    assert success.answer == DEMO_FLAG
    assert success.source == "flag_extract"
    assert stats["race_announced"] is True
    assert stats["race_stopped"] is True
    assert coordinator.stopped == ["child-a", "child-b"]
    assert len(coordinator.sent) == 1
    target, message, interrupt = coordinator.sent[0]
    assert target == "root"
    assert message["type"] == "success"
    assert interrupt is True
    assert DEMO_FLAG in message["content"]


def test_root_success_does_not_message_itself(monkeypatch) -> None:
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    coordinator = _Coordinator({"root": None, "child-a": "root"})
    success = SuccessLedger()

    async def run():
        parallel.configure(success=success, coordinator=coordinator)
        parallel.note_success("root", DEMO_FLAG, root_id="root")
        for _ in range(3):
            await asyncio.sleep(0)

    asyncio.run(run())
    assert coordinator.sent == [], "the root has nowhere to send a wake-up"
    assert coordinator.stopped == ["child-a"]


def test_note_success_is_idempotent(monkeypatch) -> None:
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    coordinator = _Coordinator({"root": None, "child-a": "root"})
    success = SuccessLedger()

    async def run():
        parallel.configure(success=success, coordinator=coordinator)
        parallel.note_success("child-a", DEMO_FLAG, root_id="root")
        parallel.note_success("child-a", DEMO_FLAG, root_id="root")
        for _ in range(3):
            await asyncio.sleep(0)

    asyncio.run(run())
    assert len(coordinator.sent) == 1


def test_finish_scan_with_a_proven_flag_stops_children_first() -> None:
    """The vendor refuses finish_scan while children are active; stop them."""
    coordinator = _Coordinator({"root": None, "child-a": "root", "child-b": "root"})
    evidence = EvidenceLedger()
    evidence.observe_output(f"answer: {DEMO_FLAG}")
    parallel.configure(success=SuccessLedger(), evidence=evidence, coordinator=coordinator)

    seen = []

    async def inner(_ctx, _raw):
        seen.append("finish")
        return json.dumps({"success": True, "scan_completed": True})

    tool = parallel.wrap_tool(_tool("finish_scan", inner))
    root = _Context(agent_id="root", parent_id=None, coordinator=coordinator, task="t")
    out = json.loads(
        asyncio.run(tool.on_invoke_tool(root, json.dumps({"summary": DEMO_FLAG})))
    )

    assert out["success"] is True
    assert coordinator.stopped == ["child-a", "child-b"]
    assert seen == ["finish"]


def test_finish_scan_without_a_proven_flag_leaves_children_running() -> None:
    coordinator = _Coordinator({"root": None, "child-a": "root"})
    parallel.configure(
        success=SuccessLedger(), evidence=EvidenceLedger(), coordinator=coordinator
    )

    async def inner(_ctx, _raw):
        return json.dumps({"success": False, "error": "no flag"})

    tool = parallel.wrap_tool(_tool("finish_scan", inner))
    root = _Context(agent_id="root", parent_id=None, coordinator=coordinator)
    asyncio.run(tool.on_invoke_tool(root, json.dumps({"summary": "still looking"})))
    assert coordinator.stopped == []


def test_agent_finish_flag_counts_only_when_evidence_supports_it() -> None:
    evidence = EvidenceLedger()
    success = SuccessLedger()
    parallel.configure(success=success, evidence=evidence, coordinator=_Coordinator())

    async def inner(_ctx, _raw):
        return json.dumps({"success": True, "agent_completed": True})

    tool = parallel.wrap_tool(_tool("agent_finish", inner))
    child = _Context(agent_id="child", parent_id="root", coordinator=_Coordinator())

    asyncio.run(
        tool.on_invoke_tool(child, json.dumps({"result_summary": f"I found {DEMO_FLAG}"}))
    )
    assert success.solved is False, "a child's prose is not evidence"

    evidence.observe_output(f"cat /flag -> {DEMO_FLAG}")
    asyncio.run(
        tool.on_invoke_tool(child, json.dumps({"result_summary": f"I found {DEMO_FLAG}"}))
    )
    assert success.solved is True
    assert success.answer == DEMO_FLAG


def test_root_is_resolved_from_the_graph_not_the_first_event() -> None:
    """A resumed run emits a child event before the root's; the graph wins."""
    coordinator = _Coordinator({"root": None, "child-first": "root"})
    parallel.configure(coordinator=coordinator)
    parallel.bind_root("child-first")  # what a naive first-event binding would do
    assert parallel.root_id() == "root"
    assert parallel.is_root("child-first") is False
    assert parallel.is_root("root") is True


def test_reset_run_clears_stale_bindings() -> None:
    """A second attempt must not inherit a coordinator or a solved ledger."""
    parallel.configure(
        success=SuccessLedger(),
        evidence=EvidenceLedger(),
        coordinator=_Coordinator({"root": None, "child": "root"}),
    )
    parallel.bind_root("root")
    parallel.reset_run()
    assert parallel.is_root("root") is True  # no graph: treated as root
    assert parallel.stats()["spawned"] == 0
    assert parallel.stats()["race_announced"] is False
    assert parallel.stats()["race_stopped"] is False


def test_is_root_uses_the_coordinator_graph() -> None:
    parallel.configure(coordinator=_Coordinator({"root": None, "child": "root"}))
    assert parallel.is_root("root") is True
    assert parallel.is_root("child") is False
    parallel.configure(coordinator=None)
    assert parallel.is_root("anything") is True


def test_bind_attempt_swaps_the_graph_without_resetting_the_spawn_ceiling() -> None:
    """Attempt 2 gets a fresh graph, but the run-wide two-child limit stays."""
    first = _Coordinator({"root-1": None, "child-1": "root-1"})
    second = _Coordinator({"root-2": None, "child-2": "root-2"})
    parallel.configure(coordinator=first)
    assert parallel.root_id() == "root-1"

    parallel.bind_attempt(second)
    assert parallel.root_id() == "root-2"
    assert parallel.is_root("root-2") is True
    assert parallel.is_root("root-1") is False

    calls = []

    async def inner(_ctx, _raw):
        calls.append("spawn")
        return json.dumps({"success": True})

    tool = parallel.wrap_tool(_tool("create_agent", inner))
    root = _Context(agent_id="root-2", parent_id=None, coordinator=second)

    async def run():
        return [await tool.on_invoke_tool(root, "{}") for _ in range(3)]

    asyncio.run(run())
    assert parallel.stats()["spawned"] == 2
    assert len(calls) == 2


def test_usage_summary_attributes_child_calls() -> None:
    summary = parallel.usage_summary(
        root_turns=5,
        before={"llm_calls": 10, "input_tokens": 100, "output_tokens": 50},
        after={"llm_calls": 30, "input_tokens": 700, "output_tokens": 350},
    )
    assert summary["root_turns"] == 5
    assert summary["total_llm_calls"] == 20
    assert summary["child_llm_calls"] == 15
    assert summary["turns"] == 20
    assert summary["input_tokens"] == 600
    assert summary["output_tokens"] == 300


def test_usage_summary_never_reports_fewer_turns_than_the_root() -> None:
    """A meter that missed requests must not make a parallel run look cheaper."""
    summary = parallel.usage_summary(
        root_turns=9, before={"llm_calls": 0}, after={"llm_calls": 2}
    )
    assert summary["child_llm_calls"] == 0
    assert summary["turns"] == 9


def _prepare_main(tmp_path, monkeypatch) -> None:
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


def test_child_win_ends_the_run_and_lands_in_result_json(tmp_path, monkeypatch) -> None:
    from ctf_strix import agent as agent_mod

    _prepare_main(tmp_path, monkeypatch)
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")

    def fake_run_agent(task, answers, qid, **kwargs):
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
        assert success.solved is True
        agent_mod._record_answer(answers, [qid], DEMO_FLAG, qid, derived=set())
        return 3, {
            "success": success.snapshot(),
            "parallel": {**parallel.stats(), "usage": {"turns": 3}},
        }

    monkeypatch.setattr(agent_mod, "_run_agent", fake_run_agent)
    assert agent_mod.main() == 0

    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "solved"
    assert payload["answers"] == {"flag": DEMO_FLAG}
    assert payload["parallel"]["max_subagents"] == 2
    assert payload["parallel"]["race_announced"] is True
    assert "parallel:" in payload["writeup"]


def _agent_source() -> str:
    return (ROOT / "src" / "ctf_strix" / "agent.py").read_text(encoding="utf-8")


def test_sink_only_raises_solved_stop_for_the_root() -> None:
    src = _agent_source()
    assert "success.solved and (not parallel_on or agent_id == root_agent)" in src


def test_attempt_loop_binds_a_fresh_coordinator() -> None:
    """Each attempt must hand the runner a new graph, not a closed old one."""
    src = _agent_source()
    assert "parallel.bind_attempt(attempt_coordinator)" in src
    assert "coordinator=attempt_coordinator" in src


def test_engagement_activity_is_root_only() -> None:
    """Child output arrives on the same sink; ``name``/``args`` are root-scoped."""
    src = _agent_source()
    assert "if engagement and agent_id == root_agent:" in src


def test_child_flag_is_recorded_before_the_root_is_woken() -> None:
    src = _agent_source()
    assert "flag captured by sub-agent" in src
    assert "parallel.note_success(agent_id, child_flag, root_id=root_agent)" in src
