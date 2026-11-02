"""2026-11-02 external review: measurement-integrity + wiring fixes.

Every test here pins a place where the *reported* result disagreed with what
actually happened, or where a guard was present in the eval harness but
absent from the shipped entrypoint.  Those outrank capability work: they
corrupt every experiment that reads the number afterwards.
"""

from __future__ import annotations

import ast
import asyncio
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "src" / "ctf_strix" / "agent.py"


def _agent_tree() -> ast.Module:
    return ast.parse(AGENT.read_text(encoding="utf-8"))


def _func(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _called_names(node: ast.AST) -> set[str]:
    """Names of every function called inside ``node``."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            if isinstance(fn, ast.Name):
                out.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                out.add(fn.attr)
    return out


# --------------------------------------------------------------------------
# flag extraction fallback
# --------------------------------------------------------------------------


def test_degraded_flag_extraction_takes_the_first_candidate(monkeypatch) -> None:
    """The docstring forbids "take the last one" -- the fallback did exactly that.

    Stale recon notes from another challenge and in-band decoys both put a
    wrong flag *later* in the blob, so ``[-1]`` is the worst possible choice.
    """
    import ctf_strix.flag_extract as fx
    from ctf_strix import agent as agent_mod

    def boom(*_args, **_kwargs):
        raise RuntimeError("extractor unavailable")

    monkeypatch.setattr(fx, "best_flag", boom)

    blob = "noise FLAG{first_is_right} more text FLAG{stale_from_other_box}"
    assert agent_mod._extract_flag(blob, "box.example") == "FLAG{first_is_right}"


def test_degraded_flag_extraction_still_rejects_placeholders(monkeypatch) -> None:
    """The fallback must not turn ``FLAG{...}`` into an answer."""
    import ctf_strix.flag_extract as fx
    from ctf_strix import agent as agent_mod

    def boom(*_args, **_kwargs):
        raise RuntimeError("extractor unavailable")

    monkeypatch.setattr(fx, "best_flag", boom)

    assert agent_mod._extract_flag("the answer is FLAG{...}", "box.example") is None


# --------------------------------------------------------------------------
# "never started" must not be reported as "completed"
# --------------------------------------------------------------------------


def test_run_agent_counts_attempts_that_actually_started() -> None:
    """``runs_ok`` is what distinguishes "ran and failed" from "never ran"."""
    func = _func(_agent_tree(), "_run_agent")
    assigned = {
        t.id
        for node in ast.walk(func)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        for t in [node]
    }
    assert "runs_ok" in assigned, (
        "_run_agent must count attempts that returned, so an all-attempts-failed "
        "run can be told apart from a real failed solve"
    )
    assert "no_attempt_ran" in AGENT.read_text(encoding="utf-8")


def test_main_turns_all_failed_attempts_into_stop_reason_error() -> None:
    """The flag has to be acted on, not merely recorded."""
    main = _func(_agent_tree(), "main")
    src = ast.get_source_segment(AGENT.read_text(encoding="utf-8"), main) or ""
    assert "no_attempt_ran" in src, "main must consume the flag"
    assert 'stop_reason = "error"' in src, "main must not report completed"


# --------------------------------------------------------------------------
# guards must be wired into the shipped entrypoint
# --------------------------------------------------------------------------


def test_official_entrypoint_installs_the_sweep_guard() -> None:
    """The sweep guard was wired only into the eval harness.

    ``scripts/run_strix_ctf.py`` installed it; ``agent.py`` -- the actual CTFY
    entrypoint -- never did, so every measured sweep result came from a build
    that had the guard and every submitted build did not.
    """
    called = _called_names(_func(_agent_tree(), "_run_agent"))
    assert "install_sweep_guard" in called, (
        "agent.py must install sweep_guard; it was previously imported only by "
        "the eval harness, so the shipped image ran without that layer"
    )


def test_install_order_is_mount_hook_then_all_three_guards() -> None:
    """Order matters: the mount hook must wrap ``_with_bounded_result`` first."""
    func = _func(_agent_tree(), "_run_agent")
    order: list[str] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
        if name in {
            "install_mount_hook",
            "install_enum_guard",
            "install_journey_guard",
            "install_sweep_guard",
            "install_finish_guard",
            "verify_mount",
        }:
            order.append((node.lineno, name))

    order.sort()
    sequence = [name for _line, name in order]
    assert sequence[:5] == [
        "install_mount_hook",
        "install_enum_guard",
        "install_journey_guard",
        "install_sweep_guard",
        "install_finish_guard",
    ], f"unexpected guard install order: {sequence}"
    assert "verify_mount" in sequence, "wiring must be verified right after install"


def test_verify_mount_is_asked_for_all_three_marks() -> None:
    """A verifier that omits a mark cannot notice that guard missing."""
    func = _func(_agent_tree(), "_run_agent")
    call = next(
        n
        for n in ast.walk(func)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "verify_mount"
    )
    literal = ast.literal_eval(call.args[0])
    assert set(literal) == {
        "_ctf_guarded",
        "_ctf_journey_guarded",
        "_ctf_sweep_guarded",
    }, f"verify_mount must require every guard mark, got {literal}"


def test_guard_verification_failure_is_visible_in_diagnostics() -> None:
    """A silent False is the exact failure mode these guards exist to prevent."""
    func = _func(_agent_tree(), "_run_agent")
    src = ast.get_source_segment(AGENT.read_text(encoding="utf-8"), func) or ""
    assert 'diag["guard_mount"]' in src, (
        "a failed guard verification must land in result.json diagnostics; the "
        "platform does not read stdout, and 'guards inert' must not look like "
        "'guards did not fire today'"
    )


# --------------------------------------------------------------------------
# behavioural: the three guards really do all land on exec_command
# --------------------------------------------------------------------------


def test_all_three_guards_reach_exec_command(monkeypatch) -> None:
    """End-to-end wiring check against a stand-in for strix's factory.

    Uses a stub ``strix.agents.factory`` so the test exercises the real
    ``install_mount_hook`` / ``install()`` / ``verify_mount`` code paths without
    needing the full runtime (which is absent on this machine).
    """
    from agents.tool import FunctionTool

    guard_mount = pytest.importorskip("ctf_strix.guard_mount")
    enum_guard = pytest.importorskip("ctf_strix.enum_guard")
    journey_guard = pytest.importorskip("ctf_strix.journey_guard")
    sweep_guard = pytest.importorskip("ctf_strix.sweep_guard")

    factory = types.ModuleType("strix_fake_factory")

    def _with_bounded_result(tool):  # noqa: ANN001
        return tool

    def _configure_shell_tools(toolset, **_kwargs):  # noqa: ANN001
        return None

    def _configure_filesystem_tools(toolset, **_kwargs):  # noqa: ANN001
        return None

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
    monkeypatch.setattr(guard_mount, "_MARK", "_ctf_mounted", raising=False)

    guard_mount.install_mount_hook()
    enum_guard.install()
    journey_guard.install()
    sweep_guard.install()

    assert guard_mount.verify_mount(
        ("_ctf_guarded", "_ctf_journey_guarded", "_ctf_sweep_guarded")
    ) is True

    # And the marks really are on a tool that comes out of the shell path,
    # which is the path that carries every request to the target.
    probe = types.SimpleNamespace(
        exec_command=FunctionTool(
            name="exec_command",
            description="probe",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=lambda ctx, raw: "ok",
        )
    )
    factory._configure_shell_tools(probe, chat_completions=False, strict_schemas=False)
    marks = {a for a in vars(probe.exec_command) if a.startswith("_ctf_")}
    assert {
        "_ctf_guarded",
        "_ctf_journey_guarded",
        "_ctf_sweep_guarded",
    } <= marks, f"missing marks on exec_command: {marks}"

def test_guard_mount_failure_shows_up_in_the_writeup() -> None:
    """`result.json` carries the writeup; stdout is not read by the platform.

    A failed mount has to be readable after the run, otherwise "guards inert"
    is indistinguishable from "guards found nothing to say".
    """
    import ctf_strix.agent as agent_mod

    text = agent_mod._writeup(
        {"challenge": {"name": "x"}, "run_mode": "instance"},
        {},
        None,
        1.0,
        {"guard_mount": "failed"},
    )
    assert "guard_mount: FAILED" in text


def test_guards_stay_opt_in_for_smoke_level_task_parsing() -> None:
    """Nothing in this fix may change task parsing or budgets."""
    import ctf_strix.agent as agent_mod

    task = {"run_mode": "instance", "scope": ["https://box.example:443"]}
    assert agent_mod._targets_from(task) == ["https://box.example:443"]
