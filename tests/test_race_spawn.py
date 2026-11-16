"""``race_spawn``: one call, blank-context child, same two-child ceiling.

Vendored ``create_agent`` asks the model to view the graph and pick skills
first, and hands the child the parent's whole history — measured as the reason
the race protocol never fired (ledger §4.246).  This suite pins the replacement
tool: registered only under ``CTF_ALLOW_SUBAGENTS``, forwards ``parent_history=[]``
and ``skills=[]``, refuses nested spawns, keeps the two-child ceiling, and rolls
the counter back when the runner rejects a spawn.

All fixtures are synthetic.  No challenge ids, targets, or real answers.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import parallel  # noqa: E402


class _Spawner:
    """Stand-in for the runner-provided ``spawn_child_agent`` callable."""

    def __init__(self, fail: bool = False):
        self.calls: list[dict] = []
        self.fail = fail

    async def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("runner said no")
        return {"success": True, "agent_id": f"child{len(self.calls)}"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Start from a surface that does not already carry ``race_spawn``.

    ``register_race_tool`` short-circuits when the process-wide
    ``factory._EXTRA_TOOLS`` already holds the tool (it is not per-test state),
    so an earlier test that went through ``install_ctf_toolset`` with the switch
    on would otherwise make ``captured`` empty here.
    """
    from strix.agents import factory

    before_extra = tuple(factory._EXTRA_TOOLS)  # noqa: SLF001
    factory._EXTRA_TOOLS[:] = [  # noqa: SLF001
        t for t in before_extra if getattr(t, "name", "") != "race_spawn"
    ]
    monkeypatch.delenv("CTF_ALLOW_SUBAGENTS", raising=False)
    parallel.reset_run()
    parallel._RACE_TOOL_INSTALLED = False
    yield
    factory._EXTRA_TOOLS[:] = before_extra  # noqa: SLF001
    parallel.reset_run()
    parallel._RACE_TOOL_INSTALLED = False


def _tool(monkeypatch):
    """Register the tool and return the run-context builder it expects."""
    monkeypatch.setenv("CTF_ALLOW_SUBAGENTS", "1")
    captured: list = []
    names = parallel.register_race_tool(captured.append)
    assert names == ["race_spawn"]
    assert len(captured) == 1
    assert getattr(captured[0], "name", "") == "race_spawn"
    return captured[0]


def _spawn(_tool_unused=None, inner=None, name="direction", task="check one thing"):
    return json.loads(
        asyncio.run(parallel.spawn_direction(dict(inner or {}), name, task))
    )


def test_tool_is_absent_unless_enabled(monkeypatch) -> None:
    captured: list = []
    assert parallel.register_race_tool(captured.append) == []
    assert captured == []


def test_spawn_gets_blank_context_and_no_skills(monkeypatch) -> None:
    _tool(monkeypatch)
    spawner = _Spawner()
    inner = {"agent_id": "root", "parent_id": None, "spawn_child_agent": spawner}

    out = _spawn(inner=inner, name="auth bypass", task="try the header trick")

    assert out["success"] is True
    call = spawner.calls[0]
    # Blank context is the point: the brief is the child's whole input.
    assert call["parent_history"] == []
    assert call["skills"] == []
    assert call["task"] == "try the header trick"
    assert call["name"] == "auth bypass"
    assert parallel.stats()["spawned"] == 1


def test_second_child_allowed_third_refused(monkeypatch) -> None:
    _tool(monkeypatch)
    spawner = _Spawner()
    inner = {"agent_id": "root", "parent_id": None, "spawn_child_agent": spawner}

    assert _spawn(inner=inner)["success"] is True
    assert _spawn(inner=inner)["success"] is True
    refused = _spawn(inner=inner)

    assert refused["success"] is False
    assert refused["subagent_limit"] == parallel.MAX_SUBAGENTS
    assert len(spawner.calls) == parallel.MAX_SUBAGENTS


def test_child_cannot_spawn(monkeypatch) -> None:
    _tool(monkeypatch)
    spawner = _Spawner()
    inner = {"agent_id": "child1", "parent_id": "root", "spawn_child_agent": spawner}

    out = _spawn(inner=inner)

    assert out["success"] is False
    assert spawner.calls == []


def test_runner_failure_rolls_the_counter_back(monkeypatch) -> None:
    _tool(monkeypatch)
    failing = _Spawner(fail=True)
    ok = _Spawner()
    inner_bad = {"agent_id": "root", "parent_id": None, "spawn_child_agent": failing}
    inner_ok = {"agent_id": "root", "parent_id": None, "spawn_child_agent": ok}

    assert _spawn(inner=inner_bad)["success"] is False
    assert parallel.stats()["spawned"] == 0
    # The ceiling still allows the full budget after a failed spawn.
    assert _spawn(inner=inner_ok)["success"] is True
    assert _spawn(inner=inner_ok)["success"] is True
    assert parallel.stats()["spawned"] == 2


def test_empty_task_is_refused(monkeypatch) -> None:
    _tool(monkeypatch)
    spawner = _Spawner()
    inner = {"agent_id": "root", "parent_id": None, "spawn_child_agent": spawner}

    out = _spawn(inner=inner, task="   ")

    assert out["success"] is False
    assert spawner.calls == []


def test_missing_spawner_reports_instead_of_raising(monkeypatch) -> None:
    _tool(monkeypatch)
    out = _spawn(inner={"agent_id": "root", "parent_id": None})

    assert out["success"] is False
    assert "spawner" in out["error"]