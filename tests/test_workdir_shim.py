"""Regression: ``exec_command(workdir=...)`` outside the workspace.

GLM-5.3-EV on CTFARENA-009 sent ``workdir=/tmp`` and ``workdir=/workspace``
and the sandbox manifest validator rejected both before the command ran —
two turns burnt for zero information.  The shim rewrites the argument into a
``cd <dir> &&`` prefix, which is what the tool would have done anyway.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.tool_trim import install_workdir_shim  # noqa: E402


class _FakeTool:
    def __init__(self) -> None:
        self.name = "exec_command"
        self.seen: list[str] = []

    async def on_invoke_tool(self, ctx, raw_input):  # noqa: ANN001, ARG002
        self.seen.append(raw_input)
        return "ok"


def test_workdir_is_rewritten_into_cd_prefix(monkeypatch):
    from strix.agents import factory

    monkeypatch.setattr(factory, "_ctf_workdir_shim", False, raising=False)
    tool = _FakeTool()
    monkeypatch.setattr(factory, "_wrap_exec_command", lambda t: t)

    install_workdir_shim()
    wrapped = factory._wrap_exec_command(tool)
    asyncio.run(wrapped.on_invoke_tool(None, json.dumps({"cmd": "ls -la", "workdir": "/tmp"})))

    sent = json.loads(tool.seen[-1])
    assert sent["cmd"] == "cd /tmp && ls -la"
    assert "workdir" not in sent


def test_no_workdir_leaves_command_alone(monkeypatch):
    from strix.agents import factory

    monkeypatch.setattr(factory, "_ctf_workdir_shim", False, raising=False)
    tool = _FakeTool()
    monkeypatch.setattr(factory, "_wrap_exec_command", lambda t: t)

    install_workdir_shim()
    wrapped = factory._wrap_exec_command(tool)
    asyncio.run(wrapped.on_invoke_tool(None, json.dumps({"cmd": "id"})))

    assert json.loads(tool.seen[-1])["cmd"] == "id"


def test_install_is_idempotent(monkeypatch):
    from strix.agents import factory

    monkeypatch.setattr(factory, "_ctf_workdir_shim", False, raising=False)
    monkeypatch.setattr(factory, "_wrap_exec_command", lambda t: t)

    install_workdir_shim()
    first = factory._wrap_exec_command
    install_workdir_shim()
    assert factory._wrap_exec_command is first