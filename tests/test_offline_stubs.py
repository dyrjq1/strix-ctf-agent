"""Regression: removed network tools leave the model retrying into a wall.

CTFARENA-095 (DeepSeek) called ``web_search`` twice; because the tool had been
deleted from ``_BASE_TOOLS`` each call returned ``Tool 'web_search' not found``
and burned a full model turn.  The stubs keep the *name* but answer
deterministically without touching the network, which also matches the
competition rule ``internet_policy=deny``.

The schema is deliberately **not** inherited any more.  Inheriting it cost
4,143 characters (30% of the trimmed surface) to describe a search capability
that cannot exist here.  What must be preserved is only the name, because a
missing name is what makes the model retry.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import tool_trim  # noqa: E402
from ctf_strix.tool_trim import (  # noqa: E402
    _OFFLINE_NOTICE,
    _offline_stub,
    install_ctf_toolset,
)


def test_stub_keeps_name_but_sheds_the_inherited_schema():
    """Name is load-bearing; the upstream schema is pure cost.

    Measured: inheriting ``web_search`` / ``web_get_contents`` schemas cost
    4,143 chars of a 13,656-char surface, for a capability that is denied in
    this environment.  A stub that answers with no parameters should advertise
    no parameters.
    """
    from strix.tools.web_search.tool import web_search

    stub = _offline_stub(web_search)
    assert stub.name == "web_search"
    assert stub.params_json_schema == {"type": "object", "properties": {}}
    assert stub.params_json_schema != web_search.params_json_schema
    assert "OFFLINE" in stub.description
    assert len(stub.description) < 400


def test_stub_accepts_argumentless_calls():
    """The trimmed schema must still accept whatever the model sends.

    If the schema lies (says "no params" but the runtime rejects params), the
    model burns a turn on a validation error instead of on the challenge.
    """
    from strix.tools.web_search.tool import web_search

    stub = _offline_stub(web_search)
    for payload in ('{}', '{"query": "x"}', '{"urls": ["a", "b"]}'):
        out = asyncio.run(stub.on_invoke_tool(None, payload))
        assert _OFFLINE_NOTICE in str(out)


def test_stub_returns_offline_notice():
    from strix.tools.web_search.tool import web_search

    stub = _offline_stub(web_search)
    out = asyncio.run(stub.on_invoke_tool(None, '{"query": "ctfy flag"}'))
    assert _OFFLINE_NOTICE in str(out)
    assert "internet_policy=deny" in str(out)


def test_install_keeps_network_tools_as_stubs(monkeypatch):
    from strix.agents import factory

    monkeypatch.setattr(tool_trim, "_CTF_STUBBED_TOOLS", [], raising=False)
    install_ctf_toolset()
    names = [t.name for t in factory._BASE_TOOLS]
    assert "web_search" in names
    assert "web_get_contents" in names
    assert set(tool_trim._CTF_STUBBED_TOOLS) == {"web_search", "web_get_contents"}

    stub = next(t for t in factory._BASE_TOOLS if t.name == "web_search")
    out = asyncio.run(stub.on_invoke_tool(None, '{"query": "anything"}'))
    assert "no outbound internet" in str(out)


def test_stub_is_idempotent_across_reinstalls():
    """Re-installing must not stack the "[OFFLINE STUB]" prefix.

    Both entrypoints may call ``install_ctf_toolset`` (official container path
    and the eval harness).  Wrapping a stub again used to produce
    "[OFFLINE STUB] [OFFLINE STUB] ..." and silently grow the surface.
    """
    from strix.agents import factory

    install_ctf_toolset()
    first = next(t for t in factory._BASE_TOOLS if t.name == "web_search")
    first_len = len(first.description)
    install_ctf_toolset()
    second = next(t for t in factory._BASE_TOOLS if t.name == "web_search")
    assert second.description.count("[OFFLINE STUB]") == 1
    assert len(second.description) == first_len


def test_mcp_tools_are_dropped_by_default():
    """No MCP server exists in the image; five schemas advertised nothing.

    Measured: 3,355 chars (24.5% of the trimmed surface) and zero calls across
    7 failed trajectories.  ``drop_mcp=False`` must still be available for a
    future image that does ship servers.
    """
    from strix.agents import factory

    install_ctf_toolset()
    names = {t.name for t in factory._BASE_TOOLS}
    for name in ("list_mcps", "search_mcp_tools", "get_mcp_tool_schema",
                 "describe_mcp", "call_mcp"):
        assert name not in names


def test_todo_tools_follow_the_bookkeeping_switch():
    """Todo is the same judgment as the 17 bookkeeping tools: no score.

    It cost 4,212 chars (30.8%) and saw zero calls.  Engagement still needs it,
    because there the deliverable is a report.
    """
    from strix.agents import factory

    install_ctf_toolset(drop_bookkeeping=True)
    assert not any("todo" in t.name for t in factory._BASE_TOOLS)
