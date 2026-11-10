"""One probe-tool list, four consumers -- and it must stay complete.

The failure this guards against is silent.  Before the consolidation,
``enum_guard`` knew seven tool names while ``journey_guard`` and
``sweep_guard`` each carried a three-name copy.  Nothing raised: the shorter
lists simply never matched ``http_probe`` / ``route_map`` / ``method_sweep`` /
``path_variants``, so the auth-wall detector and the sweep detector were off
for every call made through a primitive.  Measured on the last batch, those
four names carried 10-13% of all probe traffic.

A replay proves it: eight ``http_probe`` calls against a 401 endpoint moved
``journey_guard.state.observe_calls`` from 0 to 8 only after the lists were
unified.

Two invariants are asserted here:

1. Every guard module references the same set (no copies to drift).
2. Every name in that set actually exists in the real tool surface.  A name
   that does not exist is not a bug that raises -- it is a guard that quietly
   never fires, which cost this project a 1170-second run on CTFARENA-012.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import enum_guard, journey_guard, probe_surface, sweep_guard  # noqa: E402


def test_all_guards_share_one_list():
    assert enum_guard._PROBE_TOOLS is probe_surface.PROBE_TOOLS
    assert journey_guard._PROBE_TOOLS is probe_surface.PROBE_TOOLS
    assert sweep_guard._PROBE_TOOLS is probe_surface.PROBE_TOOLS


def test_primitives_are_recognised():
    """The four v2 primitives were the ones silently dropped."""
    for name in ("http_probe", "route_map", "method_sweep", "path_variants"):
        assert probe_surface.is_probe_tool(name)


def test_webprim_request_tools_are_recognised():
    """authdiff / jsrecon carry a request; http_burst is a volume tool."""
    for name in ("authdiff", "jsrecon"):
        assert probe_surface.is_probe_tool(name)
    assert not probe_surface.is_probe_tool("http_burst")
    assert "http_burst" in probe_surface.NETWORK_TOOLS


def test_journey_guard_counts_primitive_calls():
    """The concrete regression: a 401 through http_probe used to be invisible.

    Replayed against the pre-fix code this yields ``observe_calls == 0`` --
    the guard was not wrong, it was never called.
    """
    guard = journey_guard.JourneyGuard()
    for _ in range(3):
        guard.observe("http_probe", "GET /login", "401 Unauthorized")
    assert guard.state.observe_calls == 3
    assert guard.state.wall_hit >= 1


def test_sweep_guard_sees_a_sweep_made_through_a_primitive():
    """Same shape for the sweep guard: 200 paths in one ``path_variants`` call."""
    import json

    payload = json.dumps({"method": "GET", "paths": [f"/p{i}" for i in range(200)]})
    guard = sweep_guard.SweepGuard()
    hint = guard.check("path_variants", payload)
    assert hint is not None
    assert "SWEEP GUARD" in hint
    assert guard.hits == 1


def test_names_are_either_registered_or_deliberately_dropped():
    """A name that is neither makes the guard inert, not broken.

    ``repeat_request`` is the interesting case: it is a real strix tool, but
    ``tool_trim`` drops the six Caido tools by default (no ``caido-cli`` in the
    image).  So "present" is not the invariant -- "present or knowingly
    dropped" is.  An invented name falls through both buckets and fails.
    """
    from strix.agents import factory

    from ctf_strix import capabilities, probe_surface, tool_trim

    upstream = tool_trim.original_tool_names() or {t.name for t in factory._BASE_TOOLS}

    tool_trim.install_ctf_toolset()
    tool_trim.install_workdir_shim()
    capabilities.install_web_capabilities()

    current = {t.name for t in factory._BASE_TOOLS}
    current |= {getattr(t, "name", "") for t in factory.registered_agent_tools()}
    # Shell capability tools are built per agent, not part of either list.
    current |= {"exec_command", "write_stdin"}

    for name in probe_surface.PROBE_TOOLS:
        if name in current:
            continue
        assert name in upstream, f"guard watches a name strix never shipped: {name}"
        assert name in probe_surface.CONDITIONAL_TOOLS, (
            f"{name} exists upstream but is not registered, and is not declared "
            f"conditional -- either register it or declare why it is dropped"
        )
        assert name in tool_trim._CAIDO_DEPENDENT, (
            f"{name} is declared conditional but no installer drops it"
        )


def test_trimming_is_reversible():
    """``_BASE_TOOLS`` is a vendor module-level tuple; trimming mutates it.

    Without a snapshot the original surface is unreachable without a process
    restart, which makes an A/B rollback a re-exec instead of a call.
    """
    from strix.agents import factory

    from ctf_strix import tool_trim

    tool_trim.install_ctf_toolset()
    trimmed = len(factory._BASE_TOOLS)
    assert trimmed < 43
    assert tool_trim.restore_base_tools()
    restored = len(factory._BASE_TOOLS)
    assert restored == 43
    assert "create_note" in {t.name for t in factory._BASE_TOOLS}
    tool_trim.install_ctf_toolset()
    assert len(factory._BASE_TOOLS) == trimmed


def test_non_probe_tools_are_excluded():
    """Counting local reads would make every guard fire on noise."""
    for name in ("read_file", "think", "load_skill", "create_todo", "web_search"):
        assert not probe_surface.is_probe_tool(name)
