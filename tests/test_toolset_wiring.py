"""End-to-end wiring: ask ``install_toolset`` and look at the real registry.

The unit tests around the catalogue prove the *table* is right.  These prove the
table and the running process agree -- which is the failure that actually
happened three times (capabilities, sweep_guard, aisec): something was measured
under one configuration and shipped under another.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

pytest.importorskip("strix.agents.factory", reason="vendor tree not importable here")


# No sandbox backend is installed here on purpose: registration must work
# without one.  If it ever needs a live sandbox, that is itself the bug --
# a tool that can only be registered after the sandbox starts is a tool the
# platform's dry run would never see.

@pytest.fixture()
def registry():
    """Register for one kind and return ``(tool names, groups, prompt text)``."""

    def run(kind: str, task: dict | None = None):
        from ctf_strix import agent, prompt
        from strix.agents import factory

        # ``_EXTRA_TOOLS`` is a process-wide list; other tests register into it.
        # Measure each call from an empty registry, then put it back so this
        # test does not leak into the next one either.
        saved = list(factory._EXTRA_TOOLS)
        factory._EXTRA_TOOLS.clear()
        try:
            hint, groups = agent.install_toolset(task or {}, kind)
            after = {t.name for t in factory.registered_agent_tools()}
            prompt.activate(kind, tuple(groups), after)
            return after, groups, prompt.build({})
        finally:
            factory._EXTRA_TOOLS[:] = saved
            prompt.activate("web", ("base", "web"), None)

    return run


def test_file_challenge_registers_attachment_tools_but_no_http(registry):
    names, groups, text = registry("file")
    assert "unpack_archive" in names
    for web_tool in ("http_probe", "route_map", "method_sweep", "path_variants"):
        assert web_tool not in names, f"file challenge registered {web_tool}"
        assert f"`{web_tool}`" not in text, f"file challenge is told about {web_tool}"
    assert "web_cve_lookup" not in names
    assert "`web_cve_lookup`" not in text
    assert "`unpack_archive`" in text


def test_web_challenge_registers_http_and_not_attachment_tools(registry):
    names, groups, text = registry("web", {"challenge": {"description": "a login page"}})
    assert {"http_probe", "route_map", "method_sweep", "path_variants"} <= names
    assert "web_cve_lookup" in names
    assert "`web_cve_lookup`" in text
    # Traffic memory travels with the HTTP surface: it is the only way to read
    # back an exchange after its body scrolled out of the context.
    assert {"traffic_list", "traffic_view"} <= names
    assert "`traffic_list`" in text
    for file_tool in ("unpack_archive",):
        assert file_tool not in names
        assert f"`{file_tool}`" not in text


def test_tcp_challenge_registers_socket_tools(registry):
    names, groups, text = registry("tcp")
    assert {"tcp", "tcp_batch"} <= names
    assert "http_probe" not in names
    assert "web_cve_lookup" not in names


def test_aisec_is_not_registered_on_a_plain_web_task(registry, monkeypatch):
    monkeypatch.delenv("CTF_AISEC", raising=False)
    names, groups, text = registry("web", {"challenge": {"description": "a vault"}})
    assert "aisec" not in groups
    assert "ai_fingerprint" not in names
    assert "`ai_fingerprint`" not in text


def test_aisec_is_registered_when_the_task_says_it_is_an_agent(registry, monkeypatch):
    monkeypatch.delenv("CTF_AISEC", raising=False)
    task = {"challenge": {"description": "chat assistant", "tags": ["agentic_ai"]}}
    names, groups, text = registry("web", task)
    assert "aisec" in groups
    assert "ai_fingerprint" in names
    assert "`ai_fingerprint`" in text

def test_a_tool_that_failed_to_register_is_not_promised(monkeypatch):
    """A partial installer must not leave a promise in the prompt.

    ``groups`` is a package deal: ``install_web_capabilities`` appends ``web``
    once even if three of its four tools failed.  The prompt therefore filters
    by measured names as well, which is what this pins.
    """
    from ctf_strix import agent, prompt
    from strix.agents import factory

    saved = list(factory._EXTRA_TOOLS)
    factory._EXTRA_TOOLS.clear()
    try:
        # Pretend only one of the four web primitives made it into the registry.
        import ctf_strix.discovery as discovery
        import ctf_strix.variants as variants

        def boom(*_args, **_kwargs):
            raise RuntimeError("installer exploded")

        monkeypatch.setattr(discovery, "register", boom)
        monkeypatch.setattr(variants, "register", boom)

        _hint, groups = agent.install_toolset({}, "web")
        names = frozenset(t.name for t in factory.registered_agent_tools())
        prompt.activate("web", tuple(groups), names)
        text = prompt.build({})

        assert "`http_probe`" in text
        assert "`route_map`" not in text, "prompt promised a tool that failed to install"
        assert "`method_sweep`" not in text
        assert "`path_variants`" not in text
    finally:
        factory._EXTRA_TOOLS[:] = saved
        prompt.activate("web", ("base", "web"), None)
