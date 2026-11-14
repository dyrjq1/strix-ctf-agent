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


def test_official_entry_resolves_challenge_id_of():
    """``main()`` 里每个名字都必须能解析，尤其提交链要的 ``challenge_id_of``。

    2026-11-14 实测：``main()`` 的 autosubmit 分支用了 ``challenge_id_of(task)``
    却没有导入，两次都抛 NameError、被 except 吞成一行 "autosubmit
    unavailable"——解出 flag、写对了 result.json，但一次都没提交。
    评测链路（run_strix_ctf.py）自带那份导入，所以冒烟一路全绿；只有真跑
    官方入口才看得见。这类"用了但没导入"的疏漏，字节码层面一抓一个准：
    它必然以 LOAD_GLOBAL 出现，而正确导入后是 LOAD_FAST。
    """
    import dis
    import inspect

    from ctf_strix import agent as agent_mod

    source = inspect.getsource(agent_mod._run_agent)
    assert "challenge_id_of(task)" in source, "提交链不再取题号？同步更新本测试"

    globals_used = {
        instr.argval
        for instr in dis.get_instructions(agent_mod._run_agent)
        if instr.opname == "LOAD_GLOBAL"
    }
    assert "challenge_id_of" not in globals_used, (
        "_run_agent() 把 challenge_id_of 当全局用了——漏了函数内导入，"
        "autosubmit 会被 except 静默吞掉"
    )


def test_file_challenge_registers_attachment_tools_but_no_http(registry):
    names, groups, text = registry("file")
    assert "file_triage" in names
    assert {"decode_blob", "unpack_archive", "elfpeek"} <= names
    for web_tool in ("http_probe", "route_map", "method_sweep", "path_variants"):
        assert web_tool not in names, f"file challenge registered {web_tool}"
        assert f"`{web_tool}`" not in text, f"file challenge is told about {web_tool}"
    assert "web_cve_lookup" not in names
    assert "`web_cve_lookup`" not in text
    assert "`decode_blob`" in text


def test_web_challenge_registers_http_and_not_attachment_tools(registry):
    names, groups, text = registry("web", {"challenge": {"description": "a login page"}})
    assert {"http_probe", "route_map", "method_sweep", "path_variants"} <= names
    assert "web_cve_lookup" in names
    assert "`web_cve_lookup`" in text
    # Traffic memory travels with the HTTP surface: it is the only way to read
    # back an exchange after its body scrolled out of the context.
    assert {"traffic_list", "traffic_view"} <= names
    assert "`traffic_list`" in text
    for file_tool in ("file_triage", "decode_blob", "unpack_archive"):
        assert file_tool not in names
        assert f"`{file_tool}`" not in text


def test_web_challenge_registers_viability_probe(registry):
    """The ladder tool must be in the real web registry, not just importable.

    It is the one call that turns "this direction is dead" into an engine-side
    verdict, so a version that exists in ``viability.py`` but never registers
    is indistinguishable from a model that chose not to use it.
    """
    names, groups, text = registry("web", {"challenge": {"description": "a login page"}})
    assert "viability_probe" in names
    assert "`viability_probe`" in text


def test_viability_probe_disappears_when_ablated(registry, monkeypatch):
    """``CTF_VIABILITY=0`` must remove both the tool and its prompt line.

    The prompt reads the measured registry, so this also pins that the
    catalogue row cannot promise a tool the registry refused.
    """
    monkeypatch.setenv("CTF_VIABILITY", "0")
    names, groups, text = registry("web", {"challenge": {"description": "a login page"}})
    assert "viability_probe" not in names
    assert "`viability_probe`" not in text
    # The ablation is scoped to one capability: the rest of the surface stays.
    assert "http_probe" in names
    assert "`http_probe`" in text


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
