"""W1 guard truncation counterexample tests.

These tests verify that the three-path output truncation (regular / Shell /
filesystem) actually clips oversized tool outputs, passes non-exceeding outputs
unchanged, and does not double-wrap already-wrapped tools.

The original guard-mount bug (silent pass-through) was caused by applying
``_with_bounded_result`` only to the regular tool list while the Shell and
filesystem capability paths configured their tools separately.  These tests
exist so that bug cannot recur.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix.guard_mount import (
    _TOOL_OUTPUT_MAX_CHARS,
    _clip_output,
    _wrap_for_truncation,
    install_mount_hook,
)
from agents.tool import FunctionTool


def test_clip_output_passes_short_text_unchanged():
    text = "a" * 100
    result = _clip_output(text)
    assert result == text
    assert "truncated" not in result


@pytest.mark.asyncio
async def test_clip_output_truncates_long_text():
    """End-to-end truncation keeps exclusive head/tail markers, drops the middle.

    Goes through ``_wrap_for_truncation`` -> ``on_invoke_tool`` (the same path
    the shell/filesystem hooks use), not ``_clip_output`` directly.
    """
    head_mark = "HEADMARK"
    mid_mark = "MIDMARK"
    tail_mark = "TAILMARK"
    long_text = head_mark + "a" * _TOOL_OUTPUT_MAX_CHARS + mid_mark + "b" * _TOOL_OUTPUT_MAX_CHARS + tail_mark

    async def on_invoke(ctx, inp):
        return long_text

    wrapped = _wrap_for_truncation(_tool(on_invoke=on_invoke))
    result = await wrapped.on_invoke_tool(None, "")
    assert len(result) <= _TOOL_OUTPUT_MAX_CHARS
    assert "truncated" in result
    assert head_mark in result, "head marker must be visible after truncation"
    assert tail_mark in result, "tail marker must be visible after truncation"
    assert mid_mark not in result, "middle marker must be clipped away"


async def _echo(ctx, raw_input: str):
    return raw_input


async def _return_long(ctx, inp):
    return "A" * 50_000


async def _return_short(ctx, inp):
    return "hello world"


async def _return_dict(ctx, inp):
    return {"key": "value"}


def _tool(name="test_tool", on_invoke=None):
    return FunctionTool(
        name=name,
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=on_invoke or _echo,
    )


@pytest.mark.asyncio
async def test_wrap_clips_oversized_output():
    tool = _tool(on_invoke=_return_long)
    wrapped = _wrap_for_truncation(tool)
    result = await wrapped.on_invoke_tool(None, "")
    assert len(result) <= _TOOL_OUTPUT_MAX_CHARS
    assert "truncated" in result


@pytest.mark.asyncio
async def test_wrap_passes_short_output_unchanged():
    tool = _tool(on_invoke=_return_short)
    wrapped = _wrap_for_truncation(tool)
    result = await wrapped.on_invoke_tool(None, "")
    assert result == "hello world"
    assert "truncated" not in result


def test_wrap_is_idempotent():
    tool = _tool(on_invoke=_return_long)
    once = _wrap_for_truncation(tool)
    twice = _wrap_for_truncation(once)
    assert once is twice
    assert getattr(twice, "_ctf_output_clipped", False)


@pytest.mark.asyncio
async def test_wrap_passes_non_string_output_unchanged():
    tool = _tool(on_invoke=_return_dict)
    wrapped = _wrap_for_truncation(tool)
    result = await wrapped.on_invoke_tool(None, "")
    assert result == {"key": "value"}


pytest.importorskip("strix.agents.factory", reason="vendor strix not importable")


def test_shell_tools_path_gets_truncation():
    from strix.agents import factory

    install_mount_hook()

    long_output = "Z" * 50_000

    async def on_invoke(ctx, inp):
        return long_output

    class Probe:
        pass

    probe = Probe()
    probe.exec_command = FunctionTool(
        name="exec_command",
        description="shell",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=on_invoke,
    )

    factory._configure_shell_tools(probe, chat_completions=False, strict_schemas=False)
    assert getattr(probe.exec_command, "_ctf_output_clipped", False), (
        "exec_command was not wrapped by shell tools hook"
    )


def test_filesystem_tools_path_gets_truncation():
    from strix.agents import factory

    install_mount_hook()

    long_output = "Y" * 50_000

    async def on_invoke(ctx, inp):
        return long_output

    class Probe:
        pass

    probe = Probe()
    probe.read = FunctionTool(
        name="read",
        description="fs",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=on_invoke,
    )

    factory._configure_filesystem_tools(probe, chat_completions=False)
    assert getattr(probe.read, "_ctf_output_clipped", False), (
        "read was not wrapped by filesystem tools hook"
    )


def test_install_mount_hook_is_idempotent():
    """Calling install_mount_hook twice must not raise; the wrapper is the same object.

    The second call must return the *same* ``_with_bounded_result`` callable
    as the first -- idempotence is a wiring property, not a marker property.
    """
    from strix.agents import factory

    install_mount_hook()
    first = factory._with_bounded_result
    install_mount_hook()
    second = factory._with_bounded_result
    assert first is second, (
        "install_mount_hook is not idempotent: _with_bounded_result changed "
        "across calls"
    )
