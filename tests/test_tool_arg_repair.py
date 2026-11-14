"""形状错误的工具调用：能无损拆包就拆，拆不了要给可纠正的提示。

## 为什么

2026-11-12 批量日志：``finish_scan`` 145 次调用里 127 次失败，形状分布是
78 次 ``{"arguments": "<json 字符串>"}``、11 次把别的工具的参数塞进来
（``{"exec_command": "true"}`` / ``{"cmd": "..."}``）、3 次 ``{}``。
SDK 在 ``DONT_LOG_TOOL_DATA`` 下把 **JSON 解析失败和 pydantic 校验失败**
统一报成 ``Invalid JSON input for tool X``，模型因此以为是自己转义写错，
把同一段又包一层——CYBENCH-028 重试 82 次、1782 秒、33M token。

这些用例钉住三件事：拆包是无损的；拒绝时**内层工具不执行**且提示里带着
期望字段；合法调用一个字节都不改。
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix import tool_arg_repair  # noqa: E402

FINISH_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string", "description": "Business-level summary."},
        "methodology": {"type": "string", "description": "Frameworks and approach."},
        "technical_analysis": {"type": "string", "description": "Findings + themes."},
        "recommendations": {"type": "string", "description": "Prioritized remediation."},
    },
    "required": ["executive_summary", "methodology", "technical_analysis", "recommendations"],
    "additionalProperties": False,
}

GOOD = {
    "executive_summary": "summary",
    "methodology": "method",
    "technical_analysis": "analysis",
    "recommendations": "fix",
}


class FakeTool:
    """Only what install() touches: name, schema, on_invoke_tool."""

    def __init__(self, name: str, schema: dict, result: str = "ran") -> None:
        self.name = name
        self.params_json_schema = schema
        self.result = result
        self.seen: list[str] = []

    async def on_invoke_tool(self, ctx, raw_input: str) -> str:  # noqa: ANN001, ARG002
        self.seen.append(raw_input)
        return self.result


@pytest.fixture
def factory(monkeypatch):
    pytest.importorskip("strix.agents")
    from strix.agents import factory as strix_factory

    monkeypatch.setattr(strix_factory, "_with_bounded_result", lambda tool: tool)
    return strix_factory


def _install(factory, tool):
    guard = tool_arg_repair.install()
    wrapped = factory._with_bounded_result(tool)
    return guard, wrapped


def _run(tool, args):
    return asyncio.run(tool.on_invoke_tool(None, args))


def test_wrapped_arguments_string_is_unwrapped_and_tool_runs(factory):
    """78 次的真实形状：四个字段被裹进一个字符串，拆开后应当正常执行。"""
    tool = FakeTool("finish_scan", FINISH_SCHEMA)
    guard, wrapped = _install(factory, tool)

    out = _run(wrapped, json.dumps({"arguments": json.dumps(GOOD)}))

    assert out == "ran"
    assert len(tool.seen) == 1
    assert json.loads(tool.seen[0]) == GOOD, "inner must receive the unwrapped object"
    assert guard.repaired == 1


def test_other_tools_arguments_get_actionable_message_and_skip_inner(factory):
    """``{"exec_command": "true"}``：不接受执行，退回带期望字段的提示。"""
    tool = FakeTool("finish_scan", FINISH_SCHEMA)
    _guard, wrapped = _install(factory, tool)

    out = _run(wrapped, json.dumps({"exec_command": "true"}))

    assert tool.seen == [], "a rejected call must not run the tool"
    assert out.startswith("ARGUMENT ERROR — finish_scan did NOT run")
    assert "missing required field(s)" in out
    assert "executive_summary" in out and "recommendations" in out
    assert "exec_command" in out, "the message must echo what the model actually sent"
    assert "top-level JSON key" in out
    assert len(out) < 1200


def test_correct_call_is_passed_through_byte_for_byte(factory):
    tool = FakeTool("finish_scan", FINISH_SCHEMA)
    guard, wrapped = _install(factory, tool)

    raw = json.dumps(GOOD, ensure_ascii=False).replace(",", ", ")
    assert _run(wrapped, raw) == "ran"
    assert tool.seen == [raw]
    assert guard.repaired == 0


def test_empty_object_missing_everything_is_rejected(factory):
    tool = FakeTool("finish_scan", FINISH_SCHEMA)
    _guard, wrapped = _install(factory, tool)

    out = _run(wrapped, "{}")
    assert tool.seen == []
    assert out.startswith("ARGUMENT ERROR")


def test_non_json_input_returns_message_instead_of_raising(factory):
    tool = FakeTool("finish_scan", FINISH_SCHEMA)
    _guard, wrapped = _install(factory, tool)

    out = _run(wrapped, "{not json")
    assert tool.seen == []
    assert "not valid JSON" in out


def test_declared_arguments_property_is_left_alone(factory):
    """少数工具真的把 ``arguments`` 当参数名；那是合法调用，不许拆。"""
    schema = {
        "type": "object",
        "properties": {"arguments": {"type": "string"}},
        "required": ["arguments"],
    }
    tool = FakeTool("legacy_tool", schema)
    guard, wrapped = _install(factory, tool)

    raw = json.dumps({"arguments": json.dumps(GOOD)})
    assert _run(wrapped, raw) == "ran"
    assert tool.seen == [raw]
    assert guard.repaired == 0


def test_extra_key_is_rejected_when_schema_forbids_it(factory):
    tool = FakeTool("finish_scan", FINISH_SCHEMA)
    _guard, wrapped = _install(factory, tool)

    out = _run(wrapped, json.dumps({**GOOD, "exec_command": "id"}))
    assert tool.seen == []
    assert "unexpected field(s) exec_command" in out


def test_rejection_escalates_after_three_attempts(factory):
    """同一形状反复失败时，第三次起明确要求换做法，别原地重试。"""
    tool = FakeTool("finish_scan", FINISH_SCHEMA)
    _guard, wrapped = _install(factory, tool)
    bad = json.dumps({"cmd": "echo done"})

    first = _run(wrapped, bad)
    _run(wrapped, bad)
    third = _run(wrapped, bad)

    assert "#3" not in first
    assert "rejected call #3" in third
    assert "Stop resending it" in third


def test_tools_without_schema_are_untouched(factory):
    tool = FakeTool("think", {})
    guard, wrapped = _install(factory, tool)

    assert _run(wrapped, '{"thought": "x"}') == "ran"
    assert tool.seen == ['{"thought": "x"}']
    assert guard.repaired == 0


def test_real_sdk_tool_unwraps_before_pydantic_validation(factory):
    """真 SDK 路径：``_parse_function_tool_json_input`` 与 pydantic 校验都在内层。

    前面的用例用的是假工具，只证明"本层逻辑对"；这条把 ``agents.function_tool``
    真正建出来的 ``FunctionTool`` 接进来，证明包装后**时序**也是对的：拆包发生在
    SDK 解析/校验之前，否则模型仍然只会收到 ``Invalid JSON input``。
    """
    from types import SimpleNamespace

    from agents import function_tool

    seen: list[tuple[str, str, str, str]] = []

    @function_tool(name_override="finish_scan")
    def finish_scan(
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> str:
        """Report the result of the engagement."""
        seen.append((executive_summary, methodology, technical_analysis, recommendations))
        return "ok"

    guard = tool_arg_repair.install()
    wrapped = factory._with_bounded_result(finish_scan)
    ctx = SimpleNamespace(tool_name="finish_scan")

    out = asyncio.run(wrapped.on_invoke_tool(ctx, json.dumps({"arguments": json.dumps(GOOD)})))

    assert out == "ok"
    assert seen == [("summary", "method", "analysis", "fix")]
    assert guard.repaired == 1


def test_real_sdk_tool_rejection_does_not_run_the_function(factory):
    """真 SDK 路径的拒绝臂：函数一次都不能被调用，返回的是可纠正提示。"""
    from types import SimpleNamespace

    from agents import function_tool

    ran: list[int] = []

    @function_tool(name_override="finish_scan")
    def finish_scan(
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> str:
        """Report the result of the engagement."""
        ran.append(1)
        return "ok"

    _guard = tool_arg_repair.install()
    wrapped = factory._with_bounded_result(finish_scan)
    ctx = SimpleNamespace(tool_name="finish_scan")

    out = asyncio.run(wrapped.on_invoke_tool(ctx, json.dumps({"exec_command": "true"})))

    assert ran == []
    assert isinstance(out, str) and out.startswith("ARGUMENT ERROR — finish_scan did NOT run")


def test_both_entrypoints_install_the_repair_layer():
    """两个入口必须都装：评测入口装过、交付入口没装，等于只测了个空壳。"""
    for rel in ("src/ctf_strix/agent.py", "scripts/run_strix_ctf.py"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "tool_arg_repair import install as install_arg_repair" in text, rel
        assert "install_arg_repair()" in text, rel