"""工具参数修复层：把「形状错误」变成一次可纠正的提示，而不是让整轮跑死。

## 为什么需要它（实测证据）

2026-11-12 的批量日志里，``finish_scan`` 145 次调用中 127 次失败，18 个 run 受影响。
把 ``run.log`` 里模型发出的**原始参数串**逐条解析后，形状是：

- 78 次：``{"arguments": "<一整段 JSON 字符串>"}`` —— 四个叙事字段被裹进一个字符串；
- 11 次：``{"exec_command": "true"}`` / ``{"cmd": "echo done"}`` —— 把**别的工具**的参数塞进来；
- 3 次：``{}``。

SDK 只有在 ``DONT_LOG_TOOL_DATA`` 打开时才统一抛
``Invalid JSON input for tool finish_scan``——**JSON 解析失败和 pydantic 校验失败
共用同一句话**（``agents/tool.py:_parse_function_tool_json_input``）。模型看到的是
"JSON 不合法"，于是以为转义写错了，把同一段又包一层。CYBENCH-028 这一个 run
就这样重试了 82 次、烧掉 1782 秒和 3300 万 token，最后撞 MaxTurns；CTFARENA-043
重试 22 次。

这不是模型"不会写 JSON"，它写的是合法 JSON，只是**形状**不对；而错误文案没告诉它
形状是什么。修法不需要改 prompt、也不依赖任何题面：在这层把
（a）可无损拆包的形状直接拆开，（b）拆不了的把**期望字段**和**它实际发来的键**
原样告诉模型，让它下一轮就能改对。

## 挂在哪

和其它守卫一样替换 ``factory._with_bounded_result``；必须在
``guard_mount.install_mount_hook()`` 之后、且**最后安装**——后装的是最外层，
这样下游守卫（finish/autosubmit/各种计数器）看到的已经是修好的参数串。

## 边界

- 只做"形状"判断，不猜内容：不替模型编造字段值，不改变合法调用。
- ``arguments`` 若本身就是该工具的声明字段（少数工具如此），一律放行。
- 拒绝时**不执行**内层工具，返回值就是给模型的提示；计数按工具名累计，
  第三次起换更硬的措辞，避免在同一形状上无限重试。
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: 施加过本层的工具会带上这个标记，重复安装不套娃。
_MARK: Final = "_ctf_arg_repaired"

#: 单个参数的说明截断长度（schema 里的 description 可能很长）。
_DESC_LIMIT: Final = 110

#: 提示里最多列多少个实发键。
_KEYS_LIMIT: Final = 8

#: 同一工具被拒几次后改用更硬的措辞。
_ESCALATE_AFTER: Final = 3


def _signature(schema: dict[str, Any]) -> str:
    """把 JSON schema 压成一行 ``name: type — description`` 列表。"""
    props = schema.get("properties") or {}
    required = set(schema.get("required") or ())
    parts: list[str] = []
    for name, spec in props.items():
        spec = spec if isinstance(spec, dict) else {}
        kind = spec.get("type") or spec.get("anyOf") or "any"
        if isinstance(kind, list):
            kind = "|".join(str(k) for k in kind)
        elif isinstance(kind, dict):
            kind = "object"
        desc = str(spec.get("description") or "").strip()
        desc = desc[:_DESC_LIMIT] + ("…" if len(desc) > _DESC_LIMIT else "")
        suffix = "" if name in required else " (optional)"
        parts.append(f"{name}: {kind}{suffix}" + (f" — {desc}" if desc else ""))
    return "; ".join(parts) if parts else ""


class ArgRepair:
    """按工具名统计被拒次数，决定提示的措辞。"""

    def __init__(self) -> None:
        self.repaired = 0
        self.rejected: dict[str, int] = {}

    def _message(self, tool_name: str, why: str, schema: dict[str, Any], sent: list[str]) -> str:
        count = self.rejected.get(tool_name, 0)
        self.rejected[tool_name] = count + 1
        print(f"[argrepair] {tool_name}: rejected #{count + 1} ({why})", flush=True)
        sig = _signature(schema)
        sent_text = ", ".join(sent[:_KEYS_LIMIT]) or "(nothing)"
        head = f"ARGUMENT ERROR — {tool_name} did NOT run: {why}."
        if count + 1 >= _ESCALATE_AFTER:
            head += (
                f" This is rejected call #{count + 1} with the same shape."
                " Stop resending it; either build the call from the signature below,"
                " or do something else and come back later."
            )
        lines = [head]
        if sig:
            lines.append(f"Signature: {sig}")
        else:
            lines.append("This tool takes no arguments.")
        lines.append(f"You sent these top-level keys: {sent_text}")
        lines.append(
            "Re-issue the call with every required field as its own top-level JSON key"
            " and the real content as that key's value — do not nest the arguments"
            " inside a single string field."
        )
        return "\n".join(lines)

    def check(self, tool_name: str, schema: dict[str, Any], raw_input: str) -> tuple[str, str | None]:
        """返回 ``(可交给内层的参数串, 拒绝提示)``；第二项非空时不要调用内层。

        Args:
            tool_name: 工具名，仅用于提示文案与计数。
            schema: ``tool.params_json_schema``。
            raw_input: 模型发来的原始参数串。

        Returns:
            ``(fixed, None)`` 表示放行（可能已拆包）；``(raw_input, message)`` 表示拒绝。
        """
        if not isinstance(schema, dict) or not schema:
            return raw_input, None
        props = schema.get("properties") or {}
        required = [str(k) for k in (schema.get("required") or ())]
        if not props and not raw_input.strip():
            return raw_input, None

        text = raw_input.strip()
        if not text:
            parsed: Any = {}
        else:
            try:
                parsed = json.loads(text)
            except Exception as exc:  # noqa: BLE001 - 任何解析失败都当作形状问题
                return raw_input, self._message(
                    tool_name, f"arguments are not valid JSON ({type(exc).__name__})", schema, []
                )

        if not isinstance(parsed, dict):
            return raw_input, self._message(
                tool_name,
                f"arguments must be a JSON object, got {type(parsed).__name__}",
                schema,
                [],
            )

        # ``arguments`` 本身是声明字段时，它就是合法参数，不许拆。
        if "arguments" in props:
            return raw_input, None

        # 无损拆包：{"arguments": "<json object>"} → 内层对象。
        unwrapped = False
        if set(parsed) == {"arguments"} and isinstance(parsed.get("arguments"), str):
            try:
                inner = json.loads(parsed["arguments"])
            except Exception:  # noqa: BLE001 - 拆不动就走拒绝提示
                inner = None
            if isinstance(inner, dict):
                parsed = inner
                unwrapped = True
                self.repaired += 1
                logger.info("ctf arg repair: unwrapped 'arguments' for %s", tool_name)
                print(f"[argrepair] {tool_name}: unwrapped nested 'arguments'", flush=True)

        sent = [str(k) for k in parsed]
        missing = [k for k in required if k not in parsed]
        if missing:
            return raw_input, self._message(
                tool_name,
                "missing required field(s) " + ", ".join(missing),
                schema,
                sent,
            )

        if schema.get("additionalProperties") is False and props:
            extra = [k for k in sent if k not in props]
            if extra:
                return raw_input, self._message(
                    tool_name,
                    "unexpected field(s) " + ", ".join(extra),
                    schema,
                    sent,
                )

        if unwrapped:
            return json.dumps(parsed, ensure_ascii=False), None
        return raw_input, None


def install() -> ArgRepair:
    """把参数修复层挂到最外层。

    Must be installed last: wrappers installed later run first, and every
    downstream guard must see already-repaired arguments.

    Returns:
        The installed instance, for diagnostics and tests.
    """
    from strix.agents import factory

    repair = ArgRepair()
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, _MARK, False):
            return tool
        inner = tool.on_invoke_tool
        schema = getattr(tool, "params_json_schema", None) or {}
        name = str(getattr(tool, "name", "") or "tool")

        async def invoke(ctx: Any, raw_input: str) -> Any:
            fixed, message = repair.check(name, schema, raw_input)
            if message is not None:
                return message
            return await inner(ctx, fixed)

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return repair