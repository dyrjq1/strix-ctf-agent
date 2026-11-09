"""守卫挂载点：把三个运行时守卫接到**所有**会产生工具调用的路径上。

## 这一层为什么必须存在

三个守卫（`enum_guard` / `journey_guard` / `finish_guard`）都是通过替换
``factory._with_bounded_result`` 来改 ``on_invoke_tool`` 的。这个手法本身没错——
但**它是错的挂载点**。

strix 建造 agent 时走三条不同的路：

1. ``factory._build_agent`` 里的常规工具列表 → 逐个过 ``_with_bounded_result``；
2. ``Shell`` capability 的 ``configure_tools`` → 走 ``_configure_shell_tools``，
   **完全绕过** ``_with_bounded_result``；
3. ``Filesystem`` capability 的 ``configure_tools`` → 走 ``_configure_filesystem_tools``，
   会经过。

而 ``exec_command`` 和 ``write_stdin``——**唯一能真正把请求打到靶机上的两个工具**
——只存在于第 2 条路上。

## 后果有多严重（实测）

一次复跑：45 次调用、1170s 撞墙钟、日志里 16 次 401/403，
三个守卫的计数器**全是 0**。把这次运行的真实会话（``.state/agents.db`` 里的
``function_call`` / ``function_call_output`` 逐条）灌进同一个守卫类重放，
结果是 ``wall_hit=7 payloads=9 prompts=3``——**判定逻辑完全正确，只是从来没被调用过**。

所以之前所有"守卫无效"的结论都推错了方向：不是规则不对，是接线没接上。
守卫只覆盖了 ``view_agent_graph``、``create_agent``、``think`` 这类流程工具，
它们永远不会发出攻击载荷，自然一次都不触发。

## 修法

不碰 vendor 代码，用**三重挂钩**把 ``_with_bounded_result`` 变成真正的统一挂载点：

- 替换 ``factory._with_bounded_result``（常规路径，原有行为）；
- 替换 ``factory._configure_shell_tools``，先跑原函数，再把注入过的
  ``_with_bounded_result`` 施加到 toolset 的每个工具；
- 替换 ``factory._configure_filesystem_tools``，同上。

三条路的幂等标记各自独立，重复施加不会套娃。这样 ``_with_bounded_result``
这个名字才当得起它的作用——**任何 FunctionTool 进 agent 前都会经过这里**。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable, Final

if TYPE_CHECKING:
    from agents.tool import FunctionTool

logger = logging.getLogger(__name__)

#: 施加过守卫的工具会带上这个标记，避免三重挂钩互相套娃。
_MARK = "_ctf_mounted"

#: Character ceiling for any single tool output.  Strix's own
#: ``_with_bounded_result`` caps at 50 KB bytes; this is a narrower
#: character-level safety net that applies to every path (regular /
#: Shell / filesystem).  The value is borrowed from strix's 50 KB
#: byte budget (one UTF-8 char ≤ 4 bytes = ~12.5k chars, doubled
#: for non-ASCII headroom).  This is a wiring fix, not a budget
#: tuning knob -- the ceiling already existed; it just was not
#: universally enforced.
_TOOL_OUTPUT_MAX_CHARS: Final = 32_000


def _clip_output(text: str) -> str:
    """Return *text* unchanged when under the ceiling, else head + tail."""
    limit = _TOOL_OUTPUT_MAX_CHARS
    if len(text) <= limit:
        return text
    head = limit * 3 // 4
    tail = limit - head - 40
    return text[:head] + f"\n...[truncated {len(text)} chars total]\n" + text[-tail:]


def _wrap_for_truncation(tool: "FunctionTool") -> "FunctionTool":
    """Wrap *tool* so every output string is clipped to the ceiling.

    Idempotent; does nothing when the tool already carries the mark.
    Runs *outside* the strix byte-level cap so it catches anything
    that escapes that layer, including structured returns that the
    byte cap skips.
    """
    if getattr(tool, "_ctf_output_clipped", False):
        return tool

    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        result = await invoke_tool(ctx, raw_input)
        if isinstance(result, str):
            result = _clip_output(result)
        return result

    tool.on_invoke_tool = invoke
    tool._ctf_output_clipped = True
    return tool


def _apply_to_toolset(toolset: Any, mount: Callable[["FunctionTool"], "FunctionTool"]) -> None:
    """把 ``mount`` 施加到 toolset 上的每个 FunctionTool。

    toolset 是 capability 构造出来的临时对象（``vars()`` 即可枚举），
    它的字段就是最终交给 agent 的工具实例。

    Args:
        toolset: capability 的 toolset 实例。
        mount: 挂载函数，即被替换过的 ``_with_bounded_result``。
    """
    from agents.tool import FunctionTool

    for name, tool in list(vars(toolset).items()):
        if not isinstance(tool, FunctionTool):
            continue
        try:
            setattr(toolset, name, mount(tool))
        except Exception:  # noqa: BLE001 - 挂载失败不能拖垮建 agent
            logger.warning("ctf guard mount failed for tool %r", name, exc_info=True)


def install_mount_hook() -> None:
    """把 ``_with_bounded_result`` 变成覆盖 shell / filesystem 路径的统一挂载点。

    必须在任何守卫 ``install()`` **之前**调用：守卫们替换的是
    ``factory._with_bounded_result`` 这个属性，本函数把这条属性真正接到
    capability 路径上。

    幂等：重复调用只装一次。
    """
    from strix.agents import factory

    if getattr(factory, _MARK, False):
        return

    original_shell = factory._configure_shell_tools
    original_fs = factory._configure_filesystem_tools

    def shell_hook(toolset: Any, **kwargs: Any) -> None:
        original_shell(toolset, **kwargs)
        # 注意：必须读 factory 上的**当前**属性，而不是 import 时抓到的快照。
        # 三个守卫会依次替换这个属性，用快照会漏掉后装的守卫。
        _apply_to_toolset(toolset, factory._with_bounded_result)

    def fs_hook(toolset: Any, **kwargs: Any) -> None:
        original_fs(toolset, **kwargs)
        _apply_to_toolset(toolset, factory._with_bounded_result)

    # Layer the output truncation *outside* the guards so it runs
    # after every guard has recorded its counters but before the
    # result enters history.  This is the narrowest character-level
    # ceiling and catches any path that the strix byte-level cap
    # misses (structured returns, sub-agent channels, etc.).
    _original_bounded = factory._with_bounded_result

    def _bounded_with_truncation(tool: Any) -> Any:
        return _wrap_for_truncation(_original_bounded(tool))

    factory._with_bounded_result = _bounded_with_truncation  # type: ignore[assignment]

    factory._configure_shell_tools = shell_hook  # type: ignore[assignment]
    factory._configure_filesystem_tools = fs_hook  # type: ignore[assignment]
    factory._ctf_mounted = True  # type: ignore[attr-defined]


def verify_mount(expected_marks: tuple[str, ...] = ("_ctf_guarded",)) -> bool:
    """跑一遍真实配置路径，确认守卫标记确实落到了 `exec_command` 上。

    **必须在所有守卫 `install()` 之后调用**——它验证的是"最终接线"，不是
    "钩子装上了"。

    这个函数存在的理由值得写下来：这次 bug 的本质是**静默失效**。日志打印了
    ``guard installed``、程序不报任何错、计数器永远是 0，而 0 恰好和"今天没
    触发"长得一模一样。把"是否真的挂上"变成启动时就能看见的一行输出，
    就不会再出现"跑了 1170 秒才发现守卫全废"。

    Args:
        expected_marks: 必须出现在 `exec_command` 私有属性里的标记，
            默认只要求枚举守卫（旅程守卫可选加进来）。改成传参，
            测试里可以放宽或加严。

    Returns:
        接线正确返回 True；否则返回 False 并打 warning。
    """
    from strix.agents import factory

    try:
        from agents.tool import FunctionTool
    except Exception:  # noqa: BLE001 - SDK 不可用，当作无法验证
        return False

    async def _noop(ctx: Any, raw: str) -> str:
        return "verify"

    class _Probe:
        pass

    probe = _Probe()
    for tool_name in ("exec_command", "write_stdin"):
        setattr(
            probe,
            tool_name,
            FunctionTool(
                name=tool_name,
                description="verify",
                params_json_schema={"type": "object", "properties": {}},
                on_invoke_tool=_noop,
            ),
        )

    try:
        factory._configure_shell_tools(probe, chat_completions=False, strict_schemas=False)
    except Exception:  # noqa: BLE001 - 配置失败本身就是接线问题
        logger.warning("ctf guard verify: configure_shell_tools raised", exc_info=True)
        return False

    marks = {a for a in vars(probe.exec_command) if a.startswith(("_ctf_", "_strix_"))}
    missing = [m for m in expected_marks if m not in marks]
    if missing:
        logger.warning(
            "ctf guard verify FAILED: exec_command missing %s (has %s) — guards inert",
            missing,
            sorted(marks),
        )
        return False
    return True
