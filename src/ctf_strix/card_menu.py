"""第 N 轮之后，把本题的候选卡菜单摆给模型，让它自己点 3 张。

## 为什么

见 :mod:`ctf_strix.card_pick` 模块注释：平台 tag 是题型词、卡表键是技术词，
确定性规则永远命中不了；"看到证据再挑打法"只能由模型做。起手只给 playbook
（不给具体技巧），跑几步之后再让它按已观测的线索选。

## 轮次的定义

「一轮」= 模型的一次输入→输出（一次 ``get_response`` / 一次完整的
``stream_response``），**不是**一次工具调用：同一条回复里的并行工具调用是
一轮，模型只发文本不发工具也是一轮。计数挂在模型上（:class:`_TurnProxy` 包
``StrixProvider.get_model`` 的返回值，与 llm_compat / context 的代理同一条
接缝），所以工具数量变化不影响"第几轮"。

## 做法

与 :mod:`ctf_strix.turn_budget` 同一个注入点（工具结果末尾，
``factory._with_bounded_result``，经 ``guard_mount`` 已存在），一次性触发：

* 第 ``after`` 轮（默认 3）的回复之后，**该轮工具调用的结果**上注入菜单
  :func:`card_pick.menu`——工具结果就是模型下一轮输入的尾部，模型在看到它
  的同时看到菜单；
* 已经选过卡（``card_pick.chosen()`` 非空）或卡池为空时不再注入。

按 attempt 复位：``agent.py`` 的 attempt 循环里调 :func:`reset_current`。
关掉用 ``CTF_CARD_MENU=0``（消融/对照臂），默认开。
"""

from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING, Any

from ctf_strix.tool_notes import append_note

if TYPE_CHECKING:  # pragma: no cover
    from agents import FunctionTool

logger = logging.getLogger(__name__)

_MARK = "_ctf_card_menu"

#: 模块级当前守卫；``agent.py`` 在 attempt 循环里复位。
_GUARD: "CardMenuGuard | None" = None


class TurnCounter:
    """模型已完成回复的计数（一轮 = 一次输入→输出）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._turns = 0

    def bump(self) -> int:
        with self._lock:
            self._turns += 1
            return self._turns

    def current(self) -> int:
        with self._lock:
            return self._turns

    def reset(self) -> None:
        with self._lock:
            self._turns = 0


#: 进程内单例：模型代理与守卫都读它，attempt 复位时归零。
_TURNS = TurnCounter()


def _counts_as_a_turn(args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
    """这次模型调用算不算「一轮」。

    压缩/去重这类工具面为空的内部调用不算：它们不是题目推理的一轮，
    计入会把菜单提前一轮摆出来。判据只看 ``tools``——题目推理的调用都带
    工具表，内部总结调用显式传 ``tools=[]``。
    """
    tools = kwargs.get("tools")
    if tools is None and len(args) > 3:
        tools = args[3]
    if tools is None:
        return True  # 看不出来就按真轮次算（宁可晚一轮，不吞轮次）
    return bool(tools)


class _TurnProxy:
    """透明代理：数模型回复轮次，其余一律转发给内层 Model。"""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def close(self) -> None:
        await self._inner.close()

    async def _cleanup_on_run_end(self, owner: object) -> None:
        await self._inner._cleanup_on_run_end(owner)

    def get_retry_advice(self, request: Any) -> Any:
        return self._inner.get_retry_advice(request)

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        result = await self._inner.get_response(*args, **kwargs)
        if _counts_as_a_turn(args, kwargs):
            _TURNS.bump()
        return result

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        counted = _counts_as_a_turn(args, kwargs)
        inner = self._inner.stream_response(*args, **kwargs)

        async def _gen() -> Any:
            completed = False
            try:
                async for event in inner:
                    yield event
                completed = True
            finally:
                # 半路被取消/关闭的流不算一轮：那次的输入模型没答完。
                if completed and counted:
                    _TURNS.bump()

        return _gen()


def _enabled() -> bool:
    return os.environ.get("CTF_CARD_MENU", "1").strip().lower() not in {"0", "off", "false"}


class CardMenuGuard:
    """第 ``after`` 轮（默认 3）之后注入一次卡菜单。线程模型同 turn_budget。

    注入点仍是工具结果末尾：第 ``after`` 轮的回复发完之后，该轮工具调用
    的结果回来时把菜单接在后面。守卫只读 :data:`_TURNS`，自己不数工具。
    """

    def __init__(self, *, after: int = 3) -> None:
        self.after = max(int(after), 1)
        self._lock = threading.Lock()
        self._fired = False

    @property
    def fired(self) -> bool:
        """菜单是否已经摆给模型看过（本 attempt）。"""
        with self._lock:
            return self._fired

    def reset(self) -> None:
        with self._lock:
            self._fired = False
        _TURNS.reset()

    def observe(self) -> str | None:
        from ctf_strix import card_pick

        hint: str | None = None
        with self._lock:
            if self._fired:
                return None
            if _TURNS.current() < self.after:
                return None
            self._fired = True
        try:
            if card_pick.chosen() or card_pick.pool_size() == 0:
                return None
            text = card_pick.menu()
        except Exception:  # noqa: BLE001 - 菜单故障不能拖垮挑战本身
            logger.warning("card menu failed", exc_info=True)
            return None
        return ("\n\n" + text) if text else None


def install(after: int = 3) -> "CardMenuGuard | None":
    """挂到所有工具的调用入口 + 模型回复计数；``CTF_CARD_MENU=0`` 时什么都不装。"""
    global _GUARD  # noqa: PLW0603 - 进程内单例
    if not _enabled():
        return None
    if _GUARD is not None:
        return _GUARD

    from strix.agents import factory

    if not getattr(factory, "_ctf_mounted", False):
        raise RuntimeError(
            "call guard_mount.install_mount_hook() before card_menu.install()"
        )

    _install_turn_proxy()
    guard = CardMenuGuard(after=after)
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, _MARK, False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            try:
                hint = guard.observe()
            except Exception:  # noqa: BLE001
                logger.warning("card menu observe failed", exc_info=True)
                return result
            if hint:
                return append_note(result, hint)
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    _GUARD = guard
    logger.info("Card menu guard installed")
    return guard


def _install_turn_proxy() -> bool:
    """把轮次计数代理挂到 ``StrixProvider.get_model`` 上（幂等）。

    与 llm_compat / context 同一个接缝：它们各自包一层透明代理，互不感知、
    顺序无关。模型在 scan_setup 里构造，本函数在那之前调用。
    """
    from strix.config.models import StrixProvider

    if getattr(StrixProvider, "_ctf_card_turns_patched", False):
        return True
    original = StrixProvider.get_model

    def patched(self: Any, model_name: str | None) -> Any:
        return _TurnProxy(original(self, model_name))

    StrixProvider.get_model = patched  # type: ignore[method-assign]
    StrixProvider._ctf_card_turns_patched = True  # type: ignore[attr-defined]
    logger.info("Card menu turn counter installed")
    return True


def reset_current() -> None:
    """attempt 开始时复位计数（轮次 + 已注入标记）。未安装时是 no-op。"""
    if _GUARD is not None:
        _GUARD.reset()


def shown() -> bool:
    """菜单是否已摆给模型看过（未安装 / 未到轮次 / 已复位都算没摆）。"""
    guard = _GUARD
    return bool(guard is not None and guard.fired)