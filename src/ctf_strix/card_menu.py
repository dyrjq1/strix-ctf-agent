"""第 N 次工具调用后，把本题的候选卡菜单摆给模型，让它自己点 3 张。

## 为什么

见 :mod:`ctf_strix.card_pick` 模块注释：平台 tag 是题型词、卡表键是技术词，
确定性规则永远命中不了；"看到证据再挑打法"只能由模型做。起手只给 playbook
（不给具体技巧），跑几步之后再让它按已观测的线索选。

## 做法

与 :mod:`ctf_strix.turn_budget` 同一个注入点（工具结果末尾，
``factory._with_bounded_result``，经 ``guard_mount`` 已存在），一次性触发：

* 第 ``after`` 次工具调用（默认 5）注入菜单 :func:`card_pick.menu`；
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


def _enabled() -> bool:
    return os.environ.get("CTF_CARD_MENU", "1").strip().lower() not in {"0", "off", "false"}


class CardMenuGuard:
    """在第 ``after`` 次工具调用后注入一次卡菜单。线程模型同 turn_budget。"""

    def __init__(self, *, after: int = 5) -> None:
        self.after = max(int(after), 1)
        self._lock = threading.Lock()
        self._calls = 0
        self._fired = False

    def reset(self) -> None:
        with self._lock:
            self._calls = 0
            self._fired = False

    def observe(self) -> str | None:
        from ctf_strix import card_pick

        hint: str | None = None
        with self._lock:
            if self._fired:
                return None
            self._calls += 1
            if self._calls < self.after:
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


def install(after: int = 5) -> "CardMenuGuard | None":
    """挂到所有工具的调用入口；``CTF_CARD_MENU=0`` 时什么都不装。"""
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


def reset_current() -> None:
    """attempt 开始时复位计数。未安装时是 no-op。"""
    if _GUARD is not None:
        _GUARD.reset()