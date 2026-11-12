"""turn 预算倒计时：在 ``MaxTurnsExceeded`` 之前让模型有序交卷。

## 为什么需要它

尸检（2026-11-12，8 局对照 run）里 4/8 失败局的直接死因是**轮次耗尽**：
finish 被拒 1-3 次 → 在低产出路径上空转 → attempt 预算打满 → vendor 抛
``MaxTurnsExceeded``，``result=None``，一个字都没交。墙钟侧已有
[SOFT DEADLINE] 收敛提示，但预算耗尽的局时间上往往远没到软截止——
**模型对"我还剩几轮"零感知**，而时间对"我还剩几秒"同样零感知的问题
已经用工具结果注入解决过一次（见 ``deadline_guard`` 模块注释），轮次
是同一个问题的另一半。

## 做法

与 ``deadline_guard`` 同一注入点（工具结果末尾，紧贴下一步决策）、
同样的外层包装（``factory._with_bounded_result``），两个一次性触发点：

==========  =====================================================
触发点      注入内容
==========  =====================================================
75% 预算    收敛提醒：停开新调查线，把已有线索推向"读到真答案"
剩最后 N 轮 强指令交卷：立刻报出当前最强候选；被 finish 拒收就
            用剩余轮次抓具体数据，不许再开新调查
==========  =====================================================

按 **attempt** 计数与复位：``agent.py`` 的 attempt 循环里每个 attempt
预算不同（``_attempt_turns`` 按 split 切分），attempt 开始时调
:func:`reset`。这与 ``enum_guard.soft_reset``/``idle.reset`` 同一时机，
理由也相同——新 attempt 本身就是"换机制"的指令，旧计数不该继承。
"""

from __future__ import annotations

import logging
import math
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: 施加过本守卫的工具标记。
_MARK = "_ctf_turn_budget"

#: 模块级当前守卫。``agent.py`` 在 attempt 循环里经 :func:`reset_current`
#: 复位；包装层经 :func:`active_guard` 取。装一次、进程内复用。
_GUARD: "TurnBudgetGuard | None" = None


class TurnBudgetGuard:
    """按 attempt 的轮次预算计数，并在阈值处往工具结果里注入倒计时。

    线程模型与 ``DeadlineGuard`` 相同：状态读写加锁。

    Args:
        warn_frac: 达到该预算比例时注入收敛提醒（一次性）。
        final_reserve: 剩余轮次 ≤ 该值时注入交卷强指令（一次性）。
    """

    def __init__(self, *, warn_frac: float = 0.75, final_reserve: int = 5) -> None:
        self.warn_frac = float(warn_frac)
        self.final_reserve = max(int(final_reserve), 1)

        self._lock = threading.Lock()
        self._budget = 0
        self._calls = 0
        self._warned = False
        self._final = False

    # ------------------------------------------------------------ 生命周期
    def reset(self, budget: int) -> None:
        """开始一个新 attempt：换预算、清计数与已触发标志。

        ``budget <= 0`` 表示该 attempt 无预算上限——守卫保持静默。
        """
        with self._lock:
            self._budget = max(int(budget), 0)
            self._calls = 0
            self._warned = False
            self._final = False

    @property
    def calls(self) -> int:
        with self._lock:
            return self._calls

    # ------------------------------------------------------------ 观察
    def observe(self) -> str | None:
        """记一次工具调用，返回要追加到工具结果后的提示（或 None）。"""
        hint: str | None = None
        with self._lock:
            if self._budget <= 0:
                return None
            self._calls += 1
            warn_at = max(math.ceil(self._budget * self.warn_frac), 1)
            final_at = max(self._budget - self.final_reserve, warn_at)
            used, remaining = self._calls, max(self._budget - self._calls, 0)

            if self._calls >= final_at and not self._final:
                self._final = True
                hint = self._final_hint(used, remaining)
            elif self._calls >= warn_at and not self._warned:
                self._warned = True
                hint = self._warn_hint(used, remaining)
        return hint

    # ------------------------------------------------------------ 提示文案
    def _warn_hint(self, used: int, remaining: int) -> str:
        return (
            f"\n\n[TURN BUDGET] {used} of {self._budget} tool calls used this "
            f"attempt, {remaining} left. Stop opening new lines of "
            "investigation. Drive what you already have toward reading the "
            "real answer: one concrete exploit/decode/read beats three more "
            "probes."
        )

    def _final_hint(self, used: int, remaining: int) -> str:
        return (
            f"\n\n[TURN BUDGET FINAL] Only {remaining} tool calls left in this "
            "attempt, then it ends automatically with nothing submitted. Do "
            "ONE of these now:\n"
            "  (a) If you have a candidate answer, report it verbatim "
            "immediately.\n"
            "  (b) If finish was refused for lack of a flag, spend the "
            "remaining calls pulling concrete data (dump the table, cat the "
            "config, read the file) — not on new reconnaissance.\n"
            "An attempt that ends unsubmitted scores zero regardless of how "
            "close it was."
        )


def install() -> "TurnBudgetGuard":
    """把轮次守卫挂到所有工具的调用入口上。

    必须在 ``guard_mount.install_mount_hook()`` 之后、且**晚于**
    ``deadline_guard.install()`` 调用：两个守卫替换同一个
    ``factory._with_bounded_result``，后装的在最外层，提示才会出现在
    最终结果末尾（[SOFT DEADLINE] 在前、[TURN BUDGET] 在后，与决策的
    距离最近）。

    Raises:
        RuntimeError: 挂载钩子未装。静默失效比启动就炸更糟，所以宁可炸。
    """
    from strix.agents import factory

    global _GUARD  # noqa: PLW0603 - 进程内单例
    if _GUARD is not None:
        return _GUARD

    if not getattr(factory, "_ctf_mounted", False):
        raise RuntimeError(
            "call guard_mount.install_mount_hook() before turn_budget.install()"
        )

    guard = TurnBudgetGuard()
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
            except Exception:  # noqa: BLE001 - 计数器故障不能拖垮挑战本身
                logger.warning("turn budget guard observe failed", exc_info=True)
                return result
            if hint:
                return f"{result}{hint}"
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    _GUARD = guard
    logger.info("Turn budget guard installed")
    return guard


def reset_current(budget: int) -> None:
    """attempt 开始时复位计数。未安装时是 no-op，调用方无须判断。"""
    if _GUARD is not None:
        _GUARD.reset(budget)
