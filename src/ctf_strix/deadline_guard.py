"""组合时限：软截止 + 停滞检测 + 答案宽限。

## 为什么不能只用墙钟

墙钟只有一个动作——杀。但一题失败的真实原因通常分两种，它们的正确处置
完全不同：

1. **方向错了**：还在枚举、还在试同一类载荷，时间全花在无效劳动上。
   这种该做的是**打断并逼它换机制**，不是直接判死。
2. **真的卡死了**：进程在等一个永不返回的 socket、在等 stdin、在跑一个
   死循环。这种要给再多时间也没用，该**立刻杀**。

只用一个截止时间，两种情况得到同样的处理，于是要么杀得太早（把第 1 种
误判成第 2 种），要么等得太久（一题吃掉整批 1/4 的时间）。

## 三道闸门

| 闸门 | 触发 | 动作 |
|---|---|---|
| 软截止 ``soft`` | 超过该秒数 | 不杀；把"必须收敛"写进下一次工具结果 |
| 停滞 ``stall`` | 连续该秒数无任何 LLM 输出 / 工具调用 | 杀 |
| 答案宽限 ``grace`` | 输出里已出现形如答案的串 | 抑制停滞判定 ``grace`` 秒，保证收尾不被"看起来安静"误杀 |

轮次上限保持原样。**用时间替代轮次是错的**：时间是环境的属性（机器快慢、
网络抖动），轮次才是成本的直接约束。

## 为什么注入点在工具结果里

与 `enum_guard` 同一结论：写进 system prompt 的"请及时收敛"会随上下文增长
衰减，模型对"我已经跑了多久"没有感知。而工具结果是紧贴下一步决策的输入，
在那里插入一条带具体秒数的提示，才真的会改变下一轮的行为。

## 为什么不用 ``on_llm_start`` 改 ``input_items``

那是 strix `ReportUsageHooks` 的做法，但本模块要在**墙钟被杀**的场景下
仍然有效，而 `on_llm_start` 只在模型被调用时触发——卡死时永远不会触发。
工具结果注入则挂在实际调用上，两者互补。
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: 形如答案的串。用于"答案宽限"判定。
#:
#: 刻意宽松：宁可多给 20 秒，也不要在最后一步把已到手的答案砍掉。SAMPLE-005
#: 就是踩在这个边界上的——flag 在截止线前一刻出现，收尾没来得及跑完。
_ANSWER_RE = re.compile(
    r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[^}\s]{2,}\}|\b[0-9a-f]{32}\b"
)

#: 施加过本守卫的工具标记。
_MARK = "_ctf_deadline"


class DeadlineGuard:
    """按组合时限规则监视一次 run，并在工具结果里注入收敛提示。

    线程安全：strix 的 agent 在同一个事件循环里跑，但工具调用可能跨线程，
    状态读写一律加锁。

    Args:
        wall: 硬上限（秒），到点由父进程杀，这里只用于算进度。
        soft: 软截止（秒）。
        stall: 停滞阈值（秒）。
        grace: 答案宽限（秒）。
        turns: 轮次上限，只用于在提示里给出"还剩几轮"。
    """

    def __init__(
        self,
        *,
        wall: float,
        soft: float,
        stall: float,
        grace: float,
        turns: int,
    ) -> None:
        self.wall = float(wall)
        self.soft = float(soft)
        self.stall = float(stall)
        self.grace = float(grace)
        self.turns = int(turns)

        self._lock = threading.Lock()
        self._start = time.time()
        self._last_activity = self._start
        self._tool_calls = 0
        self._soft_injected = False
        self._answer_seen_at: float | None = None
        self._answer: str | None = None
        self._grace_verdict: bool | None = None
        self.observations = 0

    # ------------------------------------------------------------ 状态查询
    def _state_locked(self) -> dict[str, Any]:
        now = time.time()
        elapsed = now - self._start
        idle = now - self._last_activity
        return {
            "now": now,
            "elapsed": elapsed,
            "idle": idle,
            "tool_calls": self._tool_calls,
            "remaining": max(self.wall - elapsed, 0.0),
            "idle_left": max(self.stall - idle, 0.0),
            # soft<=0 表示"禁用软截止"。不显式排除的话 elapsed>=0 恒真，
            # 会在第一次工具结果里就灌收敛指令——实测冒烟里就踩到了。
            "soft_hit": self.soft > 0 and elapsed >= self.soft,
            "answer": self._answer,
        }

    def should_kill(self) -> str | None:
        """是否该由父进程杀掉本次 run。

        Returns:
            触发原因；不该杀返回 None。

            · ``stall`` —— 长时间没有任何工具活动（真卡死）。
            · ``wall``  —— 已到硬上限。**硬上限不可被任何规则延长**。
        """
        with self._lock:
            st = self._state_locked()
            answer_at = self._answer_seen_at
        # 已有答案时不判停滞：它可能正在组织最终答案，不是卡死。答案宽限
        # 只作用于这一条判定——它让"安静"在这段时间里不算可疑，但绝不延长
        # 硬上限（否则任何早出现的候选串都能白拿额外预算）。
        if st["idle"] >= self.stall:
            # 宽限只在**答案出现之后的那一个** stall 窗口内生效：它保护的是
            # "刚拿到答案、正在组织收尾"这一段，而不是给后续所有静默永久免死。
            # 用一次性标志实现，否则日志里一旦出现任何形似 flag 的串（包括
            # 题面里的示例），整题的停滞检测就永久失效。
            #
            # 标志必须在**第一次判定时**就置位并记住结论（见 `_grace_verdict`），
            # 不能每次都重算——`idle` 只增不减，否则"返回一次 None 之后下一次
            # 立刻变 stall"，等于宽限从来没起作用。
            if self._grace_verdict is None:
                lag = None if answer_at is None else st["now"] - answer_at
                if lag is not None and lag > self.grace:
                    return "stall"  # 答案早就是"旧闻"，宽限无从谈起
                self._grace_verdict = lag is not None
            return None if self._grace_verdict else "stall"
        if st["elapsed"] >= self.wall:
            return "wall"
        return None

    def snapshot(self) -> dict[str, Any]:
        """给记录用的摘要。"""
        with self._lock:
            st = self._state_locked()
            return {
                "elapsed": round(st["elapsed"], 1),
                "tool_calls": st["tool_calls"],
                "soft_hit": self._soft_injected,
                "answer_at_s": round(self._answer_seen_at - self._start, 1)
                if self._answer_seen_at else None,
                "answer": self._answer,
                "killed_for": self.should_kill(),
            }

    # ------------------------------------------------------------ 观察
    def observe(self, text: str) -> str | None:
        """记一次活动，返回要追加到工具结果后的提示（或 None）。

        Args:
            text: 本次工具调用的原始参数与结果文本，用于探测答案串。

        Returns:
            提示文本；无需提示时返回 None。
        """
        hint: str | None = None
        with self._lock:
            self._tool_calls += 1
            self._last_activity = time.time()
            self.observations += 1

            if self._answer is None:
                m = _ANSWER_RE.search(text or "")
                if m:
                    self._answer = m.group(0)
                    self._answer_seen_at = self._last_activity

            st = self._state_locked()

        if st["soft_hit"] and not self._soft_injected:
            with self._lock:
                self._soft_injected = True
            hint = self._soft_hint(st)
        self._flush(st)
        return hint

    def _flush(self, st: dict[str, Any]) -> None:
        """把状态落到 sidecar，供父进程的看门狗读取。

        注入的是工具**返回值**，而 strix 的事件日志回显的是注入之前的原始
        输出——父进程翻 stdout 只能看到"没有 [SOFT DEADLINE]"，无法区分
        "没注入"和"注入了但没回显"。SAMPLE-004 就这样被误判成接线断了。

        写文件失败不能拖垮挑战，所以只吞掉 OSError。
        """
        path = os.environ.get("CTF_DEADLINE_PATH")
        if not path:
            return
        payload = {
            "elapsed": round(st["elapsed"], 1),
            "tool_calls": st["tool_calls"],
            "soft_hit": self._soft_injected,
            "answer": self._answer,
            "answer_at_s": round(self._answer_seen_at - self._start, 1)
            if self._answer_seen_at
            else None,
        }
        try:
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp, path)
        except OSError:
            logger.warning("deadline sidecar write failed", exc_info=True)

    def _soft_hint(self, st: dict[str, Any]) -> str:
        """软截止时注入的收敛指令。

        刻意不去说"还有 X 秒就杀掉"——那会诱导模型为了保命而乱交一个猜测。
        要它做的是**收敛动作**：把手头最强的线索打到最后一击，或者直接报出
        已得到的答案。
        """
        return (
            f"\n\n[SOFT DEADLINE] {st['elapsed']:.0f}s elapsed, hard stop at "
            f"{self.wall:.0f}s. Stop exploring. From now on pick ONE:\n"
            "  (a) If you already have the answer, report it verbatim NOW.\n"
            "  (b) Otherwise take the single strongest lead you have and send the "
            "one request/command that would confirm it. No new enumeration, no "
            "new wordlists, no re-reading files you already read.\n"
            f"You have used {st['tool_calls']} tool calls of a {self.turns}-turn budget. "
            "An unfinished attempt scores zero, so a confirmed partial answer is "
            "worth more than one more probe."
        )


def install(guard: DeadlineGuard) -> DeadlineGuard:
    """把 ``guard`` 挂到所有工具的调用入口上。

    必须在 `guard_mount.install_mount_hook()` **之后**、其他守卫之后调用：
    它同样替换 ``factory._with_bounded_result``，而挂载钩子里读的是
    ``factory`` 上的**当前**属性，所以后装的会套在最外层——这正是我们要的
    位置：收敛提示应该出现在最终结果的末尾，紧跟模型下一步决策。

    Args:
        guard: 已构造好的监视器。

    Returns:
        同一个 guard，方便链式使用。

    Raises:
        RuntimeError: 未先调用 ``install_mount_hook``。这会静默失效，
            所以宁可启动就炸。
    """
    from strix.agents import factory

    if not getattr(factory, "_ctf_mounted", False):
        raise RuntimeError("call guard_mount.install_mount_hook() before deadline.install()")

    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, _MARK, False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            try:
                hint = guard.observe(f"{raw_input}\n{result}")
            except Exception:  # noqa: BLE001 - 计时器故障不能拖垮挑战本身
                logger.warning("deadline guard observe failed", exc_info=True)
                return result
            if hint:
                return f"{result}{hint}"
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
