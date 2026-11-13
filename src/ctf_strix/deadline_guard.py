"""软截止注入 + 把观测写给父进程看门狗。

## 为什么不能只用墙钟

墙钟只有一个动作——杀。但一题失败的真实原因通常分两种，它们的正确处置
完全不同：

1. **方向错了**：还在枚举、还在试同一类载荷，时间全花在无效劳动上。
   这种该做的是**打断并逼它换机制**，不是直接判死。
2. **真的卡死了**：进程在等一个永不返回的 socket、在等 stdin、在跑一个
   死循环。这种要给再多时间也没用，该**立刻杀**。

只用一个截止时间，两种情况得到同样的处理，于是要么杀得太早（把第 1 种
误判成第 2 种），要么等得太久（一题吃掉整批 1/4 的时间）。

## 三道闸门：本模块只执行第一道

| 闸门 | 触发 | 动作 | 执行者 |
|---|---|---|---|
| 软截止 ``soft`` | 超过该秒数 | 不杀；把"必须收敛"写进下一次工具结果 | **本模块** |
| 停滞 ``stall`` | 连续该秒数无任何 LLM 输出 / 工具调用 | 杀 | 父进程看门狗 |
| 答案宽限 ``grace`` | 输出里已出现形如答案的串 | 抑制停滞判定 ``grace`` 秒，保证收尾不被"看起来安静"误杀 | 父进程看门狗 |

后两道在本模块里**只剩数据责任**：每次工具返回都把答案出现时刻与软截止状态
原子写进 sidecar（``CTF_DEADLINE_PATH``），父进程 ``scripts/eval_sample.py``
把它和 stdout 扫描合并后自己判定。这里曾有一份 ``should_kill()`` 复刻 stall/grace，
但生产链路从没有调用方——两份阈值只要不一致就会互相打架，所以删掉了：
判定只留父进程一处。

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

from ctf_strix.tool_notes import append_note

import asyncio
import json
import logging
import math
import os
import re
import threading
import time
from typing import TYPE_CHECKING, Any

from ctf_strix.flag_extract import FLAG_RE

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: 形如答案的串。命中即记下出现时刻，供父进程的"答案宽限"使用。
#:
#: 刻意宽松：宁可多给 20 秒，也不要在最后一步把已到手的答案砍掉。有一道题
#: 就是踩在这个边界上的——flag 在截止线前一刻出现，收尾没来得及跑完。
#:
#: 两个分支拼起来：前缀部分**直接取** ``FLAG_RE.pattern``（标签式前缀的唯一
#: 真值，这里不再手抄一份白名单），32-hex 分支保持原样——裸 hex 是很多平台
#: 的真实答案形态，但它不属于"标签 + 花括号"，所以只能并进来。负向环视必须
#: 留着，否则 ``key=sk-<32hex>`` 这类密钥会被当成答案（tests/test_turn_budget）。
_ANSWER_RE = re.compile(
    "(?:%s)|%s" % (FLAG_RE.pattern, r"\b(?<![A-Za-z0-9_-])[0-9a-f]{32}\b")
)

#: 施加过本守卫的工具标记。
_MARK = "_ctf_deadline"

#: 单次工具调用的默认秒数上限。
#:
#: 为什么需要一个上限：软截止提示挂在「工具返回之后」，模型一次卡在
#: ``sleep 180`` / ``yield_time_ms=120000~180000`` 里，提示就永远送不出去
#: （实测 6/7 条被外层 SIGKILL 的 run 日志里没有一行 ``[deadline]``）。给
#: 单次调用一个上限，才能保证「每次工具结果」这个注入点一直存在。
#:
#: 120 秒对应一条实测失败形态的下界：正常题单次调用是秒级到十几秒，而失败
#: 那些卡死在 2–3 分钟的显式等待上。上限只裁长尾，不动正常调用。
_DEFAULT_MAX_TOOL_SECONDS = 120.0


def _max_tool_seconds() -> float:
    """解析 ``CTF_MAX_TOOL_SECONDS``，空串/非法值/非正数一律回落默认值。

    这个值来自环境变量，配置写错不该让整道题崩掉，更不该让超时变成 0 秒
    把每一次正常工具调用都砍断。
    """
    raw = os.environ.get("CTF_MAX_TOOL_SECONDS")
    text = str(raw).strip() if raw is not None else ""
    if not text:
        return _DEFAULT_MAX_TOOL_SECONDS
    try:
        value = float(text)
    except (TypeError, ValueError):
        return _DEFAULT_MAX_TOOL_SECONDS
    if not math.isfinite(value) or value <= 0:
        return _DEFAULT_MAX_TOOL_SECONDS
    return value


class DeadlineGuard:
    """按组合时限规则监视一次 run，并在工具结果里注入收敛提示。

    线程安全：strix 的 agent 在同一个事件循环里跑，但工具调用可能跨线程，
    状态读写一律加锁。

    Args:
        wall: 硬上限（秒），到点由父进程杀，这里只用于算单次工具超时与提示进度。
        soft: 软截止（秒）；<=0 表示禁用。
        turns: 轮次上限，只用于在提示里给出"还剩几轮"。
    """

    def __init__(self, *, wall: float, soft: float, turns: int) -> None:
        self.wall = float(wall)
        self.soft = float(soft)
        self.turns = int(turns)

        self._lock = threading.Lock()
        self._start = time.time()
        self._tool_calls = 0
        self._soft_injected = False
        self._answer_seen_at: float | None = None
        self._answer: str | None = None

    # ------------------------------------------------------------ 单次调用超时
    def tool_timeout(self) -> float:
        """单次工具调用允许占用的秒数：剩余 wall 预算减去收尾预留。

        三个数各自解决一件事：

        · ``cap``（默认 120s）——裁掉「一次调用吃掉几分钟」的长尾，保证工具
          结果这个注入点还在。可用 ``CTF_MAX_TOOL_SECONDS`` 覆盖。
        · ``reserve``（40s）——留给收尾：模型看到 ``[DEADLINE]`` 之后还要发一次
          确认请求并调 ``finish_scan``，这段时间不能被下一次超时占掉。
        · ``floor``（5s）——预算已经见底时给一个仍可执行的短窗口，而不是 0 或
          负数（``wait_for(0)`` 会在调用开始前就取消，等于连一条命令都不让跑）。
        """
        remaining = self.wall - (time.time() - self._start)
        reserve = 40.0
        floor = 5.0
        cap = _max_tool_seconds()
        return max(floor, min(cap, remaining - reserve))

    # ------------------------------------------------------------ 状态查询
    def _state_locked(self) -> dict[str, Any]:
        """调用方必须已持锁。只算本模块真正会读的字段。"""
        elapsed = time.time() - self._start
        return {
            "elapsed": elapsed,
            "tool_calls": self._tool_calls,
            # soft<=0 表示"禁用软截止"。不显式排除的话 elapsed>=0 恒真，
            # 会在第一次工具结果里就灌收敛指令——实测冒烟里就踩到了。
            "soft_hit": self.soft > 0 and elapsed >= self.soft,
        }

    def snapshot(self) -> dict[str, Any]:
        """给记录用的摘要。

        ⚠️ 这个方法的调用点常常就在收尾路径上，**不能在里面再进一次**
        ``self._lock``：``threading.Lock`` 不可重入，一旦有调用方已经持锁
        再走到这里，收尾阶段会永久挂起。实测 2026-10-31 的 074/GLM 臂：
        agent 在 218.9s 就打完 ``[usage]``，随后卡在 ``[deadline]`` 这一行
        直到 600s 被墙钟 SIGKILL——每道解出的题白等近 400 秒。
        （当时是 ``snapshot()`` 自己调 ``should_kill()`` 重入；那个方法已删，
        但"这个方法只做一次取锁"的约束仍然成立。）

        所以先取锁算状态，出锁后不再做任何需要锁的动作。

        B-5 日志卫生：这里**不导出答案明文**——这个 dict 会直接进 run.log 的
        ``[deadline]`` 行（见 ``run_strix_ctf`` 收尾打印）；父进程的答案宽限
        只需要出现时刻，不需要值。
        """
        with self._lock:
            st = self._state_locked()
            answer_at_s = (
                round(self._answer_seen_at - self._start, 1)
                if self._answer_seen_at
                else None
            )
            return {
                "elapsed": round(st["elapsed"], 1),
                "tool_calls": st["tool_calls"],
                "soft_hit": self._soft_injected,
                "answer_at_s": answer_at_s,
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
            now = time.time()

            if self._answer is None:
                m = _ANSWER_RE.search(text or "")
                if m:
                    # 只做「出现过」的闩锁与时刻记录：答案明文不导出本进程
                    # （snapshot / sidecar 都只落时刻，B-5 日志卫生）。
                    self._answer = m.group(0)
                    self._answer_seen_at = now

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
        "没注入"和"注入了但没回显"。一次 run 就这样被误判成接线断了。

        写文件失败不能拖垮挑战，所以只吞掉 OSError。
        """
        path = os.environ.get("CTF_DEADLINE_PATH")
        if not path:
            return
        payload = {
            "elapsed": round(st["elapsed"], 1),
            "tool_calls": st["tool_calls"],
            "soft_hit": self._soft_injected,
            # B-5 日志卫生：sidecar 不落答案明文（父进程只消费时刻；诊断
            # 字段会随结果记录外发）。
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
            # 单次调用必须有上限：提示挂在「工具返回之后」，模型卡在一次
            # 2–3 分钟的显式等待里，软截止就永远送不出去。超时不是错误，
            # 而是「预算快没有了」这个事实的投递方式——所以超时分支照旧
            # 走下面的 observe()，让 ``[SOFT DEADLINE]`` 跟着返回。
            timeout = guard.tool_timeout()
            try:
                result = await asyncio.wait_for(inner(ctx, raw_input), timeout=timeout)
            except asyncio.TimeoutError:
                result = (
                    "[DEADLINE] this call exceeded the remaining wall-clock budget and "
                    "was aborted. Do not retry it, do not sleep, do not start any new "
                    "enumeration. If you already hold the answer, report it verbatim "
                    "NOW; otherwise send the single request or command that would "
                    "confirm your strongest lead, then finish_scan immediately."
                )
            except asyncio.CancelledError:
                # 硬截止取消整条 run 时不能被当成超时吞掉：吞了就再也杀不掉。
                raise
            try:
                hint = guard.observe(f"{raw_input}\n{result}")
            except Exception:  # noqa: BLE001 - 计时器故障不能拖垮挑战本身
                logger.warning("deadline guard observe failed", exc_info=True)
                return result
            if hint:
                return append_note(result, hint)
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
