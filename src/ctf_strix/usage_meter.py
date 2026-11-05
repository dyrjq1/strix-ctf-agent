"""统计一次 run 的 token 用量（含所有子 agent）。

## 为什么需要单独做

strix 自己有 ``ReportUsageHooks`` 会把用量记进 ``report_state``，并落盘到 run
目录——但那是**给人看的运行报告**，字段形状随版本变，且要等一次完整
``save_run_data`` 才写出去。评测要的是"这一题花了多少 token"，必须能稳定读到。

而且批测里被墙钟杀掉是常态。被 SIGKILL 的进程没有机会保存任何东西，所以
计数器必须**由我们持有**，且能在进程内被父进程读到（本模块是给 ``run_strix_ctf``
这种"一题一进程"的场景用的，进程退出前把数字打进 stdout）。

## 手法

monkey-patch ``ReportUsageHooks.on_llm_end``：先累加，再调原函数。
和三个守卫一样——运行时注入，不改 vendor 代码，strix 升级不用 rebase。

## 为什么挂在 on_llm_end 而不是包 LLM client

``on_llm_end`` 拿到的是**SDK 已经归一化过的** ``Usage``，包含了 provider
特有的 cache/推理 token 处理。包 client 需要自己解析各家响应格式，容易漏。
挂 hook 拿到的数字和 strix 自己报表用的是同一个来源，不会打架。
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: 单次调用输出 token 的默认硬顶。正常 answer / 推理调用多在 8k 以内；
#: 一次调用生成 3 万以上几乎只能是失控循环或病态长推理。取 2^15：
#: 对正常调用留出约 4 倍余量，对 151k 的实测失控事件仍低 4.6 倍。
#: 这是止损守卫（watchdog），不是可调预算旋钮：用环境变量覆盖只为
#: 诊断/复现，不改变「单次调用」这个判据。
DEFAULT_MAX_OUTPUT_PER_CALL = 32_768
_CAP_ENV = "CTF_MAX_OUTPUT_PER_CALL"


class OutputBudgetExceeded(BaseException):
    """一次 LLM 调用的输出超过硬顶。

    故意继承 ``BaseException``：strix 的 turn 循环与工具层到处是
    ``except Exception``，普通异常会被吞成一条工具错误然后继续跑，
    失控调用已经发生，继续跑只会把墙钟烧光。必须像
    ``WallclockExceeded`` 一样直达 ``main`` 的收尾，让 finally 写出
    result.json。
    """

    def __init__(self, message: str, *, output_tokens: int, cap: int) -> None:
        super().__init__(message)
        self.output_tokens = int(output_tokens)
        self.cap = int(cap)


#: 进程级累计。评测是"一题一进程"，所以不需要按 run 区分。
_lock = threading.Lock()
_calls: int = 0
_input_tokens: int = 0
_output_tokens: int = 0
_total_tokens: int = 0
_installed = False
#: 第一次触顶的诊断。只记一次，后续调用只负责继续抛，不再覆盖现场。
_trip: dict[str, Any] | None = None
#: install() 时保存的原始 hook，供测试恢复；生产进程不会用它。
_originals: tuple[Any, Any] | None = None
#: 由父进程用环境变量指定。每轮 LLM 调用后立即原子写盘，这样即使本进程随后
#: 被墙钟 SIGKILL，父进程仍能读到"死前已经花了多少"，不会把真实消耗记成 0。
_sink: Path | None = None


#: 当前是否有一次 LLM 请求在路上，以及它是什么时候发出的（epoch 秒）。
#:
#: 父进程的停滞检测只能看见 stdout 里的 TOOL/OUT 行，而模型"正在思考"这段
#: 时间完全不产生任何行。SAMPLE-006 因此被误杀：83 秒后最后一个工具返回，
#: 模型接着跑了一次 60 秒以上的长推理，看门狗直接判 stall——它没卡死，
#: 只是在想。所以额外暴露一个在途标记：请求发出时置位，回来时清掉。
_inflight_since: float | None = None


def _persist_locked() -> None:
    """把当前累计值原子写到 sink。调用方必须已持有 ``_lock``。"""
    if _sink is None:
        return
    payload = {
        "llm_calls": _calls,
        "input_tokens": _input_tokens,
        "output_tokens": _output_tokens,
        "total_tokens": _total_tokens,
        "inflight_since": _inflight_since,
    }
    tmp = _sink.with_name(f".{_sink.name}.{os.getpid()}.tmp")
    try:
        _sink.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, _sink)
    except OSError:
        # 计量失败不能影响挑战本身；最坏退化成 stdout 的收尾行。
        logger.warning("Failed to persist usage snapshot to %s", _sink, exc_info=True)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _int_attr(obj: Any, *names: str) -> int:
    """从 usage 对象上取第一个存在的整数属性。

    不同 SDK 版本/ provider 的字段名不一样（input_tokens / prompt_tokens），
    逐个试，取不到就当 0——统计少算一点，也比整个 run 因为 AttributeError
    崩掉好。
    """
    for n in names:
        v = getattr(obj, n, None)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    return 0


def max_output_per_call() -> int:
    """单次调用输出硬顶。

    ``CTF_MAX_OUTPUT_PER_CALL`` 为正整数时覆盖默认值；非法值或非正值回落到
    默认值。非正值不被解释成「关闭」——这个守卫一旦可被一个拼错的环境变量
    关掉，就会在真正失控时静默失效。
    """
    raw = os.environ.get(_CAP_ENV, "").strip()
    if raw:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return DEFAULT_MAX_OUTPUT_PER_CALL


def trip_info() -> dict[str, Any] | None:
    """返回第一次触顶的诊断（无触顶时为 ``None``）。"""
    with _lock:
        return dict(_trip) if _trip is not None else None


def raise_if_tripped() -> None:
    """若本进程已触顶，抛出与 hook 相同类型的异常。

    并行竞速里触顶的可能是子 agent：异常只结束它的 task，root 可能被
    ``request_stop`` 正常唤醒并返回。``_run_agent`` 在 run 结束后调用本函数，
    把「子 agent 触顶」同样落成 ``stop_reason="output_budget"``。
    """
    info = trip_info()
    if info is not None:
        raise _exceeded_error(info)


def begin_run() -> None:
    """Clear per-run stop state without touching the cumulative counters.

    Production is one challenge per process, but tests and embedded callers
    execute ``main`` more than once in the same interpreter.  A trip from the
    previous run must not refuse the next run's first paid call.  Cumulative
    token counters stay process-wide, matching the module's existing contract.
    """
    global _trip, _inflight_since
    with _lock:
        _trip = None
        _inflight_since = None


def _agent_label(context: Any, agent: Any) -> str:
    ctx = getattr(context, "context", None)
    if isinstance(ctx, dict):
        agent_id = ctx.get("agent_id")
        if isinstance(agent_id, str) and agent_id:
            return agent_id
    name = getattr(agent, "name", None)
    return name if isinstance(name, str) and name else "unknown"


def _exceeded_error(info: dict[str, Any]) -> OutputBudgetExceeded:
    return OutputBudgetExceeded(
        f"single-call output {int(info['output_tokens'])} > cap {int(info['cap'])} "
        f"(call {int(info.get('call', 0))}, cumulative output "
        f"{int(info.get('cumulative_output_tokens', 0))})",
        output_tokens=int(info["output_tokens"]),
        cap=int(info["cap"]),
    )


async def _stop_other_agents(context: Any) -> None:
    """触顶后停掉同一 scan 的其它 agent（parallel 竞速语义）。

    ``context.context`` 里的 coordinator 是 strix 的 AgentCoordinator。
    这里只发 ``request_stop``，不调用 ``trigger_budget_stop``：后者会让其它
    agent 抛 ``BudgetExceededError``，和真正的 token 预算耗尽在结果里同形。
    触顶的那个 agent 由 ``on_llm_end`` 自己抛 ``OutputBudgetExceeded``。
    """
    ctx = getattr(context, "context", None)
    if not isinstance(ctx, dict):
        return
    coordinator = ctx.get("coordinator")
    if coordinator is None:
        return
    own = str(ctx.get("agent_id") or "")
    try:
        others = await coordinator.active_agents_except(own)
    except Exception:  # noqa: BLE001 - 止损失败不能掩盖原始异常
        logger.warning("output budget: listing active agents failed", exc_info=True)
        return
    for info in others or []:
        target = str((info or {}).get("agent_id") or "")
        if not target or target == own:
            continue
        try:
            await coordinator.request_stop(target)
        except Exception:  # noqa: BLE001 - 同上
            logger.warning("output budget: stopping %s failed", target, exc_info=True)


def snapshot() -> dict[str, int]:
    """当前累计值。

    Returns:
        含 ``llm_calls`` / ``input_tokens`` / ``output_tokens`` / ``total_tokens``。
    """
    with _lock:
        return {
            "llm_calls": _calls,
            "input_tokens": _input_tokens,
            "output_tokens": _output_tokens,
            "total_tokens": _total_tokens,
        }


def install() -> None:
    """装上计数器与单次输出止损。幂等。"""
    global _installed, _sink, _originals
    if _installed:
        return

    raw = os.environ.get("CTF_USAGE_PATH", "").strip()
    _sink = Path(raw) if raw else None

    from strix.core import hooks as strix_hooks

    original = strix_hooks.ReportUsageHooks.on_llm_end
    original_start = strix_hooks.ReportUsageHooks.on_llm_start

    async def on_llm_start(self: Any, context: Any, agent: Any, *a: Any, **kw: Any) -> Any:
        global _inflight_since
        # 一个 agent 触顶后，同一进程里任何新发起的调用都拒绝。这样即使
        # coordinator 停机有竞态，也不会有第二个付费调用溜出去。
        with _lock:
            trip = dict(_trip) if _trip is not None else None
        if trip is not None:
            raise _exceeded_error(trip)
        with _lock:
            _inflight_since = time.time()
            _persist_locked()
        return await original_start(self, context, agent, *a, **kw)

    async def on_llm_end(
        self: Any,
        context: Any,
        agent: Any,
        response: Any,
    ) -> None:
        usage = getattr(response, "usage", None)
        global _calls, _input_tokens, _output_tokens, _total_tokens, _inflight_since, _trip
        if usage is not None:
            i = _int_attr(usage, "input_tokens", "prompt_tokens")
            o = _int_attr(usage, "output_tokens", "completion_tokens")
            t = _int_attr(usage, "total_tokens") or (i + o)
            cap = max_output_per_call()
            over: dict[str, Any] | None = None
            with _lock:
                # 先比较本次 o，再累计；触顶也要计数，否则 result.json 会把
                # 真正烧掉的那次输出报少。
                call_no = _calls + 1
                cumulative = _output_tokens + o
                _calls += 1
                _input_tokens += i
                _output_tokens += o
                _total_tokens += t
                _inflight_since = None
                if o > cap:
                    if _trip is None:
                        _trip = {
                            "call": call_no,
                            "output_tokens": o,
                            "cumulative_output_tokens": cumulative,
                            "cap": cap,
                            "agent_id": _agent_label(context, agent),
                            "timestamp": time.time(),
                        }
                    over = {
                        "call": call_no,
                        "output_tokens": o,
                        "cumulative_output_tokens": cumulative,
                        "cap": cap,
                    }
                _persist_locked()
            if over is not None:
                # 先停同 scan 的其它 agent，再抛出。原始 hook 不再调用：
                # run 已确定终止，下一次 on_llm_start 也会被 _trip 拦住。
                await _stop_other_agents(context)
                raise _exceeded_error(over)
        else:
            # 拿不到 usage 也要清掉在途标记，否则看门狗会一直以为请求没回来。
            with _lock:
                _inflight_since = None
                _persist_locked()
        return await original(self, context, agent, response)

    strix_hooks.ReportUsageHooks.on_llm_end = on_llm_end  # type: ignore[method-assign]
    strix_hooks.ReportUsageHooks.on_llm_start = on_llm_start  # type: ignore[method-assign]
    _originals = (original, original_start)
    with _lock:
        _persist_locked()
    _installed = True


def reset_for_tests() -> None:
    """恢复原始 hook 并清空进程级状态。仅测试使用。

    生产进程一题一进程，不需要 reset；测试里同一个解释器会装/卸多次，
    必须把 ``_trip`` 和累计值一起清掉，否则第一个触顶用例会污染后续用例。
    """
    global _installed, _sink, _originals, _calls, _input_tokens
    global _output_tokens, _total_tokens, _inflight_since, _trip
    with _lock:
        originals = _originals
        _originals = None
        _installed = False
        _sink = None
        _calls = 0
        _input_tokens = 0
        _output_tokens = 0
        _total_tokens = 0
        _inflight_since = None
        _trip = None
    if originals is not None:
        try:
            from strix.core import hooks as strix_hooks

            strix_hooks.ReportUsageHooks.on_llm_end = originals[0]  # type: ignore[method-assign]
            strix_hooks.ReportUsageHooks.on_llm_start = originals[1]  # type: ignore[method-assign]
        except Exception:  # noqa: BLE001 - 清理失败不应让测试报错
            logger.debug("failed to restore usage hooks", exc_info=True)
