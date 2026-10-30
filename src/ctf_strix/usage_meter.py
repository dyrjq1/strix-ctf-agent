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

#: 进程级累计。评测是"一题一进程"，所以不需要按 run 区分。
_lock = threading.Lock()
_calls: int = 0
_input_tokens: int = 0
_output_tokens: int = 0
_total_tokens: int = 0
_installed = False
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
    """装上计数器。幂等。"""
    global _installed, _sink
    if _installed:
        return

    raw = os.environ.get("CTF_USAGE_PATH", "").strip()
    _sink = Path(raw) if raw else None

    from strix.core import hooks as strix_hooks

    original = strix_hooks.ReportUsageHooks.on_llm_end
    original_start = strix_hooks.ReportUsageHooks.on_llm_start

    async def on_llm_start(self: Any, context: Any, agent: Any, *a: Any, **kw: Any) -> Any:
        global _inflight_since
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
        global _calls, _input_tokens, _output_tokens, _total_tokens, _inflight_since
        if usage is not None:
            i = _int_attr(usage, "input_tokens", "prompt_tokens")
            o = _int_attr(usage, "output_tokens", "completion_tokens")
            t = _int_attr(usage, "total_tokens") or (i + o)
            with _lock:
                _calls += 1
                _input_tokens += i
                _output_tokens += o
                _total_tokens += t
                _inflight_since = None
                _persist_locked()
        else:
            # 拿不到 usage 也要清掉在途标记，否则看门狗会一直以为请求没回来。
            with _lock:
                _inflight_since = None
                _persist_locked()
        return await original(self, context, agent, response)

    strix_hooks.ReportUsageHooks.on_llm_end = on_llm_end  # type: ignore[method-assign]
    strix_hooks.ReportUsageHooks.on_llm_start = on_llm_start  # type: ignore[method-assign]
    with _lock:
        _persist_locked()
    _installed = True
