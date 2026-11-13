"""单次调用超时 + 内侧收尾预留（W2）的回归测试。

三组断言各对应一条实测出来的漏洞：

1. **没有单次调用上限**：提示挂在「工具返回之后」，模型卡在 ``sleep 180`` /
   ``yield_time_ms=120000~180000`` 里，软截止提示永远送不出去（7 条被外层
   SIGKILL 的 run 里有 6 条日志没有任何 ``[deadline]`` 行）。
2. **超时要能真的截断**，而且截断本身不是终点——它要把 ``[SOFT DEADLINE]``
   一起投递出去，否则模型只看到一句「预算没了」，不知道该收敛。``CancelledError``
   必须继续上抛：硬截止取消整条 run 时吞掉它就再也杀不掉。
3. **内外层同一个预算**：harness 用同一个秒数 ``killpg(SIGKILL)``，内层等到
   同一刻再动，``main()`` 的 finally 跑不完、``result.json`` 写不出来（rc=-15）。
   内侧必须提前 ``DEADLINE_HEADROOM_SECONDS`` 秒收尾。
"""

from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.deadline_guard import DeadlineGuard  # noqa: E402


def _guard(*, wall: float = 600.0, soft: float = 450.0) -> DeadlineGuard:
    return DeadlineGuard(wall=wall, soft=soft, turns=30)


# --------------------------------------------------------------- 1. 边界值
@pytest.mark.parametrize(
    ("remaining", "expected"),
    [
        # 剩余预算充裕 → 命中 cap，裁掉「一次调用吃掉几分钟」的长尾。
        (1000.0, 120.0),
        # 只剩 60s → cap 不再生效，减去 40s 收尾预留后剩 20s。
        (60.0, 20.0),
        # 剩 30s：20 - 40 为负 → 回落到 floor，而不是 0 / 负数。
        (30.0, 5.0),
        # 剩 41s：41 - 40 = 1，低于 floor。
        (41.0, 5.0),
    ],
)
def test_tool_timeout_boundaries(remaining: float, expected: float) -> None:
    guard = _guard(wall=1000.0)
    # 往过去挪 start，等价于「已经花了 1000 - remaining 秒」。
    guard._start -= 1000.0 - remaining

    assert guard.tool_timeout() == pytest.approx(expected, abs=0.5)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # 覆盖生效。
        ("7", 7.0),
        # 低于 floor 的 cap 被 floor 抬回来：floor 的职责是「别让一次调用
        # 变成 0」，它优先于 cap，否则把 cap 调小就等于砍断所有工具。
        ("0.5", 5.0),
    ],
)
def test_tool_timeout_cap_is_configurable(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: float
) -> None:
    guard = _guard(wall=10000.0)
    monkeypatch.setenv("CTF_MAX_TOOL_SECONDS", raw)

    assert guard.tool_timeout() == pytest.approx(expected, abs=0.01)


@pytest.mark.parametrize("raw", ["", "abc", "0", "-3", "nan", "inf"])
def test_invalid_cap_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    """配置写错不能让每次调用都变成 0 秒（等于砍断所有工具）。"""
    guard = _guard(wall=10000.0)
    monkeypatch.setenv("CTF_MAX_TOOL_SECONDS", raw)

    assert guard.tool_timeout() == pytest.approx(120.0, abs=0.5)


# --------------------------------------------------- 2. wait_for 真的截断
def _mounted_factory(monkeypatch: pytest.MonkeyPatch):
    """把 deadline.install() 装到一个假的 factory 上。

    ``install()`` 要求挂载钩子先跑过（否则直接 raise），这里直接把
    ``_ctf_mounted`` 置真、``_with_bounded_result`` 换成恒等，避免依赖
    guard_mount 的安装顺序。
    """
    pytest.importorskip("strix")
    pytest.importorskip("agents")

    from strix.agents import factory

    monkeypatch.setattr(factory, "_with_bounded_result", lambda tool: tool)
    monkeypatch.setattr(factory, "_ctf_mounted", True, raising=False)
    return factory


def test_slow_call_is_cut_and_soft_hint_is_delivered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agents.tool import FunctionTool

    import ctf_strix.deadline_guard as deadline_mod

    factory = _mounted_factory(monkeypatch)

    async def inner(ctx, raw):  # noqa: ANN001, ARG001
        await asyncio.sleep(10)
        return "REAL OUTPUT"

    tool = FunctionTool(
        name="exec_command",
        description="slow probe",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=inner,
    )

    guard = _guard(wall=600.0, soft=1.0)
    # 已过软截止：observe() 那一次必须把 [SOFT DEADLINE] 一并送出。
    guard._start -= 10
    monkeypatch.setattr(guard, "tool_timeout", lambda: 0.2)

    deadline_mod.install(guard)
    wrapped = factory._with_bounded_result(tool)

    started = time.monotonic()
    out = asyncio.run(wrapped.on_invoke_tool(None, "{}"))
    elapsed = time.monotonic() - started

    assert "[DEADLINE]" in out, "超时分支必须给模型一条明确的终止信号"
    assert "[SOFT DEADLINE]" in out, "超时也必须把收敛提示投递出去"
    assert elapsed < 2.0, "必须真被 wait_for 截断，而不是等满 10s"


def test_timeout_does_not_swallow_cancelled_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """硬截止取消整条 run 时，CancelledError 不能被当成超时吞掉。"""
    from agents.tool import FunctionTool

    import ctf_strix.deadline_guard as deadline_mod

    factory = _mounted_factory(monkeypatch)

    async def inner(ctx, raw):  # noqa: ANN001, ARG001
        raise asyncio.CancelledError

    tool = FunctionTool(
        name="exec_command",
        description="cancelled",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=inner,
    )

    guard = _guard()
    guard.tool_timeout = lambda: 5.0  # type: ignore[method-assign]
    deadline_mod.install(guard)
    wrapped = factory._with_bounded_result(tool)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(wrapped.on_invoke_tool(None, "{}"))


# ------------------------------------------------------- 3. headroom 接线
def test_headroom_constant_and_budget_math() -> None:
    from ctf_strix import agent

    assert agent.DEADLINE_HEADROOM_SECONDS == 45.0
    assert agent._budget_for_stop(1000) == 955
    assert agent._budget_for_stop(900) == 855
    # 预算小于预留时至少留 1s，不能算出 0 / 负数把 watchdog 反向关掉。
    assert agent._budget_for_stop(45) == 1
    assert agent._budget_for_stop(40) == 1
    # ``<=0`` 是「关闭墙钟」的约定值，必须原样直通——折算成 1 会装一个
    # 1 秒自杀的 watchdog，把「没有时限」变成「1 秒后死」。
    assert agent._budget_for_stop(0) == 0
    assert agent._budget_for_stop(-5) == -5


def test_main_wires_budget_for_stop_into_both_gates() -> None:
    """接线本身：纯函数对了但 main() 不调用它，等于没改。"""
    import inspect

    from ctf_strix import agent

    src = inspect.getsource(agent.main)

    assert "_budget_for_stop(wall_budget)" in src
    assert re.search(
        r"set_wall_deadline\(_llm_wall_deadline\(budget_for_stop\)\)", src
    ), "LLM 软截止必须用扣掉 headroom 的预算"
    assert re.search(
        r"_install_hard_deadline\(\s*budget_for_stop\b", src
    ), "硬截止同样必须用扣掉 headroom 的预算"