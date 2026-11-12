"""turn 预算倒计时守卫（turn_budget.TurnBudgetGuard）。

两个一次性触发点：75% 收敛提醒、剩最后 N 轮交卷强指令；
新 attempt 复位；无预算静默。
"""

from __future__ import annotations

from ctf_strix.deadline_guard import _ANSWER_RE
from ctf_strix.turn_budget import TurnBudgetGuard, reset_current


def test_answer_re_ignores_api_keys():
    """``sk-``+32hex 的供应方 key 不是答案；裸 32hex 与 FLAG{} 仍是。"""
    assert not _ANSWER_RE.search("key=sk-d41d8e0410c84ddcada76395397f90dd")
    assert _ANSWER_RE.search("d41d8e0410c84ddcada76395397f90dd")
    assert _ANSWER_RE.search("FLAG{8000c9960d30949816202811fc1a3678}")


def _drain(guard: TurnBudgetGuard, n: int) -> list[str | None]:
    return [guard.observe() for _ in range(n)]


def test_warn_then_final_then_silent():
    guard = TurnBudgetGuard(warn_frac=0.75, final_reserve=2)
    guard.reset(12)
    # 1-8 次调用静默；第 9 次（ceil(9)=9）触发提醒。
    hints = _drain(guard, 8)
    assert all(h is None for h in hints)
    warn = guard.observe()
    assert warn is not None and "9 of 12" in warn and "[TURN BUDGET]" in warn
    # 第 10 次（=12-2）触发一次交卷强指令，之后静默。
    final = guard.observe()
    assert final is not None and "2 tool calls left" in final
    assert "TURN BUDGET FINAL" in final
    assert guard.observe() is None
    assert guard.observe() is None


def test_reset_clears_flags_and_rebudgets():
    guard = TurnBudgetGuard(warn_frac=0.75, final_reserve=2)
    guard.reset(4)
    # 第 3 次（ceil(3)=3）warn，第 4 次还没到 final_at? final_at=max(4-2,3)=2
    # → 第 2 次就直接 final。这里验证复位后计数与标志都归零。
    _drain(guard, 4)
    guard.reset(20)
    hints = _drain(guard, 14)
    assert all(h is None for h in hints)
    assert guard.observe() is not None  # 第 15 次 = ceil(15)=15 warn


def test_zero_budget_silent():
    guard = TurnBudgetGuard()
    guard.reset(0)
    assert all(h is None for h in _drain(guard, 50))


def test_reset_current_noop_without_install():
    # 未 install() 时必须是 no-op（agent.py 的 attempt 循环无条件调用）。
    reset_current(10)


def test_final_reserve_floor():
    # 预算极小时 final_at=max(budget-reserve, warn_at) 不得倒挂：
    # budget=4、reserve=5 → warn_at=3、final_at=3，第 3 次直接触发 final。
    guard = TurnBudgetGuard(warn_frac=0.75, final_reserve=5)
    guard.reset(4)
    assert guard.observe() is None
    assert guard.observe() is None
    third = guard.observe()
    assert third is not None and "TURN BUDGET FINAL" in third
