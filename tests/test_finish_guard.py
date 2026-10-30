"""收工守卫的回归测试。

三条都对应真实的 0 分路径：

1. 只认大写 ``FLAG{`` → ``ctfy{...}`` 这类答案被连拒三次，白烧轮次；
2. engagement 题没有 flag → 每一次正常收工都被拒，agent 永远退不出去；
3. checker 题同理，而且它的交付物是副作用，不是 flag。
"""

from __future__ import annotations

from ctf_strix.finish_guard import FinishGuard, _MAX_REFUSALS


def test_flag_forms_are_all_recognised() -> None:
    """平台可能用任意一种前缀，守卫只认一种就会误拦。"""
    for flag in ("FLAG{abc123def}", "flag{abc123}", "ctfy{deadbeef}", "CTF{x_y-z}"):
        guard = FinishGuard()
        assert guard.check(f'{{"summary": "got {flag}"}}') is None, flag
        assert guard.allowed == 1
        assert guard.refusals == 0


def test_placeholder_is_not_a_flag() -> None:
    """``FLAG{...}`` 这种模板占位符不能当成已解出。"""
    guard = FinishGuard()
    refusal = guard.check('{"summary": "the answer is FLAG{...}"}')
    assert refusal is not None
    assert refusal["success"] is False


def test_refusal_budget_is_bounded() -> None:
    """解不出题时必须能干净收尾，不能把预算全耗在撞墙上。"""
    guard = FinishGuard()
    for _ in range(_MAX_REFUSALS):
        assert guard.check("nothing here") is not None
    assert guard.check("nothing here") is None
    assert guard.allowed == 1


def test_engagement_and_checker_never_require_flag() -> None:
    """engagement / checker 没有 flag；守卫必须让路。"""
    for _ in range(3):
        guard = FinishGuard(require_flag=False)
        assert guard.check("report saved, 5 findings") is None
        assert guard.refusals == 0
