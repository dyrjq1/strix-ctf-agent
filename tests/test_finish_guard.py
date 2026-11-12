"""收工守卫的回归测试。

三条都对应真实的 0 分路径：

1. 只认大写 ``FLAG{`` → ``ctfy{...}`` 这类答案被连拒三次，白烧轮次；
2. engagement 题没有 flag → 每一次正常收工都被拒，agent 永远退不出去；
3. checker 题同理，而且它的交付物是副作用，不是 flag。
"""

from __future__ import annotations

import re

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


def test_x_placeholder_is_not_a_flag() -> None:
    """``FLAG{xxxx}`` 来自镜像源码注释，2026-11-06 v6 冒烟据此误判 solved。"""
    guard = FinishGuard()
    refusal = guard.check('{"summary": "the answer is FLAG{xxxx}"}')
    assert refusal is not None
    assert refusal["success"] is False


def test_refusal_budget_is_bounded() -> None:
    """解不出题时必须能干净收尾，不能把预算全耗在撞墙上。"""
    guard = FinishGuard()
    for _ in range(_MAX_REFUSALS):
        assert guard.check("nothing here") is not None
    assert guard.check("nothing here") is None
    assert guard.allowed == 1


def test_second_refusal_tells_the_model_to_change_mechanism() -> None:
    """连拒两次仍是同一段文案时，模型会把同一份白卷原样再交一次。

    第 2 次起必须要求换向，而且这段文案得停在机制级：出现 URL、IP、路径或
    flag 字面量，通用守卫就退化成只对某一道题有效的提示。
    """
    guard = FinishGuard()
    first = guard.check("nothing here")
    second = guard.check("nothing here")
    assert first is not None and second is not None

    head = str(first["error"])
    tail = str(second["error"])[len(head):]
    assert str(second["error"]).startswith(head)
    assert tail, "第 2 次拒绝必须比第 1 次多说换向指令"
    assert "mechanism" in tail.lower()
    assert "finish_scan" in tail
    # 题面特定串：URL、flag 字面量、绝对路径片段。
    for leak in ("http://", "https://", "FLAG{", "ctf{", "/flag"):
        assert leak not in tail
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", tail)


def test_first_refusal_stays_the_plain_instruction() -> None:
    """第 1 次不该一上来就要求换向：它还没试过通用建议里的动作。"""
    guard = FinishGuard()
    first = guard.check("nothing here")

    assert first is not None
    assert "mechanism" not in str(first["error"]).lower()


def test_fourth_call_is_allowed_and_marked_as_giving_up() -> None:
    """拒满后放行等于放弃，不是通过；结果必须能被事后区分出来。"""
    guard = FinishGuard()
    for _ in range(_MAX_REFUSALS):
        assert guard.check("nothing here") is not None
    assert guard.gave_up is False

    assert guard.check("nothing here") is None
    assert guard.allowed == 1
    assert guard.gave_up is True


def test_stats_tracks_refusals_allowed_and_give_up() -> None:
    guard = FinishGuard()
    assert guard.stats() == {"refusals": 0, "allowed": 0, "gave_up": 0}

    guard.check("nothing here")
    guard.check("nothing here")
    assert guard.stats() == {"refusals": 2, "allowed": 0, "gave_up": 0}

    guard.check("nothing here")
    assert guard.check("nothing here") is None
    guard.check('{"summary": "got FLAG{abc123}"}')
    assert guard.stats() == {"refusals": 3, "allowed": 2, "gave_up": 1}


def test_engagement_and_checker_never_require_flag() -> None:
    """engagement / checker 没有 flag；守卫必须让路。"""
    for _ in range(3):
        guard = FinishGuard(require_flag=False)
        assert guard.check("report saved, 5 findings") is None
        assert guard.refusals == 0
