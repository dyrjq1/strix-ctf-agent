"""单题预算的硬上限（2026-11-19 用户拍板：60 轮 / 900 秒）。

这是**上限**，不是基准：每一档难度仍按自己的基准给预算（batch_eval 的
tiers、agent 的 ``_WALL_TIERS``、compete 的单次时间盒），任何路径算出来
的值超过上限就夹回来。

为什么单独一个模块：三个入口（``ctf_strix.agent``、``scripts/batch_eval``、
``scripts/compete``）和 ``scripts/run_strix_ctf`` 都要读它。放进 ``agent``
会让两个调度脚本为了两个整数拉起整个运行时（agent 模块连带 import strix
与 SDK）；放在这里 import 成本是零。

依据（2026-11-19 测试赛实测）：
* 14 次尝试全部 ``wallclock`` 收场，``turn_capped`` 一次都没出现——轮次
  从来不是当时的约束，460s 里 deepseek 只能发出 ~27 次调用，所以把轮次
  上限放到 60 不会自己生效，得配合 900s 墙钟；
* 用户定调：既然解不解出不重要、但要保证跑得动，就给足一整个长预算，
  而不是在 450/690s 处切一刀。
"""

from __future__ import annotations

#: 一题（跨所有 attempt 合计）的轮次上限。
MAX_TURNS: int = 60

#: 一题（跨所有 attempt 合计）的墙钟上限，秒。
MAX_WALLCLOCK_S: int = 900


def clamp_turns(value: object) -> int:
    """把任意轮次值夹进 ``[1, MAX_TURNS]``；不可解析时返回上限。"""
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return MAX_TURNS
    return max(1, min(number, MAX_TURNS))


def clamp_wallclock(value: object) -> int:
    """把任意墙钟值夹进 ``[0, MAX_WALLCLOCK_S]``；不可解析时返回上限。

    0 在调用方语义里是「关闭墙钟」，保持 0 原样返回——把它夹成 900 会让
    「关掉」变成「15 分钟后自杀」。
    """
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return MAX_WALLCLOCK_S
    if number <= 0:
        return 0
    return min(number, MAX_WALLCLOCK_S)