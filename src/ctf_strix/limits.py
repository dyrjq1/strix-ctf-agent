"""单题预算的硬上限（2026-11-20 初选赛：轮次不设限 / 墙钟 1800 秒）。

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
#:
#: 2026-11-20 初选赛中用户定：**取消轮次上限**，只留墙钟。轮次不是当时的
#: 真实约束（11-19 测试赛 14 次尝试全部死于墙钟、``turn_capped`` 零次），
#: 卡住的是方向选择。这里留一个远大于任何实际用量的数当哨兵——``clamp_turns``
#: 的语义是``[1, MAX_TURNS]``，没有“无上限”表示法，所以用一个发不出去的
#: 大数代替，真正的界由 ``MAX_WALLCLOCK_S`` 负责。
MAX_TURNS: int = 1_000_000

#: 一题（跨所有 attempt 合计）的墙钟上限，秒。
#:
#: 2026-11-20 初选赛内的两次调整：
#: * 15:25 用户定为 5400s（1.5h，原 900s）；
#: * 17:06 改回 **1800s（30 分钟）**——实测 ``compete.py`` 是按波派单、三条
#:   车道等齐才开下一波，5400s 时两条先收车的车道空转 20–40 分钟，到收工
#:   只剩约两波（6 次机会）；1800s 时同样窗口能跑 5–6 波（15–18 次）。历史
#:   成功题 p50 只有 60–70 秒，30 分钟对解得动的题足够。
#:
#: 难度放大（medium ×1.5、hard ×2.3）先乘再被这里夹住，所以三档实际拿到的
#: 都是 1800s。
MAX_WALLCLOCK_S: int = 1800


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