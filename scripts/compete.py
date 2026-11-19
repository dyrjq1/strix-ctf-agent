#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compete.py — 比赛日长驻调度器：agent 本身算一个实例，自行浏览选题。

架构（2026-11-13 用户定调，平台实测 API 形状见 docstring 末尾）：

1. **长驻单实例**：VPS 上跑本进程，它就是平台视角的参赛 agent。循环 =
   刷题表 → 按策略选题 → 派单 → 收结果 → 更新全局账本 → 再刷。
2. **题目间上下文隔离**：每题派一个全新的 ``batch_eval.py`` 子进程
   （agent 上下文从零开始），上一题的对话**绝不**带进下一题。
3. **全局记忆外置、与题内上下文隔开**：全局账本只落盘在
   ``--state-dir``（state.json 简账 + digest.md 一行一题 + runs/<qid>/
   详报）。题内 agent 上下文零注入；要看跨题记忆只有两级接口——
   digest 的简略描述，或 runs/ 下单题详报（由人/调度器读）。
4. **并发**：``--lanes``（默认 2 = 配额 3 留 1 个余量）个 batch_eval
   子进程同时各占一个题目实例。run3 实测：3 车道与配额相等时零余量，
   任何「停止中/重试中」实例都会挤掉别人的槽位（SAMPLE-001 连撞 5 次
   429），墙钟求和几乎等于经过时间（并发度≈1）。⚠️ 需要 VPN/隧道的
   TCP 题并行车道会共享子网路由互踩（vpn.py 单 wg 接口）；遇到路由型
   失败先降 ``--lanes 1``。每条车道可用 ``--lane-config`` 绑定**不同厂商**
   的模型与凭据（一家端点挂掉不连坐）。
5. **体量档位**：题池规模赛前未知——每轮刷题表后按未关闭题数自动判
   small/medium/large，只改调度参数（每题重试预算、deferred 复活敏感度），
   不动单次尝试的时间盒。分批放题时档位自动换。

选题策略（纯函数 ``rank_queue``，全部可单测）：

- 已解出 / 已关闭 / qa-only 的题不进队列；
- 优先级按平台动态积分的**剩余价值**：``solves_count`` 越少分越高
  （0 解出拿满，≥``_DECAY_SOLVERS`` 队解出归零）。难度只做同档 tie-break，
  不再单独决定先后——动态积分下"难度高但没人解出"正是最值钱的题；
- web 是实测强项（解出率 83%），类别加权优先；
- 连续失败 ``max_failures``（默认 2）次 → deferred（放弃）；
  尾巴题（≤``_TAIL_MAX_SOLVES`` 队解出）例外，用 ``_TAIL_RETRY_BUDGET``；
- deferred 题的 ``solves_count`` 较放弃时上涨 ``rerun_solves_jump``
  （默认 3）→ 判定为「其实可解」重新入队（后期重跑信号）；
- 门控题（questions[].requires）：前置问题已解的优先（解一个解锁
  一串）。

用法（VPS，串行/并行由 --lanes 控制）::

    export PF_TOKEN=... LLM_API_KEY=... LLM_API_BASE=... \
           STRIX_LLM=openai/... STRIX_RUNTIME_BACKEND=local \
           LITELLM_LOCAL_MODEL_COST_MAP=True \
           PYTHONPATH=$PWD/src:$PWD/vendor/src
    python scripts/compete.py --token "$PF_TOKEN" \
        --competition <cid> --state-dir ~/compete-state --lanes 3 \
        --turns 25 --wallclock 300 --until "2026-11-15T20:00+08:00"

    # 多厂商车道（可选）：--lane-config 一行一车道「名字|LLM_API_BASE|
    # LLM_API_KEY|模型名」（chmod 600，# 注释/空行跳过）。不配则所有车道
    # 共用当前进程的 LLM_* 环境（行为与改动前完全一致）。凭据只进子进程
    # env，不进 argv、不落 state、不打印：
    python scripts/compete.py ... --lanes 3 --lane-config ~/lanes.conf

    # 只看队列不动手：
    python scripts/compete.py ... --dry-run

平台 API（2026-11-13 playground 实测，全部 200）::

    GET /api/v1/competitions/{cid}/challenges
        → {"items": [{id, name, category, difficulty, solves_count,
           launch_count, questions[{id, mode, requires}], closed,
           is_qa_only, ...}], "total", "limit", "offset"}
    GET /api/v1/competitions/{cid}/scoreboard
        → {"items": [{rank, team_name, solved, flags_solved, score,
           attempts, entrant_kind(human|agent), ...}]}

已知边界：batch_eval 实例创建失败仍 exit 0（冒烟 #8）——本脚本以
jsonl 记录为准判成败，不信退出码。harness 侧 verify 预检对 checker
题恒 False（冒烟 #1）会压制补交——镜像内 autosubmit 已修（契约行直
交），harness 补交路径的该缺陷未修，记录在台账。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # 复用 batch_eval 的 Client/常量
    sys.path.insert(0, str(HERE))

import requests  # noqa: E402

import batch_eval  # noqa: E402

#: 单题墙钟硬上限（2026-11-19 用户定：900s）。batch_eval import 时已把
#: ``src`` 前置进 sys.path，所以这里能直接读单一真值。
from ctf_strix.limits import MAX_WALLCLOCK_S as _LIMITS_MAX_WALL_S  # noqa: E402

#: 平台地址。batch_eval.Client 同源，不另起一份。
PLATFORM = batch_eval.PLATFORM if hasattr(batch_eval, "PLATFORM") else "https://ctfy.tsinghua.edu.cn"

def ensure_bundle_tool_env() -> dict[str, str]:
    """把 bundle 部署树里的系统工具挂进本进程 env（非 bundle 布局 = no-op）。

    bootstrap.sh 把 gdb/nmap/rg/sqlmap 解到 ``<DEPLOY>/tools``，repo 在
    ``<DEPLOY>/strix-ctf-agent``，但**从不写 ~/.bashrc**；而车道的子进程只
    继承本进程 env（见 ``spawn`` 里的 ``{**os.environ, ...}``）。于是从裸
    shell 直接起 compete.py 时，干净 VPS 上 agent 的 exec_command 找不到
    这些工具（代价是静默的能力退化，不是报错）。

    库序必须是**宿主目录在前**：bundle 自带 libsystemd 252，若排最前，宿主
    的 ls/bash/curl/tar 会全挂（台账 §4.263）。

    Returns:
        实际改动的 ``{"PATH": ..., "LD_LIBRARY_PATH": ...}`` 子集，空表示没动。
    """
    # HERE = <DEPLOY>/strix-ctf-agent/scripts  →  tools 在 <DEPLOY>/tools
    deploy = HERE.parent.parent
    tools = deploy / "tools"
    if not tools.is_dir():
        return {}
    changed: dict[str, str] = {}

    path_parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    add_bins = [
        str(d)
        for d in (tools / "usr/bin", tools / "usr/sbin")
        if d.is_dir() and str(d) not in path_parts
    ]
    if add_bins:
        os.environ["PATH"] = os.pathsep.join(add_bins + path_parts)
        changed["PATH"] = os.environ["PATH"]

    lib_dirs = [
        d
        for d in (
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            str(tools / "usr/lib/x86_64-linux-gnu"),
            str(tools / "lib/x86_64-linux-gnu"),
        )
        if os.path.isdir(d)
    ]
    cur_libs = [p for p in os.environ.get("LD_LIBRARY_PATH", "").split(os.pathsep) if p]
    merged = lib_dirs + [p for p in cur_libs if p not in lib_dirs]
    if merged and merged != cur_libs:
        os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(merged)
        changed["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]
    return changed


# ---------------------------------------------------------------- 策略纯函数

#: 状态机：active（可跑）/ running / solved / failed / deferred（放弃，
#: 等 solves_count 跳变或收尾 sweep）。
ACTIVE, RUNNING, SOLVED, FAILED, DEFERRED = "active", "running", "solved", "failed", "deferred"
#: 子进程在写结果行之前就退了（派单闸门拒绝 / 环境不备）。**不是题目失败**：
#: 不计 fails、不 defer，稍后重派。与 skipped 的区别是连一行结果都没有。
INFRA = "infra"

#: 平台动态积分的参数（competition 对象）：``dynamic_points`` / ``exponential``
#: / ``decay_solvers=30`` / ``minimum_fraction=0.1``。分值随解题队数**单调下降**，
#: 地板是满分的 10%。曲线公式平台没公开，所以这里不复刻它，只取它保证的那条
#: 单调性：**他队解得越少，这道题还剩的分越多**。
#:
#: 旧表是 easy 300 / medium 200 / hard 100，且零解出再倒扣 100——那在"每题固定
#: 分值"的赛制里成立，在动态积分下正好反了。入围赛实测：2 队解出的 crypto 题值
#: 970 分，占榜首总分的 68.7%；200+ 队解出的 misc 题只剩地板价 100。按旧表排，
#: 我们最先放弃的恰好是唯一值钱的那道。
_DECAY_SOLVERS = 30
_VALUE_WEIGHT = 300
#: 同价值档位内的 tie-break：易题先打（更快出分，且早解在动态积分下有优势）。
#: 只做 tie-break，不参与主排序——权重刻意比 _VALUE_WEIGHT 小一个数量级。
_EASE_TIEBREAK = {"easy": 20, "medium": 10, "hard": 0}
#: 类别偏好：**暂时为空**——"web 是强项"这条先验站不住，见下。
#:
#: 原值 ``{"web": 60}`` 的出处是 CTFARENA 练习套 48 测 40 解（83.3%）。但那是
#: **练习套**的数字：全 web、题目高度同构、每题跑过多次（有重试）、预算
#: 600–1800s。同一批算到"单次尝试"口径只有 62.9%（100/159，docs/47 F5）。
#: 全库 64/366=17.5% 是覆盖面分母，不是解出率。真正的比赛条件样本只有
#: 入围赛那一道 web（cve_stage，98/520 队解出），我们 4 个 checkpoint 全拿到
#: ——1/1，样本量 1，既不能证强也不能证弱。
#: 结论：类别权重必须由"比赛条件下的实测"挣，没数据就平权。
_CATEGORY_WEIGHT: dict[str, int] = {}
#: 每次失败扣分；连续失败 max_failures 次 → deferred。
_FAIL_PENALTY = 90
#: 尾巴题（他队解出 ≤ 这个数）的独立重试预算。
#:
#: 依据：独立重试是弱模型上证据最强的杠杆——多一次**新上下文**尝试在 AutoPenBench
#: 上把单题 27.3% 提到 45.5%（NDSS LASTx 2026, lastx2026-42），InterCode-CTF
#: @1 89% → @5 95%（arXiv 2412.02776）；CTF 曲线在 k=5 后收益递减。取 5，不是无限。
#:
#: 旧策略下这类题连第二次都拿不到：``max_failures=2`` 直接 deferred，而复活要求
#: ``solves_count`` 上涨 3——在 0–2 队解出的题上，整场比赛可能都等不到这个跳变。
#: 结果是最值钱的题在第二次失败后就被永久放弃。
_TAIL_MAX_SOLVES = 5
_TAIL_RETRY_BUDGET = 5
#: 门控题：前置问题全部被我们解过 → 优先（解一个解锁一串）。
_GATING_BONUS = 40
#: QA 题库题（is_qa_only）：不占实例配额、通常几分钟出结果，给一点优先。
_QA_BONUS = 30
#: 「他队已解出」= 可解性已被证明。2026-11-19 用户定调：我方 agent 能力有限，
#: 优先尝试别人能解出来的题。当日测试赛实证：9 次尝试全部落在 0 解出的题上，
#: 全部 wallclock 收场、0 解出；而 ``_VALUE_WEIGHT`` 的价值优先把 0 解出题排第一。
#:
#: 量级刻意做成**分档隔离**而不是微调：460 > 未解出题的理论最高分
#: （300 价值 + 20 easy + 60 web + 30 qa + 40 门控 = 450），所以任何「他队已解」
#: 的题都排在任何未解出的题前面。组内仍按剩余价值排序（解出越少越前），
#: ``_FAIL_PENALTY`` 也照旧——连败是我们自己的证据，可以把它降回未解出题之后。
_PROVEN_BONUS = 460

#: 难度对墙钟的放大倍数（与 batch_eval 的 tiers 同源）。派单前用真实
#: 上限判会话窗口够不够，而不是拿基准 wallclock 猜。2026-11-19 起上限
#: 由 ``ctf_strix.limits.MAX_WALLCLOCK_S`` 统一夹住（900s），放大倍数不会
#: 再把线推过它。
_WALL_TIER = {"easy": 1.0, "medium": 1.5, "hard": 2.3}

#: 单次尝试的时间盒基准（easy 档；medium ×1.5、hard ×2.3 由 ``_WALL_TIER``
#: 与 batch_eval 各自的 tiers 施加）。**这不是"调小预算换分数"，是把一次尝试
#: 的长度对齐到实测的边际收益拐点**——依据是 389 条真值 run（207 解出）的离线
#: 重放，见 docs/47 §2.3.2：
#:
#: - 解出的尝试里 **73.5%（86/117）在 300s 内就结束了**；
#: - 按分档盒子（300/450/690）截断，丢掉 **21/207 = 10.1%** 的解出，腾出
#:   **31.6%** 的车道时间 = **170 次额外尝试**；只要其中 **12.3%** 解出就不亏；
#: - 同题失败一次后再试一次，实测解出率 **29.2%（42/144）**；未解出且 >300s
#:   的那 125 次尝试里，**41.6%** 的题后来被同题另一次尝试解出。
#:
#: 12.3% 的盈亏平衡线 vs 29.2% 的实测重试率，是这个数字唯一的依据。**硬上限仍然
#: 是上限**：这改的是一次尝试的长度，不是允许它无限跑。
#:
#: 2026-11-19 用户改定：300 → 900。当天 14 次尝试全部在 450/690s 的墙钟上死掉、
#: ``turn_capped`` 一次都没有——切得早的不是模型，是钟。同时轮次上限放到 60
#: （``ctf_strix.limits``），所以时间盒的基准与上限现在都是 900s。
_ATTEMPT_BOX_S = 900

#: 重派时的入口方向表。**换的是入口，不是预算**：第二次尝试的开销与第一次
#: 完全一样，改的只有「从哪个机制类别开始」。依据是重试的实测收益集中在
#: 均值回归之外的独立初始化——同题失败后再试一次解出率 29.2%（42/144），而
#: 同一初始化的重放失败高度相关（同模型、同提示、同轨迹）。按顺序轮转而不是
#: 让模型自选，是因为「自选方向」在零证据时就是它上一次的选择。
#:
#: 每条只描述机制类别，不出现题号、路径、参数名或任何一种题的具体事实
#: （命名测试）；新增条目同样受这条约束。
_ENTRY_DIRECTIONS: tuple[tuple[str, str], ...] = (
    (
        "surface",
        "先把攻击面摊平：目录/路由/参数/方法逐个枚举，列全可达端点再挑点",
    ),
    (
        "auth",
        "先走认证与授权：注册/登录/会话/cookie/令牌/角色边界，按状态机顺序测",
    ),
    (
        "client",
        "先从客户端看：页面里的 JS 与 sourcemap、前端校验、隐藏字段，"
        "以及浏览器渲染后的 DOM（browser_render）",
    ),
    (
        "input",
        "先从输入处理看：参数类型、边界、编码与解析差异、模板与注入点，"
        "一次只改一个变量",
    ),
    (
        "flow",
        "先看多步与异步流程：上传、导入、回调/webhook、任务队列、轮询接口",
    ),
    (
        "infra",
        "先看配置与基础设施：默认凭据、备份/调试/管理端点、缓存、代理与头处理",
    ),
    (
        "files",
        "先看文件与路径：读取、包含、穿越、软链、归档解包与临时目录",
    ),
)


#: 消融开关，形状与 ``CTF_BROWSER`` / ``CTF_CARDS_OFF`` 一致：只有
#: ``0/false/no/off`` 关掉，没有正向覆盖。关掉时 ``entry_direction`` 的结果被
#: 丢弃，重派退回改动前的行为（只带失败路径），用于 A/B 的另一臂。
DIRECTIONS_ENV = "CTF_REDISPATCH"


def directions_enabled() -> bool:
    """换向是否生效（A/B 的一臂靠它关掉）。"""
    raw = os.environ.get(DIRECTIONS_ENV, "").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def entry_direction(attempt: int) -> tuple[str, str] | None:
    """第 ``attempt`` 次尝试（1 起）该走的入口方向；首跑不注入。

    Args:
        attempt: 派单序号，1 = 首次尝试。

    Returns:
        ``(label, text)``；``attempt <= 1`` 时返回 ``None``——首跑加任何
        方向提示都等于给所有题统一加了偏置，那是一次没有对照的改动。
    """
    if attempt <= 1:
        return None
    return _ENTRY_DIRECTIONS[(attempt - 2) % len(_ENTRY_DIRECTIONS)]


# ---------------------------------------------------------------- 题池体量档位

#: 题池体量分档边界（按**未关闭题数** N 判定，每轮刷题表后重判——分批放题
#: 时档位会自己跟上）。战术选择由代码在开赛时自动完成：人工赛中选档 =
#: 人工注入指令（官方 Q&A Q6/Q69「赛前部署好、中途不能调试修改」）。
#:
#: 物理依据只有一条：总车道时间 ≈ 比赛时长 × lanes（10h×3 ≈ 108000
#: 车道秒）。按平均尝试 ~450s、每题 2–3 次尝试算，N 要到 ~100 才真正
#: 绑死，所以 large 的门槛放在 61：早于这个数收紧重试就是白丢 29.2% 的
#: 同题重试解出率。分档只改**调度参数**（每题给几次机会、deferred 多
#: 敏感），**不动单次尝试的时间盒**（_ATTEMPT_BOX_S 是 docs/47 §2.3.2
#: 实测拐点，动它属于"单独调预算"）。尾巴题（≤_TAIL_MAX_SOLVES 队解出）
#: 不受 max_failures 影响，由 _TAIL_RETRY_BUDGET 独立兜底，三档共用
#: ——large 档砍的是**已被广泛解出的地板价题**的深度，零解题（满值）
#: 的预算一根手指都不动。
_REGIME_BOUNDS = {"small": 12, "medium": 60}

#: 三档预设。medium = 实测默认（max_failures 2 / jump 3，docs/47 §2.3.2
#: 拐点 + 29.2% 同题重试率）；small 放大覆盖（每题分值份额大，多一次全新
#: 上下文重试的实测收益 29.2% 高于让出的车道时间）；large 收紧吞吐
#: （早 defer 早换题，把车道时间让给还没碰过的题）。
_REGIME_PRESETS: dict[str, dict[str, int]] = {
    "small": {"max_failures": 4, "rerun_solves_jump": 2},
    "medium": {"max_failures": 2, "rerun_solves_jump": 3},
    "large": {"max_failures": 1, "rerun_solves_jump": 4},
}

#: 消融开关，形状与 CTF_REDISPATCH 一致：只有 0/false/no/off 关掉。关掉时
#: 任何 N 都用 medium 默认（= 改动前行为），A/B 的对照臂靠它。
REGIME_ENV = "CTF_REGIME"


def regime_enabled() -> bool:
    """体量分档是否生效（A/B 的对照臂靠它关掉）。"""
    raw = os.environ.get(REGIME_ENV, "").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def regime_of(n_open: int) -> str:
    """按未关闭题数判体量档位。"""
    if n_open <= _REGIME_BOUNDS["small"]:
        return "small"
    if n_open <= _REGIME_BOUNDS["medium"]:
        return "medium"
    return "large"


def regime_preset(n_open: int) -> tuple[str, dict[str, int]]:
    """体量档位与其调度参数。返回 ``(档名, preset)``。

    关掉分档（CTF_REGIME=off）时固定返回 medium 默认——与改动前的行为
    逐位一致。
    """
    if not regime_enabled():
        return "medium", _REGIME_PRESETS["medium"]
    name = regime_of(n_open)
    return name, _REGIME_PRESETS[name]


def _value_bonus(chal: dict[str, Any]) -> int:
    """按平台动态积分推"这道题还剩多少分"——单调、无参数可调。

    只依赖 ``solves_count``：0 解出拿满 ``_VALUE_WEIGHT``，到 ``_DECAY_SOLVERS``
    队解出时归零（此后是地板价，彼此无差别）。用线性代理而不是复刻指数曲线，
    是因为公式未公开，而排序只需要单调性。
    """
    solves = int(chal.get("solves_count") or 0)
    if solves <= 0:
        return _VALUE_WEIGHT
    if solves >= _DECAY_SOLVERS:
        return 0
    return round(_VALUE_WEIGHT * (_DECAY_SOLVERS - solves) / _DECAY_SOLVERS)


def challenge_score(
    chal: dict[str, Any], state: dict[str, Any], my_solved: set[str]
) -> int | None:
    """单题优先级分。返回 None = 不进队列（已解出/关闭/qa-only）。

    Args:
        chal: 挑战列表 API 的一个 item。
        state: qid → 账本记录（runs/fails/solves_count_seen/status）。
        my_solved: 我们已解出的 challenge id 集合。
    """
    cid = str(chal.get("id") or "")
    if not cid or chal.get("closed"):
        return None
    rec = state.get(cid) or {}
    if rec.get("status") == SOLVED or cid in my_solved:
        return None
    score = _value_bonus(chal)
    if int(chal.get("solves_count") or 0) >= 1:
        # 别人解出来了 = 这道题在我们这套接入下确实可解，先打它。
        score += _PROVEN_BONUS
    score += _EASE_TIEBREAK.get(str(chal.get("difficulty") or ""), 10)
    score += _CATEGORY_WEIGHT.get(str(chal.get("category") or ""), 0)
    if chal.get("is_qa_only"):
        # 2026-11-13 实测：qa_only 题（SAMPLE-005/020）此前被直接判 None，
        # 从未派过单。它们不占实例配额，走 batch_eval 的 QA 分支。
        score += _QA_BONUS
    score -= _FAIL_PENALTY * int(rec.get("fails") or 0)
    requires: set[str] = set()
    for q in (chal.get("questions") or []):
        if isinstance(q, dict):
            requires.update(str(r) for r in (q.get("requires") or []))
    if requires and requires <= my_solved:
        score += _GATING_BONUS
    return score


def rank_queue(
    challenges: list[dict[str, Any]],
    state: dict[str, Any],
    my_solved: set[str],
    *,
    max_failures: int = 2,
    rerun_solves_jump: int = 3,
) -> tuple[list[dict[str, Any]], list[str]]:
    """把题表排成执行队列。

    Returns:
        ``(queue, notes)``：queue 按优先级降序；notes 是决策日志（人读，
        也进 digest）。
    """
    notes: list[str] = []
    queue: list[dict[str, Any]] = []
    my_solved = set(my_solved)
    for cid, rec in state.items():
        if rec.get("status") == DEFERRED:
            chal = next(
                (c for c in challenges if str(c.get("id") or "") == cid), None
            )
            if not chal:
                continue
            jump = int(chal.get("solves_count") or 0) - int(
                rec.get("solves_count_seen") or 0
            )
            if jump >= rerun_solves_jump:
                rec["status"] = ACTIVE
                # 新证据 = 一次全新的尝试预算；不重置的话同一轮就会被
                # 下面的 max_failures 检查原地打回 deferred。
                rec["fails"] = 0
                rec["skips"] = 0
                notes.append(
                    f"{cid}: deferred→active（solves_count +{jump}，他队验证可解）"
                )
    scored: list[tuple[int, dict[str, Any]]] = []
    for chal in challenges:
        cid = str(chal.get("id") or "")
        rec = state.get(cid) or {}
        if rec.get("status") == DEFERRED:
            notes.append(f"{cid}: deferred（连败 {rec.get('fails')} 次，放弃）")
            continue
        if rec.get("status") == RUNNING:
            continue  # 在跑的题不重复派
        score = challenge_score(chal, state, my_solved)
        if score is None:
            continue
        fails_budget = (
            _TAIL_RETRY_BUDGET
            if int(chal.get("solves_count") or 0) <= _TAIL_MAX_SOLVES
            else max_failures
        )
        if int(rec.get("fails") or 0) >= fails_budget:
            rec["status"] = DEFERRED
            rec["solves_count_seen"] = int(chal.get("solves_count") or 0)
            notes.append(f"{cid}: 连败 {fails_budget} 次→deferred")
            continue
        if int(rec.get("skips") or 0) >= max(2, max_failures):
            # B-23：连续基础设施跳过同样 defer——重派不产生任何新信息，
            # 只烧实例启动开销。他队解出数跳变仍可唤醒（与连败 defer 同门）。
            # 阈值取 ``max(2, max_failures)``：环境故障不是题目不可解的
            # 证据，它的 defer 门槛不随体量档收紧——一次平台瞬时故障就
            # 把题搁置到复活门槛之后，等于让基础设施抖动替我们选题。
            rec["status"] = DEFERRED
            rec["solves_count_seen"] = int(chal.get("solves_count") or 0)
            notes.append(f"{cid}: infra-skip 连续 {max(2, max_failures)} 次→deferred")
            continue
        scored.append((score, chal))
    scored.sort(key=lambda pair: (-pair[0], str(pair[1].get("id") or "")))
    queue = [chal for _, chal in scored]
    return queue, notes


def build_digest(state: dict[str, Any], challenges: list[dict[str, Any]]) -> str:
    """一行一题的简表：跨题记忆的「简略描述」层。详报在 runs/<qid>/。

    只含 id/类别/难度/状态/解出数/一句话——刻意不含任何答案或靶机细节，
    防止被误粘进题内上下文（全局记忆与题目上下文必须隔开）。
    """
    by_id = {str(c.get("id") or ""): c for c in challenges}
    lines = ["# compete digest（简略层；详报见 runs/<qid>/）", ""]
    for cid in sorted(set(state) | set(by_id)):
        rec = state.get(cid) or {}
        chal = by_id.get(cid) or {}
        lines.append(
            "| {id} | {cat} | {diff} | {status} | solves={n} | runs={r} | {one}".format(
                id=cid,
                cat=chal.get("category") or "?",
                diff=chal.get("difficulty") or "?",
                status=rec.get("status") or "new",
                n=chal.get("solves_count") or 0,
                r=rec.get("runs") or 0,
                one=(rec.get("one_line") or "")[:80],
            )
        )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 平台 I/O


#: 题表分页实测契约（2026-11-16，真平台）：``{items, limit, offset, total}``，
#: **默认 ``limit=50``**。只取首页 = 超过 50 题的比赛静默少一半题：不入账、不派单、
#: digest 里也不出现，看上去像"平台就这么多题"。
_PAGE_LIMIT = 100
#: total 撒谎（服务端永远说还剩）时的刹车。4000 题远超任何真实比赛。
_MAX_PAGES = 40


def fetch_challenges(token: str, cid: str, timeout: int = 30) -> list[dict[str, Any]]:
    """拉全量题表（分页 dict → items 列表）。失败抛异常，由主循环兜。

    按 ``total`` 翻页到齐为止。``total`` 缺失时退回"只取一页"的老行为；某页
    没带来任何新 id 也停——服务端忽略 offset 时不会变成死循环。
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    offset = 0
    for _ in range(_MAX_PAGES):
        r = requests.get(
            f"{PLATFORM}/api/v1/competitions/{cid}/challenges",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": _PAGE_LIMIT, "offset": offset},
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json()
        items = data.get("items") if isinstance(data, dict) else data
        page = [c for c in (items or []) if isinstance(c, dict)]
        fresh = [c for c in page if str(c.get("id")) not in seen]
        for c in fresh:
            seen.add(str(c.get("id")))
        out.extend(fresh)
        total = data.get("total") if isinstance(data, dict) else None
        if not page or not fresh or not isinstance(total, int) or len(out) >= total:
            break
        offset += len(page)
    return out


def fetch_scoreboard(token: str, cid: str, timeout: int = 30) -> dict[str, Any]:
    """拉实时榜（我们排名 + 花费，供 digest 与决策记录）。"""
    r = requests.get(
        f"{PLATFORM}/api/v1/competitions/{cid}/scoreboard",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def fetch_session_window(
    token: str, cid: str, timeout: int = 30
) -> tuple[float | None, float | None]:
    """本场比赛的 ``(当前会话结束, 下一会话开始)``，Unix 秒。

    练习场实测（2026-11-13）：sessions 是 4 小时一段、``:45–:00`` 暂停
    15 分钟，``session_end_mode=delete``——会话一结束，在跑的实例直接
    被删。run2 的 021/023「收场：error」与 003/017/018/021 的 ready
    超时全部撞在 15:45 的会话边界上，不是模型能力问题。

    无 sessions 字段（单场制）时返回 ``(None, None)``，调用方按不限期处理。
    """
    r = requests.get(
        f"{PLATFORM}/api/v1/competitions/{cid}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    r.raise_for_status()
    body = r.json()
    data = body if isinstance(body, dict) else {}
    sessions = data.get("sessions") or []
    now = time.time()

    def _ts(raw: Any) -> float | None:
        if not raw:
            return None
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None

    spans = [
        (_ts(s.get("starts_at")), _ts(s.get("ends_at")))
        for s in sessions
        if isinstance(s, dict)
    ]
    spans = [(a, b) for a, b in spans if a is not None and b is not None]
    # 当前会话：starts_at <= now < ends_at（含 15 分钟暂停段外沿）。
    current_end = next((b for a, b in spans if a <= now < b), None)
    future_starts = sorted(a for a, _ in spans if a > now)
    next_start = future_starts[0] if future_starts else (
        _ts(data.get("next_session_starts_at"))
    )
    return current_end, next_start


def session_allows_dispatch(
    now: float,
    session_end: float | None,
    next_start: float | None,
    needed_s: float,
    *,
    margin_s: float = 180.0,
) -> tuple[bool, float]:
    """会话窗口是否够跑完这一单；不够就返回要等多久。

    ``needed_s`` 是该题的实际墙钟上限（含难度放大）。``margin_s`` 给
    起实例、收尾提交、删实例留余量——实测这些加起来 60–120s，取 180s。

    返回 ``(可以派单, 需要等待的秒数)``。``session_end is None``（单场制）
    时永远放行。
    """
    if session_end is None:
        return True, 0.0
    if now >= session_end:
        # 已在暂停段：等下一场开始（缺 next_start 时按结束点+15 分钟估）。
        start = next_start if next_start is not None else session_end + 900.0
        return False, max(5.0, start - now + 5.0)
    remaining = session_end - now
    if remaining < needed_s + margin_s:
        start = next_start if next_start is not None else session_end + 900.0
        return False, max(5.0, start - now + 5.0)
    return True, 0.0


def fetch_my_solves(token: str, cid: str, timeout: int = 30) -> set[str]:
    """平台已知的「本队已解出」挑战 id。

    B-28：调度器原先只认本地 ``state.json`` 的 solved。凡是在这个 state
    之外解出的题（浏览器手解、别的 state 目录、其他 harness 补交）都会被
    当成没解过重新派单——实测用户看到"已解出的题被反复启动"。平台已有
    只读接口 ``GET /api/v1/me/solves?competition_id=…``，启动和每轮重排
    前对一遍即可。
    """
    r = requests.get(
        f"{PLATFORM}/api/v1/me/solves",
        params={"competition_id": cid},
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    items = data.get("items") if isinstance(data, dict) else data
    out: set[str] = set()
    for item in items or []:
        if isinstance(item, dict):
            cid_ = item.get("challenge_id")
            if cid_:
                out.add(str(cid_))
        elif isinstance(item, str):
            out.add(item)
    return out


def merge_platform_solves(state: dict[str, Any], solved_ids: set[str]) -> list[str]:
    """把平台已解 id 回灌进 state；返回本次新增为 solved 的 id（排序后）。"""
    added: list[str] = []
    for raw in solved_ids or ():
        cid = str(raw)
        if not cid:
            continue
        rec = state.setdefault(cid, {})
        if rec.get("status") != SOLVED:
            rec["status"] = SOLVED
            rec["one_line"] = "platform solved"
            added.append(cid)
    return sorted(added)


def deadline_reached(deadline: float | None) -> bool:
    """``--until`` 是否已到。``None`` 表示不限期。

    B-30：原先只在**外层**循环顶检查截止。车道一跑就是 15 分钟，外层在
    等车道退出时会把 ``--until`` 超出去一整轮墙钟（run3 的 13:34:05Z
    实际拖到 13:44 之后）。等待循环里也要能用同一个判据。
    """
    return deadline is not None and time.time() >= deadline


# ---------------------------------------------------------------- 状态落盘


def load_state(state_dir: Path) -> dict[str, Any]:
    p = state_dir / "state.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state_dir: Path, state: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = state_dir / "state.json.tmp"
    tmp.write_text(
        json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    os.replace(tmp, state_dir / "state.json")


def _row_count(state_dir: Path, cid: str, tag: str = "") -> int:
    """这题的结果文件里现在有几条记录（判「本轮有没有写新行」）。

    ``tag`` 对应竞速模式的 per-lane 文件（``-lane{N}``）。
    """
    p = state_dir / "runs" / f"{cid}{tag}.jsonl"
    if not p.exists():
        return 0
    try:
        return sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


def read_last_result(state_dir: Path, cid: str, tag: str = "") -> dict[str, Any] | None:
    """读 batch_eval 给这题追加的最后一条 jsonl 记录（判成败的唯一依据）。

    ``tag`` 对应竞速模式的 per-lane 文件（``-lane{N}``）。
    """
    p = state_dir / "runs" / f"{cid}{tag}.jsonl"
    if not p.exists():
        return None
    last: dict[str, Any] | None = None
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if str(rec.get("challenge") or "") == cid:
            last = rec
    return last


# ---------------------------------------------------------------- 主循环


def build_plan_item(
    cid: str, chal: dict[str, Any], *, allow_pools: bool = False
) -> dict[str, Any]:
    """派单 plan 项：**只含题号与难度**（+测试用放行标记）。

    隔离不变量：全局记忆（state/digest/既往题报告）**任何字段都不得**
    进入派单项——题内 agent 的上下文必须从零开始。以后想给题内加提示，
    只能走显式的新参数并配套隔离测试，不能顺手往这里塞。
    """
    item: dict[str, Any] = {
        "id": cid,
        "difficulty": chal.get("difficulty") or "medium",
    }
    if chal.get("is_qa_only"):
        # QA 题库题：batch_eval 走无实例分支（不 launch，/qa/submissions 交付）。
        # 只在为真时出现——不能让一个恒 False 的键改变「派单项只有
        # id/difficulty」这条隔离不变量（隔离测试逐键断言）。
        item["qa_only"] = True
    if allow_pools:
        # 练习场自测专用：SAMPLE-* 在封存/烧毁池里，不显式放行 batch_eval
        # 会直接拒跑。正式赛题不在 pools.json，不受影响。
        item["allow_burned"] = True
        item["allow_sealed"] = True
    return item


def pool_blocked_ids(root: Path | None = None) -> set[str]:
    """``experiments/pools.json`` 里封存/烧毁的题号（派单前剔除用）。

    为什么要在调度器里先剔：``batch_eval`` 开跑前的池闸门
    （``check_plan_pools``）会直接拒跑，而拒跑在车道看来是"环境问题"——
    不计失败、退避重派，于是同一条被拒的题把车道占满整个窗口。
    2026-11-16 冒烟实测：CTFARENA-047 被拒 5 次（15→240s 退避），
    15 分钟窗口里空转约 8 分钟。

    Args:
        root: 仓库根，默认按本文件位置推断。

    Returns:
        题号集合；``pools.json`` 缺失或读不出来时返回空集（与 batch_eval
        同口径：没切池子就不拦）。
    """
    root = root or Path(__file__).resolve().parent.parent
    path = root / "experiments" / "pools.json"
    try:
        pools = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if not isinstance(pools, dict):
        return set()
    out: set[str] = set()
    for key in ("sealed_excluded", "burned"):
        values = pools.get(key) or []
        if isinstance(values, list):
            out.update(str(v) for v in values if str(v).strip())
    return out


def drop_pool_blocked(
    challenges: list[dict[str, Any]], blocked: set[str]
) -> list[dict[str, Any]]:
    """剔除池闸门会拒跑的题；其余原样保序。"""
    if not blocked:
        return list(challenges)
    return [c for c in challenges if str(c.get("id") or "") not in blocked]


#: 宿主机 UDP 中转的地址。VM 上就是局域网网关；VPS 上没有这个东西，探测会
#: 在 0.5s 内失败，此时不注入 ``CTF_VPN_RELAY*``——否则每个实例都先吃一次
#: 控制口 3s 超时 + 一次注定失败的握手（11-19 实测每次白花 5–20s），
#: 而真正让隧道起来的是排在后面的直连路径。
_RELAY_HOST = os.environ.get("CTF_VPN_RELAY_HOST", "192.168.38.1")
_relay_state: dict[str, bool] = {}


def _relay_up(host: str | None = None) -> bool:
    """宿主机中转是否真在这台机器上跑着（连一次控制口，结果按进程缓存）。

    Args:
        host: 中转地址；None 取 :data:`_RELAY_HOST`。

    Returns:
        True = 控制口接受连接，可以走中转；False = 只有直连一条路。
    """
    target = host or _RELAY_HOST
    if target in _relay_state:
        return _relay_state[target]
    base = int(os.environ.get("CTF_VPN_RELAY_BASE", "47444"))
    ok = False
    try:
        with socket.create_connection((target, base + 1), timeout=0.5):
            ok = True
    except (OSError, ValueError):
        ok = False
    _relay_state[target] = ok
    if not ok:
        print(
            f"[compete] 宿主机中转 {target} 不可达（控制口 {base + 1}）——"
            "车道回落到直连 WireGuard",
            file=sys.stderr,
        )
    return ok


def _lane_env(
    lane: int,
    lane_models: list[dict[str, str]] | None = None,
    relay_up: bool | None = None,
) -> dict[str, str]:
    """给第 ``lane`` 条车道的子进程分配**独立**的 VPN 中转端口。

    宿主机的中转是「一个端口 = 一条车道 = 一套 target」。共用一套端口时，
    B 车道建的隧道会被推到 A 车道刚设的端点上：隧道能通、握手也成功，
    agent 却打在别人的实例上。这是并行跑批最容易踩、也最难看出来的坑，
    所以端口分配在派单处就固定下来，不靠运行时猜。

    ``CTF_VPN_RELAY_BASE`` 默认 47444，车道 i 用 ``BASE+2i``（控制口 +1）。
    中转地址那台机器没在跑（VPS 上没有 192.168.38.1）时**不注入**这两个变量，
    子进程只走直连——省掉每个实例一次注定失败的中转尝试。

    ``lane_models``（:func:`load_lane_config` 的产物）存在时，车道 i 额外
    覆盖 ``LLM_API_BASE`` / ``LLM_API_KEY`` / ``STRIX_LLM``——多厂商车道的
    凭据隔离。三家网关都是 OpenAI 兼容端点，模型名不带 ``/`` 时统一补
    ``openai/`` 前缀。值只进子进程 env（在 ``_spawn`` 的 env 合并里覆盖
    父进程的同名变量），不进 argv、不落 state、不打印。

    Args:
        lane: 车道序号（0 起）。
        lane_models: per-lane 厂商配置；None = 不覆盖（单厂商行为不变）。
        relay_up: 中转可用性；None = 运行 :func:`_relay_up` 现探，测试里直接给值。

    Returns:
        追加给子进程的环境变量。
    """
    base = int(os.environ.get("CTF_VPN_RELAY_BASE", "47444"))
    port = base + 2 * lane
    env: dict[str, str] = {}
    if _relay_up() if relay_up is None else relay_up:
        env["CTF_VPN_RELAY"] = f"{_RELAY_HOST}:{port}"
        env["CTF_VPN_RELAY_CONTROL"] = f"{_RELAY_HOST}:{port + 1}"
    if lane_models:
        cfg = lane_models[lane]
        model = cfg["model"]
        env["LLM_API_BASE"] = cfg["LLM_API_BASE"]
        env["LLM_API_KEY"] = cfg["LLM_API_KEY"]
        env["STRIX_LLM"] = model if "/" in model else f"openai/{model}"
    return env


def load_lane_config(path: Path) -> list[dict[str, str]]:
    """读 per-lane 厂商配置（与部署侧 lanes.conf 同格式，一行一车道）。

    行格式 ``名字|LLM_API_BASE|LLM_API_KEY|模型名``；``#`` 注释与空行跳过；
    四段都非空，少一段/多一段/有空段都拒绝（宁可启动失败，也不要拿半份
    凭据跑出一车道假 401）。文件在部署侧 chmod 600，本函数不做权限检查
    （Windows 上没有这个语义），只在出错信息里提醒。

    凭据从文件直接进子进程 env，**绝不出现在任何 print / argv / state**。
    """
    lanes: list[dict[str, str]] = []
    text = Path(path).read_text(encoding="utf-8")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4 or not all(parts):
            raise ValueError(
                f"车道配置第 {lineno} 行不是「名字|base|key|模型」四段非空："
                f"{raw[:40]}…"
            )
        name, api_base, api_key, model = parts
        lanes.append(
            {
                "name": name,
                "LLM_API_BASE": api_base,
                "LLM_API_KEY": api_key,
                "model": model,
            }
        )
    if not lanes:
        raise ValueError(f"车道配置 {path} 没有可用行（记得 chmod 600）")
    return lanes


def _mask_key(key: str) -> str:
    """启动横表里的 key 脱敏：只露尾 4 位，帮对配置、不帮泄密。"""
    return "…" + key[-4:] if len(key) >= 8 else "…(过短)"


def build_retry_notes(
    failure_path: list[str] | None,
    direction: tuple[str, str] | None,
    attempt: int,
) -> str:
    """拼 ``--retry-notes`` 文件正文；两段都没有时返回空串（不写文件）。

    两段的顺序有讲究：先说「哪些路已经走过」，再说「这次从哪儿开始」。反过来
    模型会先被方向牵着走，把上一轮的结构化事实当脚注。

    Args:
        failure_path: 同一道题前几轮的结构化失败路径（至多取 3 条）。
        direction: :func:`entry_direction` 的结果。
        attempt: 派单序号，写进标题让模型知道这是第几次。

    Returns:
        文件正文；空串表示这一单不需要重试提示。
    """
    blocks: list[str] = []
    if failure_path:
        blocks.append(
            "## 上一轮失败路径（本队自己的调试记录，不是平台提示）\n"
            + "\n".join(f"- {line}" for line in failure_path[-3:])
            + "\n\n上面这些路径已证明走不通或没有产生新观测；换机制类别，"
            "不要复读同一组探测。"
        )
    if direction is not None:
        label, text = direction
        blocks.append(
            f"## 本次换入口方向（第 {attempt} 次尝试，{label}）\n"
            f"{text}。从这个类别开始，做出观测后再决定下一步；"
            "上一轮的方向只作对照，不作为起始点。"
        )
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def _spawn(
    chal: dict[str, Any],
    args: argparse.Namespace,
    state_dir: Path,
    failure_path: list[str] | None = None,
    lane: int = 0,
    direction: tuple[str, str] | None = None,
    attempt: int = 1,
    lane_models: list[dict[str, str]] | None = None,
    tag: str = "",
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen:
    """派一个 batch_eval 子进程跑单题（agent 上下文从零开始）。

    ``failure_path`` 与 ``direction`` 只来自同一道题**本进程自己**的失败
    记录（state.json 里按 cid 存放），经显式 ``--retry-notes`` 文件交界面
    注入，绝不从 digest/别的题读——题间隔离不变量保持不变。

    ``tag`` 追加在该次 run 的所有落盘文件名上（竞速模式同题多车道并行，
    各写各的 ``{cid}-lane{N}.jsonl``，互不覆盖）；``extra_env`` 是竞速
    观察器的 ``CTF_RACE_*`` 通道。非竞速派单显式清掉这三个变量——
    race_stop 是纯 env 判定，父进程 shell 里残留的旧值会让不相干的
    分散派单也去盯一个早已结束的胜局标记。
    """
    cid = str(chal["id"])
    runs = state_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    plan = runs / f"plan-{cid}{tag}.json"
    item = build_plan_item(cid, chal, allow_pools=getattr(args, "allow_pools", False))
    plan.write_text(json.dumps([item]), encoding="utf-8")
    cmd = [
        sys.executable,
        str(HERE / "batch_eval.py"),
        "--plan",
        str(plan),
        "--turns",
        str(args.turns),
        "--wallclock",
        str(args.wallclock),
        "--out",
        str(runs / f"{cid}{tag}.jsonl"),
        "--token",
        args.token,
    ]
    if args.competition:
        cmd += ["--competition-id", args.competition]
    notes_text = build_retry_notes(failure_path, direction, attempt)
    if notes_text:
        notes = runs / f"retry-notes-{cid}{tag}.txt"
        notes.write_text(notes_text, encoding="utf-8")
        cmd += ["--retry-notes", str(notes)]
    log = open(runs / f"{cid}{tag}.stdout.log", "a", encoding="utf-8")
    lane_env = _lane_env(lane, lane_models)
    env = {**os.environ, **lane_env}
    if "CTF_VPN_RELAY" not in lane_env:
        # 中转不可用时也要把父进程可能残留的这两个变量摘掉，否则子进程
        # 还是会先去敲一个不存在的控制口。
        env.pop("CTF_VPN_RELAY", None)
        env.pop("CTF_VPN_RELAY_CONTROL", None)
    if extra_env is None:
        for stale in ("CTF_RACE_DIR", "CTF_RACE_CHALLENGE", "CTF_RACE_LANE"):
            env.pop(stale, None)
    else:
        env.update(extra_env)
    return subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)


def _sweep_orphans(token: str) -> list[str]:
    """删掉台账里**主人进程已死**的实例，返回删掉的 id。

    为什么需要这一层：``batch_eval`` 的 ``finally`` 会拆桥、拆隧道、删实例，
    但那是"进程能走到 finally"的前提。2026-11-19 实测两题在 agent 收车之后
    卡在清理段（jsonl 一行都没写），12 分钟后进程被停止信号 SIGKILL，实例
    就一直 ready 到 3 小时 TTL 结束——平台上看起来就是"没解出也没结束"。

    判定沿用 ``batch_eval`` 的所有权台账：只删"登记过、且登记时的 pid 已经
    不在了"的实例。兄弟车道（pid 还活着）和没登记的实例一律不碰——这条
    与 B-27 的教训一致（盲删会把并行车道正在用的靶机拔掉）。

    Args:
        token: 平台 token（删实例要认证）。

    Returns:
        实际删掉的实例 id 列表。
    """
    try:
        ids = batch_eval._ledger_dead_ids()
    except Exception:  # noqa: BLE001 — 台账坏了不该拖垮调度器
        return []
    done: list[str] = []
    for iid in sorted(ids):
        try:
            r = requests.delete(
                f"{PLATFORM}/api/v1/instances/{iid}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=20,
            )
        except requests.RequestException as exc:
            print(f"[compete] 回收 {iid[:8]} 失败：{exc}", flush=True)
            continue
        if r.status_code < 400 or r.status_code == 404:
            batch_eval._ledger_forget(iid)
            done.append(iid)
            print(f"[compete] 回收残留实例 {iid[:8]}（主人进程已退出）", flush=True)
        else:
            print(f"[compete] 回收 {iid[:8]} 返回 HTTP {r.status_code}", flush=True)
    return done


def _failure_lines(rec: dict[str, Any]) -> list[str]:
    """把一次失败的结果记录压成 1–3 行人读的失败路径。

    只取结构化事实（stop_reason / error / 被判否的答案 / checker 预检 /
    子进程落盘的停滞事实），不搬日志正文——重试提示里塞正文会过拟合，
    也会把无关内容带进下一轮上下文。
    """
    lines: list[str] = []
    err = str(rec.get("error") or "")
    reason = str(rec.get("stop_reason") or "")
    if rec.get("skipped"):
        lines.append(f"基础设施跳过：{err or reason}")
    elif err:
        lines.append(f"异常收场：{err[:140]}")
    elif reason:
        lines.append(f"收场：{reason}")
    rejected = rec.get("answers_rejected")
    if isinstance(rejected, dict) and rejected:
        shown = "、".join(f"{qid}={val}" for qid, val in list(rejected.items())[:3])
        lines.append(f"提交后被判否：{shown[:180]}")
    checked = rec.get("checker_checked")
    if isinstance(checked, list) and checked:
        lines.append("checker 未过：" + ",".join(map(str, checked))[:80])
    stalled = rec.get("failure_path")
    if isinstance(stalled, list):
        # batch_eval 的 failure_path 与这里第一段同源（都含「收场：X」），
        # 直接 extend 会把同一行写两遍（SAMPLE-001 实测
        # "收场：unknown；收场：unknown"）。去重后保留信息量更大的几条。
        for item in stalled[:2]:
            line = str(item)[:140]
            if line and line not in lines:
                lines.append(line)
    return lines[:3]


def _collect(
    cid: str, state: dict[str, Any], state_dir: Path, exit_code: int | None = None
) -> str:
    """子进程退出后收账：以 jsonl 最后一条记录为准（不信退出码，冒烟 #8）。"""
    rec = read_last_result(state_dir, cid) or {}
    state_rec = state.setdefault(cid, {})
    # 派单闸门/环境不备：子进程在写第一行结果之前就退了。原实现会把
    # **上一轮**的最后一条记录当本轮结果——既可能重复记一次旧失败，也会把
    # 「整批停跑」记成题目失败（11-13 一个坏 key 连烧 10 道题就是这么来的）。
    rows_before = state_rec.get("rows_before")
    if rows_before is not None and _row_count(state_dir, cid) <= int(rows_before):
        state_rec["status"] = ACTIVE
        state_rec["one_line"] = f"infra: no result row (exit {exit_code})"
        state_rec["infra_stops"] = int(state_rec.get("infra_stops") or 0) + 1
        return INFRA
    if state_rec.get("status") == SOLVED:
        # B-28：平台已解回灌的题，本地一次判负不得把它降级成 failed。
        return SOLVED
    state_rec["runs"] = int(state_rec.get("runs") or 0) + 1
    state_rec["last_run_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    state_rec["one_line"] = str(rec.get("stop_reason") or rec.get("error") or "")
    if rec.get("skipped"):
        status = FAILED
        # B-23：基础设施失败（实例连不上/无可直连地址）不是题目不可解的
        # 证据，不计入 fails；但必须计入 skips（连续口径），否则调度器会
        # 对同一题无限重派——实测单题 20+ 次 run、每次都白起一个实例。
        state_rec["skips"] = int(state_rec.get("skips") or 0) + 1
    elif rec.get("correct"):
        status = SOLVED
        state_rec["one_line"] = "solved"
        state_rec.pop("failure_path", None)
    else:
        status = FAILED
        state_rec["fails"] = int(state_rec.get("fails") or 0) + 1
        # 真跑了一次（哪怕失败）说明接入已恢复，skip 连击清零。
        state_rec["skips"] = 0
        if not rec.get("skipped"):
            fp = _failure_lines(rec)
            if fp:
                hist = list(state_rec.get("failure_path") or [])
                hist.append("；".join(fp)[:300])
                state_rec["failure_path"] = hist[-3:]
                state_rec["one_line"] = state_rec["failure_path"][-1][:80]
    state_rec["status"] = status
    return status


# ------------------------------------------------------- 竞速优先（race-first）


def race_phase_active(window_end: float, now: float) -> bool:
    """竞速窗口是否还开着（``window_end <= 0`` 即从未启用，恒 False）。"""
    return window_end > 0 and now < window_end


def _race_env(race_dir: Path, cid: str, lane: int) -> dict[str, str]:
    """给竞速车道子进程的 env 增量（race_stop 的纯 env 交界面）。"""
    return {
        "CTF_RACE_DIR": str(race_dir),
        "CTF_RACE_CHALLENGE": cid,
        "CTF_RACE_LANE": str(lane),
    }


def _race_window_end(state_dir: Path, race_first_s: int) -> float:
    """竞速窗口的**绝对**截止时刻；``race_first_s <= 0`` 表示不启用。

    窗口属于「这一场比赛」，不是「这一次进程」：compet.py 中途重启不得把
    窗口再拉长一遍（重启两次 = 两倍竞速时间）。首启时把截止时刻落盘
    （临时文件 + os.replace），此后一律读盘，坏了按已过期处理——宁可
    少竞速一阵，也不要无窗口地竞速下去。
    """
    if race_first_s <= 0:
        return 0.0
    p = state_dir / "race-window.json"
    if p.exists():
        try:
            return float(json.loads(p.read_text(encoding="utf-8"))["end"])
        except (OSError, ValueError, KeyError, TypeError):
            # 坏了按已过期处理：宁可少竞速一阵，也不要无窗口地竞速下去。
            return 0.0
    end = time.time() + race_first_s
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps({"end": end}), encoding="utf-8")
    os.replace(tmp, p)
    return end


def _collect_race(
    cid: str, state: dict[str, Any], state_dir: Path, n_lanes: int
) -> str:
    """一场竞速（所有车道都已退出）收一次账：一条竞速 = **一次**尝试。

    - 任一车道判对 → SOLVED（先解先停，赢家的结果就是全队的结果）；
    - 全败 → 记**一次** fail，不乘车道数——同题同盘的车道是相关样本，
      乘上去只会把 max_failures 提前烧穿、把题挤进 deferred；
    - 每条结果行都没写（连赛道都没跑起来）→ INFRA，不计失败，稍后重派
      （口径与分散派单的 ``_collect`` 一致）；
    - 全部车道 skipped → 只记 skip 连击，不记 fail（接入问题 ≠ 题不可解）。
    失败路径取信息量最大的一条（``_failure_lines`` 最长的非 skip 记录）。
    """
    state_rec = state.setdefault(cid, {})
    tags = [f"-lane{i}" for i in range(n_lanes)]
    before = state_rec.get("race_rows_before")
    if isinstance(before, list):
        total_before = sum(int(x or 0) for x in before)
        if sum(_row_count(state_dir, cid, tag=t) for t in tags) <= total_before:
            state_rec["status"] = ACTIVE
            state_rec["one_line"] = "infra: no result row (race)"
            state_rec["infra_stops"] = int(state_rec.get("infra_stops") or 0) + 1
            return INFRA
    if state_rec.get("status") == SOLVED:
        # B-28 同款：平台已解回灌的题，本地竞速判负不得降级。
        return SOLVED
    recs = [read_last_result(state_dir, cid, tag=t) or {} for t in tags]
    state_rec["runs"] = int(state_rec.get("runs") or 0) + 1
    state_rec["last_run_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    solved_lane = next((i for i, r in enumerate(recs) if r.get("correct")), None)
    if solved_lane is not None:
        state_rec["status"] = SOLVED
        state_rec["one_line"] = f"solved (race: lane {solved_lane})"
        state_rec.pop("failure_path", None)
        return SOLVED
    state_rec["one_line"] = str(recs[0].get("stop_reason") or recs[0].get("error") or "")
    if all(r.get("skipped") for r in recs):
        state_rec["status"] = FAILED
        state_rec["skips"] = int(state_rec.get("skips") or 0) + 1
        return FAILED
    state_rec["fails"] = int(state_rec.get("fails") or 0) + 1
    # 真跑过一次（哪怕全败）说明接入已恢复，skip 连击清零。
    state_rec["skips"] = 0
    real = [r for r in recs if not r.get("skipped")] or recs
    best = max(real, key=lambda r: len(_failure_lines(r)))
    fp = _failure_lines(best)
    if fp:
        hist = list(state_rec.get("failure_path") or [])
        hist.append("；".join(fp)[:300])
        state_rec["failure_path"] = hist[-3:]
        state_rec["one_line"] = state_rec["failure_path"][-1][:80]
    state_rec["status"] = FAILED
    return FAILED


def build_parser() -> argparse.ArgumentParser:
    """命令行契约。单独成函数，好让测试钉住默认值（尤其时间盒）。"""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--token", required=True)
    p.add_argument("--competition", required=True, help="competition id")
    p.add_argument("--state-dir", default="~/compete-state")
    p.add_argument(
        "--lanes",
        type=int,
        default=2,
        help="并发车道（默认 2：平台配额 3，留 1 个余量给停止中/重试实例）",
    )
    p.add_argument("--turns", type=int, default=60, help="单题轮次（上限 60）")
    p.add_argument(
        "--wallclock",
        type=int,
        default=_ATTEMPT_BOX_S,
        help=f"单次尝试墙钟基准（秒，easy 档；默认 {_ATTEMPT_BOX_S}，依据见 "
        "docs/47 §2.3.2）",
    )
    p.add_argument("--until", default="", help="ISO 时间，到点收工（空=一直跑）")
    p.add_argument(
        "--ignore-platform-solves",
        action="store_true",
        help="练习场重跑用：不把平台已解回灌成 solved（正式赛禁用）",
    )
    p.add_argument("--dry-run", action="store_true", help="只打印队列，不派单")
    p.add_argument("--once", action="store_true", help="排一轮队跑完就退出（冒烟用）")
    p.add_argument(
        "--race-first",
        type=int,
        default=0,
        help="开赛后先竞速 N 秒：窗口内队首题同时派给所有车道先解先停"
        "（race_stop 输家 0 LLM 停车），窗口过后回到分散派单。"
        "0（默认）= 不竞速，维持 A/B 对照臂。窗口截止时刻落 state-dir，"
        "中途重启不重置",
    )
    p.add_argument("--poll", type=float, default=10.0, help="车道轮询间隔（秒）")
    p.add_argument(
        "--lane-stagger",
        type=float,
        default=30.0,
        help="连续派两条车道之间的最小间隔秒数（默认 30）。三条车道同一秒"
        "起实例会同时压 platform/DNS/边缘节点，也容易在同一秒收场撞 DELETE；"
        "0 = 关闭错峰（旧行为）",
    )
    p.add_argument(
        "--allow-pools",
        action="store_true",
        help="放行封存/烧毁池的题（仅练习场自测；正式赛不要用）",
    )
    p.add_argument(
        "--lane-config",
        default="",
        help="per-lane 厂商配置文件（名字|LLM_API_BASE|LLM_API_KEY|模型名，"
        "一行一车道，chmod 600）；不配则所有车道共用当前进程的 LLM_* 环境",
    )
    return p


def main() -> int:
    added = ensure_bundle_tool_env()
    if "PATH" in added:
        print(f"[compete] bundle 工具已挂进 PATH（{len(added['PATH'].split(os.pathsep))} 段）", flush=True)
    args = build_parser().parse_args()

    #: per-lane 厂商配置（可选）。加载失败/行数不够车道数 = 启动即退：
    #  拿半份凭据跑起来的"成功"比失败贵得多（假 401 烧一整轮墙钟）。
    lane_models: list[dict[str, str]] | None = None
    if args.lane_config:
        try:
            lane_models = load_lane_config(Path(args.lane_config).expanduser())
        except (OSError, ValueError) as exc:
            print(f"[compete] 车道配置加载失败：{exc}", flush=True)
            return 2
        if len(lane_models) < args.lanes:
            print(
                f"[compete] 车道配置只有 {len(lane_models)} 行，"
                f"不够 --lanes {args.lanes} 条车道",
                flush=True,
            )
            return 2
        for i, cfg in enumerate(lane_models):
            print(
                f"[compete] lane {i}: {cfg['name']} @ {cfg['LLM_API_BASE']} "
                f"model={cfg['model']} key={_mask_key(cfg['LLM_API_KEY'])}",
                flush=True,
            )

    state_dir = Path(args.state_dir).expanduser()
    state = load_state(state_dir)
    # 崩溃恢复：上一进程没来得及收车的 RUNNING 是孤儿（新进程此刻还没派
    # 任何单），不复位的话这些题会被 rank_queue 永久跳过。
    for _rec in state.values():
        if _rec.get("status") == RUNNING:
            _rec["status"] = ACTIVE
            _rec["one_line"] = "orphaned run reset"
    if not args.ignore_platform_solves:
        try:
            synced = merge_platform_solves(
                state, fetch_my_solves(args.token, args.competition)
            )
            if synced:
                print(f"[compete] 平台已解回灌：{', '.join(synced)}", flush=True)
        except requests.RequestException as exc:
            print(f"[compete] 已解列表拉取失败（忽略，用本地 state）：{exc}", flush=True)
    my_solved = {cid for cid, r in state.items() if r.get("status") == SOLVED}
    running: dict[str, subprocess.Popen] = {}
    #: 题 → 车道号。车道号决定 VPN 中转端口（见 _lane_env）。
    lane_of: dict[str, int] = {}
    #: 竞速在飞：题 → {车道号 → 子进程}。一场竞速占满所有车道，全部退出
    #: 才收一次账（_collect_race）；与 running（分散派单）互斥——竞速只在
    #: 所有车道空闲时起跑，所以两本账不会同时有活。
    race_runs: dict[str, dict[int, subprocess.Popen]] = {}
    race_window_end = _race_window_end(state_dir, args.race_first)
    if race_window_end > 0:
        remaining = max(0.0, race_window_end - time.time())
        print(
            f"[compete] 竞速优先：开赛后先同题竞速 {remaining:.0f}s"
            "（窗口过后回到分散派单）",
            flush=True,
        )
    stop = False
    last_solve_sync = 0.0
    #: 连续「一行结果都没写」的车道数——用来把环境停跑的退避拉长到 5 分钟，
    #: 而不是每 poll 秒重派一次。任何一次正常收车就清零。
    infra_streak = 0
    #: 车道错峰：相邻两条车道起跑至少隔 ``--lane-stagger`` 秒。2026-11-19
    #: 实测三条车道同一秒起实例时，起实例/DNS/边缘节点跟着一起抖，收场也
    #: 挤在同一秒调 DELETE。错峰只影响"背靠背补位"，已跑了几分钟的车道不受影响。
    stagger_s = max(0.0, float(getattr(args, "lane_stagger", 0) or 0))
    last_spawn_at = 0.0

    def _sigint(_sig, _frm):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _sigint)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sigint)

    deadline = None
    if args.until:
        deadline = datetime.fromisoformat(args.until).timestamp()

    #: 会话窗口（练习场 4h 一段）：派单前要确认剩余时间够跑完这一单。
    #: 每 5 分钟刷新一次，避免跨过一次会话边界还用旧窗口。
    session_end: float | None = None
    next_start: float | None = None
    session_fetched_at = 0.0
    session_warned = False

    def _refresh_session(force: bool = False) -> None:
        nonlocal session_end, next_start, session_fetched_at
        if not force and time.time() - session_fetched_at < 300:
            return
        session_fetched_at = time.time()
        try:
            session_end, next_start = fetch_session_window(
                args.token, args.competition
            )
        except Exception as exc:  # noqa: BLE001 — 拉不到就按不限期跑
            print(f"[compete] 会话窗口拉取失败（按不限期处理）：{exc}", flush=True)
            session_end, next_start = None, None

    _refresh_session(force=True)

    #: 池闸门：封存/烧毁题派出去只会被 batch_eval 拒跑，然后在车道里退避
    #: 重派（冒烟实测空转 8 分钟）。开跑前剔除一次；--allow-pools 显式放行。
    blocked_pools = set() if args.allow_pools else pool_blocked_ids()

    #: 体量档位（题池规模未知，由题表自动判，见 _REGIME_PRESETS）。
    last_regime: str | None = None
    pool_note_printed = False

    while not stop:
        # 强杀留下的实例（台账主人 pid 已死）在这里回收：不等撞配额再收拾，
        # 也不让平台上挂着"没解出也没结束"的靶机。
        _sweep_orphans(args.token)
        if deadline_reached(deadline):
            print("[compete] 到 --until，收工", flush=True)
            break
        _refresh_session()
        try:
            challenges = fetch_challenges(args.token, args.competition)
        except Exception as exc:  # noqa: BLE001
            print(f"[compete] 题表拉取失败：{exc}，{args.poll}s 后重试", flush=True)
            time.sleep(args.poll)
            continue
        kept = drop_pool_blocked(challenges, blocked_pools)
        if len(kept) != len(challenges):
            if not pool_note_printed:
                pool_note_printed = True
                print(
                    f"[compete] 池闸门：剔除 {len(challenges) - len(kept)} 道"
                    "封存/烧毁题（--allow-pools 放行）",
                    flush=True,
                )
            challenges = kept
        # 刷新：新题自动入账；已解出（别处补交成功等）从 run 态摘除。
        for chal in challenges:
            cid = str(chal.get("id") or "")
            if cid and cid not in state:
                state[cid] = {
                    "status": ACTIVE,
                    "runs": 0,
                    "fails": 0,
                    "solves_count_seen": int(chal.get("solves_count") or 0),
                    # 只落在调度器的账本里，供收工后分题型统计（web 一枝独秀
                    # 会把 crypto/rev 的短板平均掉）。**不进派单 plan**——
                    # 题内上下文隔离不变量不受影响。
                    "category": str(chal.get("category") or ""),
                    "difficulty": str(chal.get("difficulty") or ""),
                    "one_line": "",
                }
            elif cid and not (state[cid].get("category") and state[cid].get("difficulty")):
                # 旧账本没有这两列：补一次，别让分题型统计只剩 "?"。
                state[cid]["category"] = state[cid].get("category") or str(
                    chal.get("category") or ""
                )
                state[cid]["difficulty"] = state[cid].get("difficulty") or str(
                    chal.get("difficulty") or ""
                )
        if time.time() - last_solve_sync >= 60 and not args.ignore_platform_solves:
            # B-28：赛中在浏览器/别处解出的题，60s 内同步进账，避免重派。
            last_solve_sync = time.time()
            try:
                added = merge_platform_solves(
                    state, fetch_my_solves(args.token, args.competition)
                )
            except requests.RequestException as exc:
                print(f"[compete] 已解列表拉取失败（本轮忽略）：{exc}", flush=True)
                added = []
            if added:
                print(f"[compete] 平台已解回灌：{', '.join(added)}", flush=True)
                my_solved |= set(added)
                save_state(state_dir, state)
        # 体量档位：按本轮未关闭题数判，分批放题/题目下线时自动换档。
        n_open = sum(1 for c in challenges if not c.get("closed"))
        regime_name, preset = regime_preset(n_open)
        if regime_name != last_regime:
            last_regime = regime_name
            print(
                f"[compete] 题池体量 N={n_open} → 档位 {regime_name}"
                f"（max_failures={preset['max_failures']}，"
                f"rerun_solves_jump={preset['rerun_solves_jump']}）",
                flush=True,
            )
        queue, notes = rank_queue(
            challenges,
            state,
            my_solved,
            max_failures=int(preset["max_failures"]),
            rerun_solves_jump=int(preset["rerun_solves_jump"]),
        )
        (state_dir).mkdir(parents=True, exist_ok=True)
        (state_dir / "digest.md").write_text(
            build_digest(state, challenges), encoding="utf-8"
        )
        for note in notes:
            print(f"[compete] {note}", flush=True)
        if args.dry_run:
            for chal in queue:
                print(
                    f"[queue] {chal.get('id')} {chal.get('category')} "
                    f"{chal.get('difficulty')} solves={chal.get('solves_count')}",
                    flush=True,
                )
            return 0
        # 填车道
        if (
            race_phase_active(race_window_end, time.time())
            and args.lanes > 1
            and not running
            and not race_runs
            and queue
        ):
            # 竞速优先（2026-11-17 用户拍板）：开赛窗口内，队首题同时派给
            # 所有车道先解先停，而不是各拿一题。理由：首次解出概率低，
            # 分散派单会把没解出的题排到后期——既丢动态积分的早解优势，
            # 尾部还可能覆盖不到；竞速把 N 个独立上下文押在同一题上，
            # 任一车道解出即全队得分（race_stop 已双实例实测：输家
            # 0 LLM 停车，比分散派单省 token）。窗口过后回到分散派单。
            chal = queue.pop(0)
            cid = str(chal["id"])
            needed = min(
                args.wallclock
                * _WALL_TIER.get(str(chal.get("difficulty") or ""), 1.0),
                _LIMITS_MAX_WALL_S,
            )
            ok, wait = session_allows_dispatch(
                time.time(), session_end, next_start, needed
            )
            if not ok:
                # 会话边界前的纪律与分散派单一致：宁空等，不派半场。
                queue.insert(0, chal)
                if not session_warned:
                    print(
                        f"[compete] 会话窗口不足（{cid} 需 {needed:.0f}s），"
                        f"{wait:.0f}s 后下一场再派",
                        flush=True,
                    )
                session_warned = True
            else:
                session_warned = False
                rec = state.setdefault(cid, {})
                tags = [f"-lane{i}" for i in range(args.lanes)]
                # 收车判「本轮有没有写结果行」的基线，每车道各记各的。
                rec["race_rows_before"] = [
                    _row_count(state_dir, cid, tag=t) for t in tags
                ]
                rec["status"] = RUNNING
                attempt = int(rec.get("runs") or 0) + 1
                direction = entry_direction(attempt) if directions_enabled() else None
                if direction is not None:
                    rec["direction"] = direction[0]
                    rec["directions"] = (
                        list(rec.get("directions") or []) + [direction[0]]
                    )[-5:]
                if lane_models:
                    # 只进调度器账本（赛后分厂商统计用），不进子进程上下文。
                    rec["lane_models"] = [
                        lane_models[i]["name"] for i in range(args.lanes)
                    ]
                race_dir = state_dir / "race"
                race_dir.mkdir(parents=True, exist_ok=True)
                race_runs[cid] = {}
                for lane in range(args.lanes):
                    race_runs[cid][lane] = _spawn(
                        chal,
                        args,
                        state_dir,
                        failure_path=rec.get("failure_path"),
                        lane=lane,
                        direction=direction,
                        attempt=attempt,
                        lane_models=lane_models,
                        tag=f"-lane{lane}",
                        extra_env=_race_env(race_dir, cid, lane),
                    )
                last_spawn_at = time.time()
                print(
                    f"[compete] 竞速派单 {cid}（{args.lanes} 车道同题先解先停"
                    + (f"，换向={direction[0]}" if direction else "")
                    + "）",
                    flush=True,
                )
        elif not race_runs:
            while len(running) < args.lanes and queue:
                chal = queue.pop(0)
                cid = str(chal["id"])
                needed = min(
                    args.wallclock
                    * _WALL_TIER.get(str(chal.get("difficulty") or ""), 1.0),
                    _LIMITS_MAX_WALL_S,
                )
                ok, wait = session_allows_dispatch(
                    time.time(), session_end, next_start, needed
                )
                if not ok:
                    # 会话边界前派单 = 跑到一半实例被删（实测 021/023 的
                    # error、003/017/018 的 ready 超时）。宁可空等下一场。
                    queue.insert(0, chal)
                    if not session_warned:
                        print(
                            f"[compete] 会话窗口不足（{cid} 需 {needed:.0f}s），"
                            f"{wait:.0f}s 后下一场再派",
                            flush=True,
                        )
                        session_warned = True
                    break
                session_warned = False
                # 错峰在**改 state 之前**做：等待期间收到停止信号，题要原样
                # 放回队首——先标 RUNNING 再退出的话，这题下一轮会被当孤儿跳过。
                if stagger_s and last_spawn_at:
                    gap = stagger_s - (time.time() - last_spawn_at)
                    while gap > 0 and not stop:
                        time.sleep(min(gap, 1.0))
                        gap = stagger_s - (time.time() - last_spawn_at)
                    if stop:
                        queue.insert(0, chal)
                        break
                rec = state.setdefault(cid, {})
                # 收车时用来判「本轮有没有写结果行」；必须在启动子进程之前取。
                rec["rows_before"] = _row_count(state_dir, cid)
                rec["status"] = RUNNING
                # 第几次尝试决定入口方向：失败过的题换一个机制类别起步，首跑不注入。
                # ``CTF_REDISPATCH=0`` 时退回改动前的行为，A/B 的对照臂靠它。
                attempt = int(rec.get("runs") or 0) + 1
                direction = entry_direction(attempt) if directions_enabled() else None
                if direction is not None:
                    rec["direction"] = direction[0]
                    rec["directions"] = (
                        list(rec.get("directions") or []) + [direction[0]]
                    )[-5:]
                used = set(lane_of.values())
                lane = next(i for i in range(args.lanes) if i not in used)
                if lane_models:
                    # 只进调度器账本（赛后分厂商统计用），不进任何子进程上下文。
                    rec["lane_model"] = lane_models[lane]["name"]
                running[cid] = _spawn(
                    chal,
                    args,
                    state_dir,
                    failure_path=rec.get("failure_path"),
                    lane=lane,
                    direction=direction,
                    attempt=attempt,
                    lane_models=lane_models,
                )
                lane_of[cid] = lane
                last_spawn_at = time.time()
                lane_label = (
                    f"{lane}({lane_models[lane]['name']})" if lane_models else str(lane)
                )
                print(
                    f"[compete] 派单 {cid}（{len(running)}/{args.lanes} 车道，"
                    f"lane={lane_label} 中转 {_lane_env(lane, lane_models).get('CTF_VPN_RELAY', '直连')}"
                    + (f"，换向={direction[0]}" if direction else "")
                    + "）",
                    flush=True,
                )
        save_state(state_dir, state)
        if not running and not race_runs:
            if args.once:
                print("[compete] --once：队列跑完，退出", flush=True)
                _sweep_orphans(args.token)
                return 0
            print(
                f"[compete] 队列空（无可跑题），{args.poll}s 后重刷题表",
                flush=True,
            )
            time.sleep(args.poll)
            continue
        # 等任一车道退出
        while (running or race_runs) and not stop:
            if deadline_reached(deadline):
                print("[compete] 到 --until，杀在跑车道…", flush=True)
                stop = True
                break
            time.sleep(min(args.poll, 5.0))
            for cid in list(running):
                proc = running[cid]
                if proc.poll() is None:
                    continue
                del running[cid]
                lane_of.pop(cid, None)
                status = _collect(cid, state, state_dir, exit_code=proc.returncode)
                if status == SOLVED:
                    my_solved.add(cid)
                if status == INFRA:
                    infra_streak += 1
                    wait = min(300.0, 15.0 * (2 ** min(infra_streak - 1, 4)))
                    print(
                        f"[compete] {cid} 未派成（环境问题，不计失败），"
                        f"{wait:.0f}s 后再试",
                        flush=True,
                    )
                    save_state(state_dir, state)
                    time.sleep(wait)
                    continue
                infra_streak = 0
                save_state(state_dir, state)
                print(f"[compete] {cid} 收车：{status}", flush=True)
                break
            # 竞速收车：一条竞速要等它的**所有**车道退出才收一次账
            # （先解先停由子进程自己执行：赢家写完胜局标记，输家
            # race_stop 盯到即 0 LLM 自停；这里只负责归并结果）。
            for rcid in list(race_runs):
                lanes = race_runs[rcid]
                for lane in list(lanes):
                    proc = lanes[lane]
                    if proc.poll() is None:
                        continue
                    del lanes[lane]
                if lanes:
                    continue
                del race_runs[rcid]
                status = _collect_race(rcid, state, state_dir, args.lanes)
                if status == SOLVED:
                    my_solved.add(rcid)
                if status == INFRA:
                    infra_streak += 1
                    wait = min(300.0, 15.0 * (2 ** min(infra_streak - 1, 4)))
                    print(
                        f"[compete] {rcid} 竞速未派成（环境问题，不计失败），"
                        f"{wait:.0f}s 后再试",
                        flush=True,
                    )
                    save_state(state_dir, state)
                    time.sleep(wait)
                else:
                    infra_streak = 0
                    save_state(state_dir, state)
                    print(f"[compete] {rcid} 竞速收车：{status}", flush=True)
                break
        if stop:
            print("[compete] 收到停止信号，杀掉在跑车道…", flush=True)
            for proc in [p for ls in race_runs.values() for p in ls.values()] + list(
                running.values()
            ):
                proc.terminate()
            for proc in [p for ls in race_runs.values() for p in ls.values()] + list(
                running.values()
            ):
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
            # 子进程被强杀时不会走到 batch_eval 的 finally：它的实例此刻
            # 只会留在台账里。这里立刻按"主人已死"回收一次。
            _sweep_orphans(args.token)
            save_state(state_dir, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
