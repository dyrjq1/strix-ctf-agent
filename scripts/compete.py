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
4. **并发**：``--lanes``（默认 3 = 平台实例配额）个 batch_eval 子进程
   同时各占一个题目实例。⚠️ 冒烟已知：需要 VPN/隧道的 TCP 题并行车道
   会共享子网路由互踩（vpn.py 单 wg 接口）；遇到路由型失败先降
   ``--lanes 1``。

选题策略（纯函数 ``rank_queue``，全部可单测）：

- 已解出 / 已关闭 / qa-only 的题不进队列；
- 动态积分下早解优先：easy > medium > hard 的基础分；
- ``solves_count`` 是唯一难度代理（UI 不显示难度，API 返回）：
  他队解出过 = 可解性证据加分，零解出题压后（分高但胜率未知，
  留到证明可解或收尾再打）；
- web 是实测强项（解出率 83%），类别加权优先；
- 连续失败 ``max_failures``（默认 2）次 → deferred（放弃）；
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
        --turns 25 --wallclock 900 --until "2026-11-15T20:00+08:00"

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
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # 复用 batch_eval 的 Client/常量
    sys.path.insert(0, str(HERE))

import requests  # noqa: E402

import batch_eval  # noqa: E402

#: 平台地址。batch_eval.Client 同源，不另起一份。
PLATFORM = batch_eval.PLATFORM if hasattr(batch_eval, "PLATFORM") else "https://ctfy.tsinghua.edu.cn"

# ---------------------------------------------------------------- 策略纯函数

#: 状态机：active（可跑）/ running / solved / failed / deferred（放弃，
#: 等 solves_count 跳变或收尾 sweep）。
ACTIVE, RUNNING, SOLVED, FAILED, DEFERRED = "active", "running", "solved", "failed", "deferred"

#: 基础分：动态积分下早解优先，easy 先打（快分 + 名次优势）。
_DIFFICULTY_WEIGHT = {"easy": 300, "medium": 200, "hard": 100}
#: 类别偏好：web 是实测强项（48 测 40 解），其余平权起步。
_CATEGORY_WEIGHT = {"web": 60}
#: 可解性证据：他队解出过 → 加分；零解出 → 压后（不是不打，是排后面）。
_SOLVABLE_BONUS = 150
_UNSOLVED_PENALTY = -100
#: 每次失败扣分；连续失败 max_failures 次 → deferred。
_FAIL_PENALTY = 90
#: 门控题：前置问题全部被我们解过 → 优先（解一个解锁一串）。
_GATING_BONUS = 40


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
    if not cid or chal.get("closed") or chal.get("is_qa_only"):
        return None
    rec = state.get(cid) or {}
    if rec.get("status") == SOLVED or cid in my_solved:
        return None
    score = _DIFFICULTY_WEIGHT.get(str(chal.get("difficulty") or ""), 150)
    score += _CATEGORY_WEIGHT.get(str(chal.get("category") or ""), 0)
    solves = int(chal.get("solves_count") or 0)
    score += _SOLVABLE_BONUS if solves > 0 else _UNSOLVED_PENALTY
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
        if int(rec.get("fails") or 0) >= max_failures:
            rec["status"] = DEFERRED
            rec["solves_count_seen"] = int(chal.get("solves_count") or 0)
            notes.append(f"{cid}: 连败 {max_failures} 次→deferred")
            continue
        if int(rec.get("skips") or 0) >= max_failures:
            # B-23：连续基础设施跳过同样 defer——重派不产生任何新信息，
            # 只烧实例启动开销。他队解出数跳变仍可唤醒（与连败 defer 同门）。
            rec["status"] = DEFERRED
            rec["solves_count_seen"] = int(chal.get("solves_count") or 0)
            notes.append(f"{cid}: infra-skip 连续 {max_failures} 次→deferred")
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


def fetch_challenges(token: str, cid: str, timeout: int = 30) -> list[dict[str, Any]]:
    """拉全量题表（分页 dict → items 列表）。失败抛异常，由主循环兜。"""
    r = requests.get(
        f"{PLATFORM}/api/v1/competitions/{cid}/challenges",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    items = data.get("items") if isinstance(data, dict) else data
    return [c for c in (items or []) if isinstance(c, dict)]


def fetch_scoreboard(token: str, cid: str, timeout: int = 30) -> dict[str, Any]:
    """拉实时榜（我们排名 + 花费，供 digest 与决策记录）。"""
    r = requests.get(
        f"{PLATFORM}/api/v1/competitions/{cid}/scoreboard",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


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


def read_last_result(state_dir: Path, cid: str) -> dict[str, Any] | None:
    """读 batch_eval 给这题追加的最后一条 jsonl 记录（判成败的唯一依据）。"""
    p = state_dir / "runs" / f"{cid}.jsonl"
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
    if allow_pools:
        # 练习场自测专用：SAMPLE-* 在封存/烧毁池里，不显式放行 batch_eval
        # 会直接拒跑。正式赛题不在 pools.json，不受影响。
        item["allow_burned"] = True
        item["allow_sealed"] = True
    return item


def _spawn(
    chal: dict[str, Any], args: argparse.Namespace, state_dir: Path
) -> subprocess.Popen:
    """派一个 batch_eval 子进程跑单题（agent 上下文从零开始）。"""
    cid = str(chal["id"])
    runs = state_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    plan = runs / f"plan-{cid}.json"
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
        str(runs / f"{cid}.jsonl"),
        "--token",
        args.token,
    ]
    if args.competition:
        cmd += ["--competition-id", args.competition]
    log = open(runs / f"{cid}.stdout.log", "a", encoding="utf-8")
    return subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)


def _collect(
    cid: str, state: dict[str, Any], state_dir: Path
) -> str:
    """子进程退出后收账：以 jsonl 最后一条记录为准（不信退出码，冒烟 #8）。"""
    rec = read_last_result(state_dir, cid) or {}
    state_rec = state.setdefault(cid, {})
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
    else:
        status = FAILED
        state_rec["fails"] = int(state_rec.get("fails") or 0) + 1
        # 真跑了一次（哪怕失败）说明接入已恢复，skip 连击清零。
        state_rec["skips"] = 0
    state_rec["status"] = status
    return status


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--token", required=True)
    p.add_argument("--competition", required=True, help="competition id")
    p.add_argument("--state-dir", default="~/compete-state")
    p.add_argument("--lanes", type=int, default=3, help="并发车道（平台配额 3）")
    p.add_argument("--turns", type=int, default=25)
    p.add_argument("--wallclock", type=int, default=900)
    p.add_argument("--until", default="", help="ISO 时间，到点收工（空=一直跑）")
    p.add_argument("--dry-run", action="store_true", help="只打印队列，不派单")
    p.add_argument("--once", action="store_true", help="排一轮队跑完就退出（冒烟用）")
    p.add_argument("--poll", type=float, default=10.0, help="车道轮询间隔（秒）")
    p.add_argument(
        "--allow-pools",
        action="store_true",
        help="放行封存/烧毁池的题（仅练习场自测；正式赛不要用）",
    )
    args = p.parse_args()

    state_dir = Path(args.state_dir).expanduser()
    state = load_state(state_dir)
    # 崩溃恢复：上一进程没来得及收车的 RUNNING 是孤儿（新进程此刻还没派
    # 任何单），不复位的话这些题会被 rank_queue 永久跳过。
    for _rec in state.values():
        if _rec.get("status") == RUNNING:
            _rec["status"] = ACTIVE
            _rec["one_line"] = "orphaned run reset"
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
    stop = False
    last_solve_sync = 0.0

    def _sigint(_sig, _frm):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _sigint)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sigint)

    deadline = None
    if args.until:
        from datetime import datetime
        deadline = datetime.fromisoformat(args.until).timestamp()

    while not stop:
        if deadline_reached(deadline):
            print("[compete] 到 --until，收工", flush=True)
            break
        try:
            challenges = fetch_challenges(args.token, args.competition)
        except Exception as exc:  # noqa: BLE001
            print(f"[compete] 题表拉取失败：{exc}，{args.poll}s 后重试", flush=True)
            time.sleep(args.poll)
            continue
        # 刷新：新题自动入账；已解出（别处补交成功等）从 run 态摘除。
        for chal in challenges:
            cid = str(chal.get("id") or "")
            if cid and cid not in state:
                state[cid] = {
                    "status": ACTIVE,
                    "runs": 0,
                    "fails": 0,
                    "solves_count_seen": int(chal.get("solves_count") or 0),
                    "one_line": "",
                }
        if time.time() - last_solve_sync >= 60:
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
        queue, notes = rank_queue(challenges, state, my_solved)
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
        while len(running) < args.lanes and queue:
            chal = queue.pop(0)
            cid = str(chal["id"])
            state.setdefault(cid, {})["status"] = RUNNING
            running[cid] = _spawn(chal, args, state_dir)
            print(
                f"[compete] 派单 {cid}（{len(running)}/{args.lanes} 车道）",
                flush=True,
            )
        save_state(state_dir, state)
        if not running:
            if args.once:
                print("[compete] --once：队列跑完，退出", flush=True)
                return 0
            print(
                f"[compete] 队列空（无可跑题），{args.poll}s 后重刷题表",
                flush=True,
            )
            time.sleep(args.poll)
            continue
        # 等任一车道退出
        while running and not stop:
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
                status = _collect(cid, state, state_dir)
                if status == SOLVED:
                    my_solved.add(cid)
                save_state(state_dir, state)
                print(f"[compete] {cid} 收车：{status}", flush=True)
                break
        if stop:
            print("[compete] 收到停止信号，杀掉在跑车道…", flush=True)
            for cid, proc in running.items():
                proc.terminate()
            for cid, proc in running.items():
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
            save_state(state_dir, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
