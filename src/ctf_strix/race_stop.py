"""进程间「先解先停」竞速广播。

多车道 = 多个 ``batch_eval`` 进程，各带一家厂商的模型端点，共享同一个
race 目录（``CTF_RACE_DIR``）。语义只有两条：

1. **胜局标记**：一条车道拿到**平台验证过的**正确裁决后，把
   ``win-<challenge>.json`` 原子落盘（tmp + ``os.replace``，与
   ``guard_state`` 同一纪律）。
2. **败方自停**：同题的其它车道在自己的事件汇点（``agent.py`` 的 sink，
   每个 run 最频繁的主线程检查点）发现标记即抛 :class:`RaceLost`，沿
   ``main`` 现成的「止损异常 → stop_reason」管线收尾（``race_lost``）。
   父进程派单前也查一次标记：已解出的题直接记 skip，不再烧实例配额。

只认平台验证的胜局，不认模型自报的 flag 串：单题 autosubmit 假阳性有
16 条前科（台账 §4.252），自报信号会把三条车道一起带沟里。所以标记的
写入点在 ``batch_eval`` 的跑后裁决（``client.submit`` 的 verdict 与
autosubmit sidecar 合并之后），不在 agent 侧。

**默认关闭**：未设 ``CTF_RACE_DIR`` 时所有入口为 no-op，单进程行为零
变化——单测与既有跑批不需要知道这个机制存在。

为什么不复用 ``parallel.py``：那是**进程内**子 agent 协议，靠
``AgentCoordinator`` 停孩子；车道是独立 OS 进程，互相之间唯一共享的
就是一个文件系统。跨进程杀兄弟进程在 §4.113 已被证伪（旧
``reap_orphans`` 按全账号清理互杀兄弟车道实例）——合作式自停是唯一
不越所有权边界的停法。
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

#: 题号里不允许进文件名的字符（如 ``/``、空格）统一折叠成下划线。
#: 压缩发生在文件名上，标记内容里保留原题号。
_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_.-]+")

#: 事件汇点每次都会调用 ``poll``；一次 ``stat`` 很便宜，但没必要每条
#: 事件都打——标记从落盘到被发现本来就有一个轮次的容忍窗。
_POLL_INTERVAL_S = 1.0


class RaceLost(BaseException):
    """另一条车道已用平台验证的提交解出本题，本车道停止。

    故意继承 ``BaseException``：与其它止损异常同一理由——strix 与本模块
    内部到处是 ``except Exception``，普通异常会被吞成一条工具错误然后
    继续烧预算。必须直达 ``main`` 的收尾，让 finally 把 result.json
    写出来。
    """


def _marker_path(race_dir: str, challenge_id: str) -> str:
    """胜局标记的路径：``<race_dir>/win-<sanitized challenge>.json``。"""
    safe = _SANITIZE_RE.sub("_", str(challenge_id)).strip("_") or "unknown"
    return os.path.join(race_dir, f"win-{safe}.json")


def record_win(race_dir: str, challenge_id: str, *, lane: str = "") -> bool:
    """落一个胜局标记。返回是否真的写了。

    原子写：先写 ``.tmp`` 再 ``os.replace``，兄弟车道只会看到完整 JSON
    或什么都没有，不会读到半截文件。目录不存在则建（车道们对同一目录
    并发 ``makedirs(exist_ok=True)`` 是安全的）。

    写失败不能拖垮已经解出的题，所以吞 ``OSError`` 并返回 False。
    """
    if not str(race_dir or "").strip() or not str(challenge_id or "").strip():
        return False
    path = _marker_path(str(race_dir).strip(), challenge_id)
    payload = {
        "challenge": str(challenge_id),
        "lane": str(lane or ""),
        "won_at": round(time.time(), 1),
    }
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        logger.warning("race_stop: marker write failed for %s", challenge_id)
        return False
    return True


def read_win(race_dir: str, challenge_id: str) -> dict[str, Any] | None:
    """读回一个胜局标记（lane / won_at），没有时返回 ``None``。

    供派单侧把「谁解的」写进 skip 行，供报表区分车道。读失败按
    「没有标记」处理——宁可不跳，也不能把可跑的题误判成已解。
    """
    if not str(race_dir or "").strip() or not str(challenge_id or "").strip():
        return None
    try:
        with open(_marker_path(race_dir, challenge_id), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def is_won(race_dir: str, challenge_id: str) -> bool:
    """这道题是否已有车道解出（派单前的跳过判据）。"""
    return read_win(race_dir, challenge_id) is not None


class _Watcher:
    """agent 进程内对「本题是否已被别人解出」的节流轮询。

    一次锁只做一件事：取节流时间戳或闩锁状态；``stat`` 在锁外。
    命中即闩锁——标记只删不添（手动清理 race 目录除外），闩住之后
    每次事件汇点都直说「该停了」，不再碰文件系统。
    """

    def __init__(self, race_dir: str, challenge_id: str, lane: str) -> None:
        self.race_dir = race_dir
        self.challenge_id = challenge_id
        self.lane = lane
        self._path = _marker_path(race_dir, challenge_id)
        self._lock = threading.Lock()
        self._latched = False
        self._next_poll = 0.0

    def poll(self) -> bool:
        now = time.monotonic()
        with self._lock:
            if self._latched:
                return True
            if now < self._next_poll:
                return False
            self._next_poll = now + _POLL_INTERVAL_S
        try:
            if not os.path.exists(self._path):
                return False
        except OSError:
            return False
        with self._lock:
            self._latched = True
        return True

    def describe(self) -> dict[str, Any]:
        """诊断摘要（进 result.json 的 ``race`` 字段，无敏感信息）。"""
        return {
            "enabled": True,
            "lane": self.lane,
            "latched": self._latched,
        }


_WATCHER: _Watcher | None = None


def configure(
    race_dir: str | None = None,
    challenge_id: str | None = None,
    lane: str | None = None,
) -> _Watcher | None:
    """为本进程的这一次 run 装上竞速观察器。

    参数缺省时从环境读（``CTF_RACE_DIR`` / ``CTF_RACE_CHALLENGE`` /
    ``CTF_RACE_LANE``）——batch 的子进程 env 是白名单，环境是父进程
    唯一能递进来又不进 argv 的通道（argv 会进 ps 输出与归档日志）。
    没设 ``CTF_RACE_DIR`` 返回 ``None``：机制关闭。
    """
    global _WATCHER
    race = str(race_dir if race_dir is not None else os.environ.get("CTF_RACE_DIR", "")).strip()
    challenge = str(
        challenge_id if challenge_id is not None else os.environ.get("CTF_RACE_CHALLENGE", "")
    ).strip()
    lane_id = str(lane if lane is not None else os.environ.get("CTF_RACE_LANE", "")).strip()
    if not race or not challenge:
        _WATCHER = None
        return None
    _WATCHER = _Watcher(race, challenge, lane_id)
    return _WATCHER


def reset() -> None:
    """清掉进程级观察器（测试与嵌入式调用者的隔离）。"""
    global _WATCHER
    _WATCHER = None


def watcher() -> _Watcher | None:
    """当前观察器（``None`` = 竞速关闭）。"""
    return _WATCHER


def checkpoint() -> None:
    """事件汇点调用：发现胜局标记即抛 :class:`RaceLost`。

    与 ``_check_soft_timeout`` 同一挂点同一形态——这是 run 里最频繁的
    主线程检查点，墙钟路径已经证明异常能从这里直达 ``main`` 的收尾。
    """
    current = _WATCHER
    if current is not None and current.poll():
        raise RaceLost(
            "another lane solved this challenge with a platform-verified "
            f"submission (lane marker in {current.race_dir})"
        )
