"""多车道竞速（先解先停）：跨进程胜局标记 + 事件汇点自停。

覆盖三件事：
1. **标记协议**：原子写（不留 ``.tmp``）、可读回（lane/won_at）、空目录
   no-op——「没配就是没有这个机制」是单进程跑批的兼容底线。
2. **观察器**：命中即闩锁（之后不碰文件系统）、节流窗口内不重复 stat。
3. **agent 接线**：``_check_race_lost`` 在观察器命中时抛
   :class:`RaceLost`（BaseException，绕过 ``except Exception`` 的吞没），
   未配置时是纯 no-op；``RaceLost`` 在 ``_STOP_TYPES`` 里，收尾统计
   挂得上。

不测「真实兄弟进程互相停」：那是两条 batch 进程 + 共享目录的集成行为，
单元层只锁协议形状。批跑侧的派单跳过/胜局广播在 ``batch_eval`` 的
主循环里，与既有 SKIPPED 行同款口径，由冒烟批覆盖。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402

from ctf_strix import agent as agent_mod
from ctf_strix import race_stop
from ctf_strix.race_stop import RaceLost


@pytest.fixture(autouse=True)
def _clean_watcher():
    """每个测试前后都清掉进程级观察器（测试进程会跑多个「run」）。"""
    race_stop.reset()
    yield
    race_stop.reset()


@pytest.fixture
def race_dir(tmp_path, monkeypatch):
    """配好 CTF_RACE_* 环境的共享目录。"""
    d = tmp_path / "race"
    monkeypatch.setenv("CTF_RACE_DIR", str(d))
    monkeypatch.setenv("CTF_RACE_LANE", "test-lane")
    monkeypatch.setenv("CTF_RACE_CHALLENGE", "RACE-001")
    return d


class TestMarker:
    def test_record_then_read(self, race_dir):
        assert race_stop.record_win(str(race_dir), "RACE-001", lane="lane-a")
        won = race_stop.read_win(str(race_dir), "RACE-001")
        assert won is not None
        assert won["challenge"] == "RACE-001"
        assert won["lane"] == "lane-a"
        assert won["won_at"] > 0

    def test_is_won_false_without_marker(self, race_dir):
        assert race_stop.is_won(str(race_dir), "RACE-001") is False

    def test_atomic_no_tmp_residue(self, race_dir):
        race_stop.record_win(str(race_dir), "RACE-001")
        leftovers = [p for p in os.listdir(race_dir) if p.endswith(".tmp")]
        assert leftovers == []

    def test_challenge_ids_with_path_chars(self, race_dir):
        """题号里的 ``/`` 折叠成下划线：标记留在 race 目录内，不越界。"""
        race_stop.record_win(str(race_dir), "a/b../../c", lane="x")
        assert race_stop.is_won(str(race_dir), "a/b../../c") is True
        files = [p.name for p in race_dir.iterdir()]
        assert all(name.startswith("win-") for name in files)
        assert not os.path.exists(os.path.join(str(race_dir), "c"))

    def test_empty_inputs_are_noop(self, tmp_path):
        assert race_stop.record_win("", "X") is False
        assert race_stop.record_win(str(tmp_path), "") is False
        assert race_stop.read_win("", "X") is None
        assert race_stop.is_won(str(tmp_path), "X") is False

    def test_corrupt_marker_counts_as_not_won(self, race_dir):
        """坏文件宁可不跳：把可跑的题误判成已解，代价是整道题的配额。"""
        path = race_dir / "win-RACE-001.json"
        race_dir.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        assert race_stop.is_won(str(race_dir), "RACE-001") is False


class TestWatcher:
    def test_configure_from_env(self, race_dir):
        w = race_stop.configure()
        assert w is not None
        assert w.challenge_id == "RACE-001"
        assert w.lane == "test-lane"

    def test_unconfigured_when_no_env(self, monkeypatch):
        for key in ("CTF_RACE_DIR", "CTF_RACE_CHALLENGE", "CTF_RACE_LANE"):
            monkeypatch.delenv(key, raising=False)
        assert race_stop.configure() is None
        assert race_stop.watcher() is None

    def test_missing_challenge_alone_is_not_enough(self, monkeypatch, tmp_path):
        """有目录没题号照样关：观察器不知道自己跑的是哪道题。"""
        monkeypatch.setenv("CTF_RACE_DIR", str(tmp_path))
        monkeypatch.delenv("CTF_RACE_CHALLENGE", raising=False)
        assert race_stop.configure() is None

    def test_poll_latches_on_marker(self, race_dir, monkeypatch):
        # 节流间隔清零：闩锁语义与节流语义分开验（节流单测见下）。
        monkeypatch.setattr(race_stop, "_POLL_INTERVAL_S", 0.0)
        w = race_stop.configure()
        assert w is not None
        assert w.poll() is False
        race_stop.record_win(str(race_dir), "RACE-001")
        assert w.poll() is True
        # 闩锁：标记删掉之后也保持「该停了」，不再碰文件系统。
        os.remove(next(race_dir.glob("win-*.json")))
        assert w.poll() is True

    def test_poll_throttles_when_quiet(self, race_dir):
        w = race_stop.configure()
        assert w is not None
        assert w.poll() is False
        # 节流窗口内的第二次 poll 不 stat：用「标记刚落盘也看不见」来
        # 证明这一次确实没有碰文件系统。
        race_stop.record_win(str(race_dir), "RACE-001")
        assert w.poll() is False


class TestAgentWiring:
    def test_checkpoint_raises_when_won(self, race_dir):
        race_stop.configure()
        race_stop.record_win(str(race_dir), "RACE-001")
        with pytest.raises(RaceLost):
            agent_mod._check_race_lost()

    def test_checkpoint_noop_when_unconfigured(self, race_dir):
        race_stop.reset()
        race_stop.record_win(str(race_dir), "RACE-001")
        agent_mod._check_race_lost()  # 不抛即通过

    def test_racelost_is_base_exception(self):
        """普通异常会被 strix 的 except Exception 吞成工具错误继续烧预算。"""
        assert issubclass(RaceLost, BaseException)
        assert not issubclass(RaceLost, Exception)

    def test_racelost_in_stop_types(self):
        assert RaceLost in agent_mod._STOP_TYPES

    def test_stop_state_attaches_to_racelost(self):
        """收尾统计沿 _attach_stop_state 挂载，result.json 不丢轮次。"""
        exc = RaceLost("another lane solved it")
        agent_mod._attach_stop_state(exc, 7, {"race": {"lane": "b"}})
        assert agent_mod._take_stop_state(exc) == (7, {"race": {"lane": "b"}})

    def test_marker_payload_has_no_secrets(self, race_dir):
        """标记会留在共享目录里被别的进程读：只允许题号/车道/时刻。"""
        race_stop.record_win(str(race_dir), "RACE-001", lane="lane-a")
        blob = next(race_dir.glob("win-*.json")).read_text(encoding="utf-8")
        data = json.loads(blob)
        assert set(data) == {"challenge", "lane", "won_at"}


class TestBatchPlumbing:
    """子进程 env 白名单必须真转发（test_ab_switch_plumbing 同款盲区）。

    历史事故三起：CTF_ALLOW_SUBAGENTS / CTF_RECOVERY_NOTICE /
    CTF_CARDS_OFF 都曾因白名单漏转发让 A/B 两臂实际是同一臂。这里的
    三个键漏任何一个，车道就是聋的——agent 进程永远看不到 race 目录。
    """

    def test_env_whitelist_forwards_race_vars(self, monkeypatch, tmp_path):
        seen: dict = {}

        class _Proc:
            returncode = 0

            def wait(self, timeout=None):
                return 0

        def fake_popen(argv, **kwargs):
            seen["env"] = kwargs.get("env") or {}
            return _Proc()

        monkeypatch.setattr(batch_eval.subprocess, "Popen", fake_popen)
        monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(tmp_path))
        monkeypatch.setattr(batch_eval, "_private_tmp_available", lambda: False)
        monkeypatch.setenv("CTF_RACE_DIR", str(tmp_path / "race"))
        monkeypatch.setenv("CTF_RACE_LANE", "plumbing-probe")
        monkeypatch.delenv("CTF_RACE_CHALLENGE", raising=False)

        batch_eval.run_agent(
            "http://127.0.0.1:1", 5, 60, "T-RACE",
            extra="x", challenge_id="RACE-001",
        )
        env = seen["env"]
        assert env.get("CTF_RACE_DIR") == str(tmp_path / "race")
        assert env.get("CTF_RACE_LANE") == "plumbing-probe"
        # 题号由 run_agent 显式递，优先于外层环境：子进程不依赖 task 形状。
        assert env.get("CTF_RACE_CHALLENGE") == "RACE-001"
