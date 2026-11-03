# -*- coding: utf-8 -*-
"""容器路径墙钟兜底的单元测试。

背景（接线修复）：时间限制此前只在评测 harness（``batch_eval.py``，进程组
SIGKILL）里生效；正式赛/部署验证赛的入口 ``agent.py`` 没有任何墙钟。本文件
锁住三层行为：预算解析、看门狗本身、以及异常类型必须穿透 ``except Exception``。
"""

import json
import os
import signal
import time

import pytest

from ctf_strix import agent


def test_wall_budget_env_overrides_tiers(monkeypatch):
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "123")
    assert agent._wall_budget({"challenge": {"difficulty": "easy"}}) == 123


def test_wall_budget_env_zero_disables(monkeypatch):
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    assert agent._wall_budget({"challenge": {"difficulty": "hard"}}) == 0


def test_wall_budget_env_garbage_disables_not_crashes(monkeypatch):
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "soon")
    assert agent._wall_budget({}) == 0


def test_wall_budget_tiers_match_harness(monkeypatch):
    """容器侧分层必须与 batch_eval 的难度分层同源，不允许漂移。"""
    monkeypatch.delenv("CTFY_WALL_DEADLINE", raising=False)
    assert agent._wall_budget({"challenge": {"difficulty": "easy"}}) == 600
    assert agent._wall_budget({"challenge": {"difficulty": "medium"}}) == 900
    assert agent._wall_budget({"challenge": {"difficulty": "hard"}}) == 1380


def test_wall_budget_unknown_difficulty_uses_hard_tier(monkeypatch):
    """task.json 不带难度（协议示例就没有）时取 hard 档，而不是 0。"""
    monkeypatch.delenv("CTFY_WALL_DEADLINE", raising=False)
    assert agent._wall_budget({}) == 1380
    assert agent._wall_budget({"challenge": {}}) == 1380
    assert agent._wall_budget({"challenge": {"difficulty": "impossible"}}) == 1380


def test_wall_budget_env_unset_in_fresh_container(monkeypatch):
    monkeypatch.delenv("CTFY_WALL_DEADLINE", raising=False)
    assert agent._wall_budget({"challenge": {"difficulty": "medium"}}) > 0


def test_wallclock_exception_survives_except_exception():
    """它必须穿透 strix 内部所有 ``except Exception``——这是继承
    BaseException 的全部理由；退化成 Exception 子类等于看门狗失效。"""
    with pytest.raises(agent.WallclockExceeded):
        try:
            raise agent.WallclockExceeded("boom")
        except Exception:
            pytest.fail("WallclockExceeded must not be an Exception subclass")


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="POSIX only")
def test_hard_deadline_non_positive_not_installed():
    assert agent._install_hard_deadline(0) is False
    assert agent._install_hard_deadline(-5) is False


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="POSIX only")
def test_hard_deadline_fires_then_cancel_is_safe():
    assert agent._install_hard_deadline(1) is True
    with pytest.raises(agent.WallclockExceeded):
        time.sleep(3)
    # 已响过的 alarm 再撤一次不能抛——finally 收尾路径会无条件调用它。
    agent._cancel_hard_deadline()


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="POSIX only")
def test_cancel_hard_deadline_without_install_is_safe():
    # 从未装过看门狗（Windows / 非主线程）时调用必须是无害 no-op。
    agent._cancel_hard_deadline()


def test_main_turns_wallclock_into_result_file(tmp_path, monkeypatch):
    """端到端：看门狗到点后 main 必须把已跑部分写成 result.json，
    stop_reason 用 "wallclock" 而不是 "error"（两者在根因分析里是两回事）。"""
    (tmp_path / "task.json").write_text(
        json.dumps(
            {
                "run_mode": "instance",
                "challenge": {"id": "X", "name": "x", "description": ""},
                "questions": [{"id": "flag", "prompt": "p"}],
                "target_endpoints": [
                    {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
                ],
                "result": {"path": str(tmp_path / "result.json")},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "60")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    # main() 会 setdefault CTFY_SOFT_DEADLINE；monkeypatch 管不到被测代码自己
    # 写的 env，不清理会污染后面统计工具面的测试（实测 6 连挂）。
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)

    def _hang(*args, **kwargs):
        raise agent.WallclockExceeded("wall budget 60s spent")

    monkeypatch.setattr(agent, "_run_agent", _hang)
    try:
        assert agent.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "wallclock"
        assert payload["schema_version"] == agent.BRIEF_SCHEMA_VERSION
    finally:
        os.environ.pop("CTFY_SOFT_DEADLINE", None)
