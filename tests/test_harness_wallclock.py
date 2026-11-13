# -*- coding: utf-8 -*-
"""harness 时钟同源（B-2/P0#6/DEF-9）+ 跑批 rec 缺键（DEF-13）的接线钉。

背景：``run_strix_ctf.py`` 此前只有软截止注入，没有进程内硬墙钟——父进程
（eval_sample / batch_eval）到点整组杀，被杀的那次 run 收尾行全丢、归因靠
猜。现在复用 ``agent.main`` 的两级 watchdog：软阶段在 sink 检查点抛
``WallclockExceeded``（正常收尾、exit 0、[stop] reason=wallclock），硬阶段
daemon 兜底 ``os._exit(0)``。预算 = 父进程墙钟 - 启动耗时 - headroom。

本文件两类用例：
1. 接线钉（source-shape）：harness 的五处接线一处都不能少——这类收尾路径
   单测驱动不了（要把整个 scan 跑到墙钟耗尽），钉源码形状是当前可行的
   最强验证；
2. 函数级：``_parse_usage`` 契约、``_stop_reason_of`` 对 wallclock 干净
   收场的归因与不重开。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402
from ctf_strix import agent  # noqa: E402

RUN_SRC = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
BE_SRC = (ROOT / "scripts" / "batch_eval.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------- 接线钉
def test_hard_watchdog_install_is_sourced_from_agent() -> None:
    """安装必须复用 agent 侧实现（同源），预算按进程启动时刻扣减。"""
    assert "agent_mod._install_hard_deadline(" in RUN_SRC
    assert "result_path=None" in RUN_SRC
    # 预算三项：父墙钟 - 启动耗时 - agent 同一 headroom 常量。
    assert "int(args.wall_deadline)" in RUN_SRC
    assert "_since_start" in RUN_SRC
    assert "agent_mod.DEADLINE_HEADROOM_SECONDS" in RUN_SRC
    # watchdog 只在给了墙钟时装，缺省（0）不装也不能 NameError。
    assert "if args.wall_deadline > 0:" in RUN_SRC


def test_headroom_exceeds_daemon_reserve() -> None:
    """软着陆必须抢在 daemon 硬退（预算+保留）之前、且都在父进程杀线内。

    headroom（45）> WALL_RESERVE_SECONDS（20）是这条不等式的硬前提——
    headroom 若小于 daemon 保留，预算+保留会越过父墙钟，收场权又还给
    父进程的整组杀，改动失效。
    """
    assert agent.DEADLINE_HEADROOM_SECONDS > 20.0


def test_sink_is_the_soft_checkpoint() -> None:
    """事件回调是主线程最频繁的检查点：挂起协程上的 SIGALRM 只剩旗子。"""
    sink_pos = RUN_SRC.index("    def sink(agent_id: str, event: object) -> None:")
    check_pos = RUN_SRC.index("agent_mod._check_soft_timeout()")
    assert sink_pos < check_pos < RUN_SRC.index("scan_id = args.name")


def test_wallclock_landing_is_caught_and_classified() -> None:
    """软着陆要翻成机器可读行 + exit 0，且接在 except Exception 之前。"""
    wc_pos = RUN_SRC.index("    except agent_mod.WallclockExceeded as exc:")
    guard_pos = RUN_SRC.index("    except (NoProgress, EnumExhausted, TargetAbsent)")
    generic_pos = RUN_SRC.index("    except Exception as exc:")
    assert wc_pos < guard_pos < generic_pos
    tail = RUN_SRC[wc_pos : RUN_SRC.index("    except (NoProgress", wc_pos)]
    assert "[stop] reason=wallclock" in tail


def test_watchdog_disarmed_before_summary_prints() -> None:
    """收尾汇总前解除（agent.main 同款顺序），且解除无条件安全。"""
    cancel_pos = RUN_SRC.index("agent_mod._cancel_hard_deadline()")
    elapsed_pos = RUN_SRC.index("    elapsed = time.time() - started")
    assert cancel_pos < elapsed_pos


def test_asyncio_escape_has_last_resort_net() -> None:
    """SIGALRM 打在挂起协程上时异常从 asyncio.run 逃逸——尾部必须接住。"""
    tail = RUN_SRC[RUN_SRC.index('if __name__ == "__main__":') :]
    assert "asyncio.run(main())" in tail
    assert "except _WallclockExceeded" in tail
    assert "[stop] reason=wallclock" in tail
    assert "_exit_code = 0" in tail


def test_batch_eval_rec_gains_usage_and_clean_landing() -> None:
    """DEF-13：跑批结果行要有 token 用量；干净墙钟收场计入命中。"""
    assert 'rec["usage"] = _parse_usage(log)' in BE_SRC
    assert '"[stop] reason=wallclock" in log' in BE_SRC


# --------------------------------------------------------------- 函数级
def test_parse_usage_reads_regular_and_final_lines() -> None:
    log = "noise\n[usage] calls=2 in=100 out=20 total=120\n"
    assert batch_eval._parse_usage(log) == {
        "llm_calls": 2,
        "input_tokens": 100,
        "output_tokens": 20,
        "total_tokens": 120,
    }
    final = "[usage-final] calls=3 in=9 out=1 total=10"
    assert batch_eval._parse_usage(final)["llm_calls"] == 3


def test_parse_usage_missing_line_gives_zeros() -> None:
    assert batch_eval._parse_usage("no marker here") == {
        "llm_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    }


def test_parse_usage_final_line_wins_over_regular() -> None:
    log = (
        "[usage] calls=1 in=1 out=1 total=3\n"
        "[usage-final] calls=7 in=70 out=7 total=77\n"
    )
    assert batch_eval._parse_usage(log)["llm_calls"] == 7


def test_stop_reason_wallclock_landing_is_machine_readable() -> None:
    """干净收场行必须被归因为 wallclock（而不是 unknown/error）。"""
    log = (
        "[stopped] WallclockExceeded: wall budget 435s spent\n"
        "[stop] reason=wallclock\n"
    )
    assert batch_eval._stop_reason_of(log) == "wallclock"


def test_wallclock_reason_is_not_resampled() -> None:
    """预算问题重开只是重复烧钱——不许进重开集合。"""
    assert batch_eval._resample_allowed("wallclock") is False
