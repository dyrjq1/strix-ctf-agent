"""接线批 2026-11-12：崩溃观测通道 + harness 轮次预算挂载。

三件事，全是"观测/收敛通道接线"，不碰解题行为：
1. ``batch_eval._crash_error``：子进程崩溃标记 → 结果表 error 字段；
2. ``run_strix_ctf.py``：turn_budget 必须在 deadline 守卫之后安装，
   且挂载断言（verify_mount）必须把轮次守卫的标记算进去；
3. ``run_strix_ctf.py`` 异常收场必须打机器可读的 ``[run-error]`` 行。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402

HARNESS = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------- 传输分类
def test_transport_classification():
    assert batch_eval._is_transport_error("httpx._exceptions.ReadError")
    assert batch_eval._is_transport_error("httpcore._exceptions.RemoteProtocolError")
    assert batch_eval._is_transport_error("openai.APIConnectionError")
    assert batch_eval._is_transport_error("litellm.exceptions.TimeoutError")
    assert batch_eval._is_transport_error("ConnectionResetError")
    assert batch_eval._is_transport_error("ssl.SSLError")
    # 非传输层
    assert not batch_eval._is_transport_error("ValueError")
    assert not batch_eval._is_transport_error("KeyError")
    assert not batch_eval._is_transport_error("agents.exceptions.MaxTurnsExceeded")


# ---------------------------------------------------------------- 崩溃标记解析
def test_crash_error_transport():
    log = (
        "[scan] ...\n[stopped] ReadError: Peer closed connection\n"
        "[run-error] httpx._exceptions.ReadError: Peer closed connection\n"
        "[done] 120.0s result=None\n"
    )
    err, detail = batch_eval._crash_error(log)
    assert err == "transport:httpx._exceptions.ReadError"
    assert detail == "Peer closed connection"


def test_crash_error_non_transport():
    err, _ = batch_eval._crash_error(
        "[run-error] builtins.ValueError: bad config\n"
    )
    assert err == "crash:builtins.ValueError"


def test_crash_error_turn_cap_is_not_a_crash():
    log = (
        "[stopped] MaxTurnsExceeded: 40 turns\n"
        "[run-error] agents.exceptions.MaxTurnsExceeded: 40 turns\n"
    )
    assert batch_eval._crash_error(log) is None


def test_crash_error_agent_exit():
    err, detail = batch_eval._crash_error("[agent-exit] rc=-9\n")
    assert err == "agent-exit:rc-9"
    assert detail == ""


def test_crash_error_none_when_clean():
    assert batch_eval._crash_error("[done] 60.0s result=ScanResult\n") is None


def test_run_error_line_is_multiline_anchored():
    """agent cat 自己源码时引号里会出现 [run-error] 字样——不在行首不算。"""
    log = 'x = "print(\'[run-error] httpx.ReadError: fake\')"\n[done] ok\n'
    assert batch_eval._crash_error(log) is None


# ---------------------------------------------------------------- harness 挂载顺序
def test_harness_installs_turn_budget_after_deadline():
    """两者替换同一个 ``factory._with_bounded_result``，后装的在外层。

    顺序倒了，[TURN BUDGET] 提示会被 [SOFT DEADLINE] 盖住（离决策更远）。
    """
    m_deadline = HARNESS.index("install_deadline_guard(")
    m_budget = HARNESS.index("turn_budget_mod.install()")
    assert m_budget > m_deadline


def test_harness_mount_assertion_includes_turn_budget():
    m_budget = HARNESS.index("turn_budget_mod.install()")
    m_verify = HARNESS.index("verify_mount(")
    assert m_verify > m_budget, "verify_mount 必须在 turn_budget 安装之后"
    tuple_text = HARNESS[m_verify : HARNESS.index(")", m_verify) + 1]
    assert "_ctf_turn_budget" in tuple_text


def test_harness_emits_machine_readable_run_error():
    assert '"[run-error]' in HARNESS or "'[run-error]" in HARNESS
    assert "type(exc).__module__" in HARNESS


def test_harness_budget_reset_uses_cli_turns():
    m_install = HARNESS.index("turn_budget_mod.install()")
    m_reset = HARNESS.index("tb_guard.reset(args.turns)")
    assert m_reset > m_install


# ---------------------------------------------------------------- 行为：真挂载链
def test_turn_budget_mark_reaches_exec_command():
    """按 harness 同序装链后，verify_mount 必须认出轮次守卫标记。"""
    from strix.agents import factory

    from ctf_strix import deadline_guard, guard_mount, turn_budget

    guard_mount.install_mount_hook()
    deadline_guard.install(
        deadline_guard.DeadlineGuard(wall=100, soft=75, turns=10)
    )
    guard = turn_budget.install()
    guard.reset(10)
    # 本测试只装了 mount hook + deadline + turn_budget，没装枚举/旅程/
    # 扫描/否定守卫——那些标记不存在，verify_mount 传参允许按需放宽。
    # 这里要证明的是：轮次守卫的标记经真实配置路径落到了探针工具上。
    assert guard_mount.verify_mount(("_ctf_turn_budget",)), (
        getattr(factory, "_ctf_mounted", False)
    )
