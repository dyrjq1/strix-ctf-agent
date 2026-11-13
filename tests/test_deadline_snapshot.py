"""Regression: `snapshot()` must not deadlock on the guard lock.

On 2026-10-31 the 074/GLM arm printed `[usage]` at 218.9s and then hung on the
next line -- `[deadline] ...` -- until the parent SIGKILLed it at 600s.
Root cause: `snapshot()` held `self._lock` and then called a verdict helper
(the old `should_kill()`) that acquired the same non-reentrant
`threading.Lock` again. Every finished run
therefore idled ~400s before dying, and its result was recorded as a wall-clock
timeout instead of a solve.

These tests run the snapshot in a worker thread so a regression fails in 5s
instead of hanging the suite.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.deadline_guard import DeadlineGuard  # noqa: E402


def _guard() -> DeadlineGuard:
    return DeadlineGuard(wall=600, soft=450, turns=30)


def _call_with_deadline(fn, seconds: float = 5.0):
    """Run `fn` in a thread; return its result or raise on timeout."""
    box: dict = {}

    def runner() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        raise AssertionError("call did not return within %.1fs (deadlock?)" % seconds)
    if "error" in box:
        raise box["error"]
    return box["value"]


def test_snapshot_returns_after_tool_activity():
    guard = _guard()
    guard.observe("GET / -> 200")

    snap = _call_with_deadline(guard.snapshot)

    assert snap["tool_calls"] == 1
    assert snap["soft_hit"] is False


def test_snapshot_returns_on_a_fresh_guard():
    """No activity at all: still must not deadlock."""
    assert _call_with_deadline(_guard().snapshot)["tool_calls"] == 0


def test_snapshot_after_soft_deadline_injected():
    """The real 074 path: soft hint already fired, then the run finishes."""
    guard = _guard()
    guard.observe("a")               # starts the clock
    guard._start -= 500              # pretend 500s elapsed, past soft=450
    assert guard.observe("b")        # injects the soft hint

    snap = _call_with_deadline(guard.snapshot)

    assert snap["soft_hit"] is True
    assert snap["elapsed"] >= 450


def test_old_implementation_deadlocks(monkeypatch):
    """Counter-example: prove the test catches the original bug.

    Reinstates the pre-fix shape (a verdict helper that re-acquires
    ``self._lock``) on an instance and asserts the watchdog fires. The helper
    here stands in for the deleted ``should_kill()`` so the counter-example
    stays valid without depending on code that no longer exists. If this test
    ever stops failing the way it does now, the guard has been changed again
    and the regression test needs re-reading -- it is not silently passing.
    """
    import ctf_strix.deadline_guard as dg

    guard = _guard()

    def old_snapshot(self):
        def verdict():
            # 旧 should_kill() 的第一件事就是再取一次 self._lock。
            with self._lock:
                return None

        with self._lock:
            st = self._state_locked()
            return {
                "elapsed": round(st["elapsed"], 1),
                "tool_calls": st["tool_calls"],
                "soft_hit": self._soft_injected,
                "answer": self._answer,
                "killed_for": verdict(),
            }

    monkeypatch.setattr(dg.DeadlineGuard, "snapshot", old_snapshot)

    try:
        _call_with_deadline(guard.snapshot, seconds=1.0)
    except AssertionError as exc:
        assert "deadlock" in str(exc)
    else:
        raise AssertionError(
            "the old implementation returned -- the deadlock no longer "
            "reproduces, so this counter-example must be re-derived"
        )



# -- B-5 日志卫生：答案明文不出 deadline 通道 ------------------------------


def test_snapshot_does_not_export_answer_plaintext() -> None:
    """snapshot 会直接进 run.log 的 [deadline] 行，不许带答案明文。"""
    guard = _guard()
    guard.observe("output: FLAG{abc123def}")

    snap = _call_with_deadline(guard.snapshot)

    assert "answer" not in snap
    assert snap["answer_at_s"] is not None


def test_sidecar_payload_has_no_answer_plaintext(tmp_path, monkeypatch) -> None:
    """sidecar 由父进程看门狗与结果记录消费，只落时刻不落答案。"""
    import json

    sidecar = tmp_path / "deadline.json"
    monkeypatch.setenv("CTF_DEADLINE_PATH", str(sidecar))
    guard = _guard()
    guard.observe("output: FLAG{abc123def}")

    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert "answer" not in payload
    assert payload["answer_at_s"] is not None


def test_harness_deadline_line_reports_timing_not_plaintext() -> None:
    """[deadline] 行曾把答案明文直写进 run.log（用户实测问题④）。

    源码级钉法（与 test_wiring_20261112 同款）：这行 print 在 harness 收尾
    路径里，单测起不了整条进程，只能钉文本形状。
    """
    harness = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
    assert "answer={snap" not in harness
    assert "answer_seen_at=" in harness
    parent = (ROOT / "scripts" / "eval_sample.py").read_text(encoding="utf-8")
    assert 'diag["answer_hint"]' not in parent
    assert 'st.get("answer")' not in parent
