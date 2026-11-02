"""Regression: `snapshot()` must not deadlock on the guard lock.

On 2026-10-31 the 074/GLM arm printed `[usage]` at 218.9s and then hung on the
next line -- `[deadline] ...` -- until the parent SIGKILLed it at 600s.
Root cause: `snapshot()` held `self._lock` and then called `should_kill()`,
which acquires the same non-reentrant `threading.Lock`. Every finished run
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
    return DeadlineGuard(wall=600, soft=450, stall=150, grace=20, turns=30)


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
    assert "killed_for" in snap


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


def test_should_kill_still_works_standalone():
    guard = _guard()
    assert _call_with_deadline(guard.should_kill) is None

def test_old_implementation_deadlocks(monkeypatch):
    """Counter-example: prove the test catches the original bug.

    Reinstates the pre-fix wording (call `should_kill()` while holding the
    lock) on an instance and asserts the watchdog fires. If this test ever
    stops failing the way it does now, the guard has been changed again and
    the regression test needs re-reading -- it is not silently passing.
    """
    import ctf_strix.deadline_guard as dg

    guard = _guard()

    def old_snapshot(self):
        with self._lock:
            st = self._state_locked()
            return {
                "elapsed": round(st["elapsed"], 1),
                "tool_calls": st["tool_calls"],
                "soft_hit": self._soft_injected,
                "answer": self._answer,
                "killed_for": self.should_kill(),
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
