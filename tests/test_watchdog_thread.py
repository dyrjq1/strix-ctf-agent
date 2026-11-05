"""Two-stage wall-clock watchdog: daemon thread + hard exit.

The POSIX signal path has its own tests in ``test_agent_wallclock.py``.
The daemon, flag and subprocess hard-path tests run on every platform.
Signal delivery is tested with real ``SIGALRM`` on POSIX and with a
``SIGABRT`` + ``pthread_kill`` shim on Windows, so nothing here silently
returns; the handler-guard test also runs without ``SIGALRM``.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from ctf_strix import agent
from ctf_strix import deadline
from ctf_strix import error_policy


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clean_watchdog():
    """Never let one test's watchdog outlive it."""
    error_policy.clear_wall_deadline()
    deadline.reset_for_tests()
    agent._deadline_owned = False
    agent._signal_installed = False
    previous_alarm = signal.getsignal(signal.SIGALRM) if hasattr(signal, "SIGALRM") else None
    try:
        yield
    finally:
        agent._cancel_hard_deadline()
        if previous_alarm is not None:
            try:
                signal.signal(signal.SIGALRM, previous_alarm)
            except (OSError, ValueError):
                pass
        error_policy.clear_wall_deadline()
        deadline.reset_for_tests()
        agent._deadline_owned = False
        agent._signal_installed = False
        os.environ.pop("CTFY_SOFT_DEADLINE", None)


def _task(tmp_path: Path, *, dry_run: bool = False) -> dict:
    return {
        "run_mode": "instance",
        "dry_run": dry_run,
        "challenge": {"id": "X", "name": "x", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }


def _prepare_main(tmp_path: Path, monkeypatch, task: dict) -> Path:
    (tmp_path / "task.json").write_text(json.dumps(task), encoding="utf-8")
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "60")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    return tmp_path / "result.json"


# a. Soft path: the handler raises WallclockExceeded, so main() unwinds and
#    writes result.json through its normal cleanup.
def test_soft_handler_raises_wallclock_exceeded():
    handler = agent._wallclock_handler(60)
    with pytest.raises(agent.WallclockExceeded):
        handler(int(getattr(signal, "SIGALRM", 14)), None)


def test_installed_handler_ignores_a_late_signal_after_cancel(monkeypatch):
    """The disarm gate: a signal in flight during cleanup must be a no-op."""
    monkeypatch.setattr(agent, "_llm_wall_deadline", lambda s: time.monotonic() + s)
    error_policy.clear_wall_deadline()
    agent._install_hard_deadline(60)
    installed = signal.getsignal(int(getattr(signal, "SIGALRM", 14)))
    # On Windows there is no SIGALRM handler to install; the same guard is
    # still exercised by building the handler directly.
    handler = (
        installed
        if callable(installed)
        else agent._wallclock_handler(60, guard=deadline.armed)
    )
    with pytest.raises(agent.WallclockExceeded):
        handler(int(getattr(signal, "SIGALRM", 14)), None)
    agent._cancel_hard_deadline()
    assert deadline.armed() is False
    handler(int(getattr(signal, "SIGALRM", 14)), None)  # must not raise


def test_soft_signal_goes_to_the_main_thread(monkeypatch):
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(
        signal,
        "pthread_kill",
        lambda ident, signum: sent.append((ident, signum)),
        raising=False,
    )

    assert deadline._soft_trigger(True) is True
    assert sent == [(threading.main_thread().ident, 14)]


def test_soft_flag_is_the_no_sigalrm_fallback():
    deadline.soft_timeout_flag.clear()
    assert deadline._soft_trigger(False) is True
    assert deadline.soft_timeout_flag.is_set()


def test_soft_signal_reaches_a_sleeping_main_thread(monkeypatch):
    """A worker-thread trigger must unwind the main thread.

    ``SIGALRM`` does not exist on Windows, so this simulates the POSIX
    delivery with a real signal that does: ``SIGABRT`` plus a
    ``pthread_kill``-shaped shim.  The handler still runs in the main thread,
    which is the property the POSIX path relies on.
    """
    if not hasattr(signal, "SIGABRT"):
        return
    real_signal = signal.SIGABRT
    monkeypatch.setattr(signal, "SIGALRM", real_signal, raising=False)
    monkeypatch.setattr(
        signal,
        "pthread_kill",
        lambda ident, signum: signal.raise_signal(signum),
        raising=False,
    )
    previous = signal.getsignal(real_signal)
    signal.signal(real_signal, agent._wallclock_handler(1))

    def trigger() -> None:
        time.sleep(0.2)
        deadline._soft_trigger(True)

    try:
        threading.Thread(target=trigger, daemon=True).start()
        with pytest.raises(agent.WallclockExceeded):
            time.sleep(5)
    finally:
        signal.signal(real_signal, previous)


def test_soft_path_unwinds_main_then_cancel_is_safe(tmp_path, monkeypatch):
    """The daemon's signal must reach the main thread on every platform.

    Where ``SIGALRM`` exists this is the real delivery path.  On Windows it
    is simulated with ``SIGABRT`` plus a ``pthread_kill`` shim, which still
    proves the handler runs in the main thread rather than the watchdog's.
    """
    simulated = not hasattr(signal, "SIGALRM")
    previous = None
    if simulated:
        if not hasattr(signal, "SIGABRT"):
            pytest.skip("no signal available for the soft-path simulation")
        previous = signal.getsignal(signal.SIGABRT)
        monkeypatch.setattr(signal, "SIGALRM", signal.SIGABRT, raising=False)
        monkeypatch.setattr(
            signal,
            "pthread_kill",
            lambda ident, signum: signal.raise_signal(signum),
            raising=False,
        )
    try:
        result = tmp_path / "result.json"
        error_policy.set_wall_deadline(time.monotonic() + 0.3)
        assert agent._install_hard_deadline(0.3, result_path=result) is True
        with pytest.raises(agent.WallclockExceeded):
            time.sleep(5)
        agent._cancel_hard_deadline()
    finally:
        if simulated:
            signal.signal(signal.SIGABRT, previous)


# b. Hard path: main is still alive after the soft window, so a subprocess
#    must write the fallback and exit 233.
def _run_watchdog_script(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    script = f"""
import json, os, signal, threading, time
from pathlib import Path
from ctf_strix import deadline, error_policy

result = Path(os.environ["WD_RESULT"])
{body}
"""
    env = dict(os.environ)
    env["WD_RESULT"] = str(tmp_path / "result.json")
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT / "src"), str(REPO_ROOT / "vendor" / "src")]
    )
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_hard_path_writes_fallback_and_exits_233(tmp_path):
    proc = _run_watchdog_script(
        tmp_path,
        """
error_policy.set_wall_deadline(time.monotonic() + 0.3)
assert deadline.install(
    0.3, result_path=result, schema_version=3, soft_window=0.5, signal_armed=False
)
time.sleep(10)
""",
    )
    assert proc.returncode == deadline.HARD_EXIT_CODE, proc.stderr
    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "wallclock_hard"
    assert payload["answers"] == {}
    assert payload["schema_version"] == 3


def test_hard_path_without_sigalrm_attribute(tmp_path):
    """c. Even when the platform has no SIGALRM at all, the daemon kills."""
    proc = _run_watchdog_script(
        tmp_path,
        """
if hasattr(signal, "SIGALRM"):
    del signal.SIGALRM
from ctf_strix import agent
error_policy.WALL_RESERVE_SECONDS = 0.3
assert agent._install_hard_deadline(0.5, result_path=result) is True
time.sleep(10)
""",
    )
    assert proc.returncode == deadline.HARD_EXIT_CODE, proc.stderr
    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "wallclock_hard"


def test_main_hard_path_exits_and_writes_fallback(tmp_path):
    """b. End to end: main() is still stuck when the reserve expires."""
    (tmp_path / "task.json").write_text(json.dumps(_task(tmp_path)), encoding="utf-8")
    script = """
import time
from ctf_strix import agent, error_policy

error_policy.WALL_RESERVE_SECONDS = 0.4
# On POSIX keep the signal armed but make it a no-op, so this exercises the
# hard stage on every platform instead of the soft unwind.
agent._wallclock_handler = lambda seconds, **kwargs: (lambda signum, frame: None)
agent._fetch_platform_attachments = lambda *args, **kwargs: []
agent._challenge_kind = lambda *args, **kwargs: "web"
agent._run_agent = lambda *args, **kwargs: time.sleep(30)
agent.main()
"""
    env = dict(os.environ)
    env["CTFY_WORK_DIR"] = str(tmp_path)
    env["CTFY_WALL_DEADLINE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT / "src"), str(REPO_ROOT / "vendor" / "src")]
    )
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == deadline.HARD_EXIT_CODE, proc.stderr
    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "wallclock_hard"
    assert payload["answers"] == {}
    assert payload["schema_version"] == agent.BRIEF_SCHEMA_VERSION


def test_hard_path_never_overwrites_a_result_written_during_the_window(tmp_path):
    """c. A finished run is left alone: real result kept, no exit 233."""
    proc = _run_watchdog_script(
        tmp_path,
        """
error_policy.set_wall_deadline(time.monotonic() + 0.3)
assert deadline.install(
    0.3, result_path=result, schema_version=3, soft_window=0.6, signal_armed=False
)
result.write_text(
    json.dumps({"schema_version": 3, "answers": {"flag": "REAL"},
                "stop_reason": "completed"}),
    encoding="utf-8",
)
time.sleep(2)
""",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "completed"
    assert payload["answers"] == {"flag": "REAL"}
    assert "wallclock hard stop" not in proc.stderr


def test_hard_path_does_not_overwrite_a_result_written_after_its_stale_check(
    tmp_path,
):
    """a. The daemon already passed its last stale check when main finishes.

    ``write_fallback_result`` is delayed until main has cancelled and written
    the real file, which is exactly the old race: the pre-write snapshot was
    ``None`` (no file at install time), and a skipped re-check replaced the
    real answers with an empty fallback.
    """
    proc = _run_watchdog_script(
        tmp_path,
        """
error_policy.set_wall_deadline(time.monotonic() + 0.3)
assert deadline.install(
    0.3, result_path=result, schema_version=3, soft_window=0.6, signal_armed=False
)

gate = threading.Event()
main_done = threading.Event()
real_write = deadline.write_fallback_result

def gated_write(path, schema, wall, **kwargs):
    gate.set()
    main_done.wait(10)
    return real_write(path, schema, wall, **kwargs)

deadline.write_fallback_result = gated_write
assert gate.wait(10), "hard path never reached"

# main() starts cleanup (cancel first) and lands its real result.
deadline.cancel()
tmp = result.with_name(".real.tmp")
tmp.write_text(
    json.dumps({"schema_version": 3, "answers": {"flag": "REAL"},
                "stop_reason": "solved"}),
    encoding="utf-8",
)
os.replace(tmp, result)
main_done.set()
time.sleep(0.8)
""",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "solved"
    assert payload["answers"] == {"flag": "REAL"}


# c. Windows / no SIGALRM: the daemon still arms and the soft channel is the
#    process-global flag.
def test_install_works_without_sigalrm(monkeypatch):
    monkeypatch.delattr(signal, "SIGALRM", raising=False)
    monkeypatch.setattr(agent, "_llm_wall_deadline", lambda seconds: time.monotonic() + seconds)
    error_policy.clear_wall_deadline()
    assert agent._install_hard_deadline(60) is True
    assert deadline.is_watching()
    agent._cancel_hard_deadline()
    assert not deadline.is_watching()


def test_daemon_uses_the_flag_when_no_signal_is_armed():
    deadline.soft_timeout_flag.clear()
    deadline._soft_trigger(False)
    assert deadline.soft_timeout_flag.is_set()


def test_flag_soft_path_unwinds_through_the_event_sink():
    """Windows soft path: the run notices the flag at its next event."""
    deadline.soft_timeout_flag.set()
    with pytest.raises(agent.WallclockExceeded):
        agent._check_soft_timeout()
    deadline.soft_timeout_flag.clear()
    agent._check_soft_timeout()


# d. Negative control: cancelling inside the soft window must not kill.
def test_cancel_inside_window_prevents_hard_exit(tmp_path):
    result = tmp_path / "result.json"
    error_policy.set_wall_deadline(time.monotonic() + 60)
    assert agent._install_hard_deadline(60, result_path=result) is True
    assert deadline.is_watching()
    agent._cancel_hard_deadline()
    assert not deadline.is_watching()
    time.sleep(0.6)
    assert not result.exists()


def test_main_normal_exit_cancels_watchdog(tmp_path, monkeypatch):
    result = _prepare_main(tmp_path, monkeypatch, _task(tmp_path, dry_run=True))
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)

    assert agent.main() == 0
    assert not deadline.is_watching()
    assert json.loads(result.read_text(encoding="utf-8"))["stop_reason"] == "dry_run"


def test_main_exception_path_cancels_watchdog(tmp_path, monkeypatch):
    result = _prepare_main(tmp_path, monkeypatch, _task(tmp_path))

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(agent, "_run_agent", _boom)
    assert agent.main() == 0
    assert not deadline.is_watching()
    assert json.loads(result.read_text(encoding="utf-8"))["stop_reason"] == "error"


def test_main_wallclock_path_cancels_watchdog(tmp_path, monkeypatch):
    result = _prepare_main(tmp_path, monkeypatch, _task(tmp_path))

    def _hang(*args, **kwargs):
        raise agent.WallclockExceeded("wall budget spent")

    monkeypatch.setattr(agent, "_run_agent", _hang)
    assert agent.main() == 0
    assert not deadline.is_watching()
    assert json.loads(result.read_text(encoding="utf-8"))["stop_reason"] == "wallclock"


# e. One clock: both modules read the same error_policy deadline.
def test_both_modules_see_the_same_deadline(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(error_policy, "_clock", lambda: now[0])
    error_policy.set_wall_deadline(160.0)

    assert deadline.deadline_seconds() == 60.0
    now[0] = 130.0
    assert deadline.deadline_seconds() == 30.0


def test_install_refuses_to_invent_a_second_clock(tmp_path):
    error_policy.clear_wall_deadline()
    assert deadline.install(60, result_path=tmp_path / "result.json") is False
    assert not deadline.is_watching()


def test_install_rejects_non_positive_budget(tmp_path):
    error_policy.set_wall_deadline(time.monotonic() + 60)
    assert deadline.install(0, result_path=tmp_path / "result.json") is False
    assert not deadline.is_watching()


def test_fallback_payload_is_minimal_and_atomic(tmp_path):
    path = tmp_path / "nested" / "result.json"
    assert deadline.write_fallback_result(path, 3, 1380) is True
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["answers"] == {}
    assert payload["stop_reason"] == "wallclock_hard"
    assert payload["schema_version"] == 3
    assert payload["turns"] == 0
    assert not list(path.parent.glob("*.hard.tmp"))


def test_fallback_write_failure_is_silent(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    assert deadline.write_fallback_result(blocker / "result.json", 3, 60) is False


def test_fallback_skips_a_result_that_appeared_after_install(tmp_path):
    path = tmp_path / "result.json"
    before = deadline._file_identity(path)
    path.write_text("{}", encoding="utf-8")
    assert deadline.should_write_fallback(path, before) is False


def test_fallback_writes_when_the_old_file_is_unchanged(tmp_path):
    path = tmp_path / "result.json"
    path.write_text('{"stale": true}', encoding="utf-8")
    before = deadline._file_identity(path)
    assert deadline.should_write_fallback(path, before) is True


def test_cancel_after_the_soft_signal_prevents_the_hard_exit(tmp_path):
    """The real soft-window cancel: fire, then cancel while still inside it."""
    proc = _run_watchdog_script(
        tmp_path,
        """
error_policy.set_wall_deadline(time.monotonic() + 0.2)
assert deadline.install(
    0.2, result_path=result, schema_version=3, soft_window=1.0, signal_armed=False
)
while not deadline.fired():
    time.sleep(0.01)
deadline.cancel()
time.sleep(1.2)
""",
    )
    assert proc.returncode == 0, proc.stderr
    assert not (tmp_path / "result.json").exists()


def test_hard_path_still_exits_when_the_result_write_blocks(tmp_path):
    """e. A wedged stat/write must not delay the guaranteed exit past ~1s."""
    started = time.monotonic()
    proc = _run_watchdog_script(
        tmp_path,
        """
def hang(path, before):
    time.sleep(30)

deadline.should_write_fallback = hang
error_policy.set_wall_deadline(time.monotonic() + 0.2)
assert deadline.install(
    0.2, result_path=result, schema_version=3, soft_window=0.2, signal_armed=False
)
time.sleep(20)
""",
    )
    elapsed = time.monotonic() - started
    assert proc.returncode == deadline.HARD_EXIT_CODE, proc.stderr
    assert elapsed < 8, f"hard exit took {elapsed:.1f}s despite the 1s write bound"
    assert "wallclock hard stop" in proc.stderr


def test_hard_path_still_exits_when_the_write_itself_blocks(tmp_path):
    """e. The write leg (tmp + replace) is also bounded by the helper join."""
    started = time.monotonic()
    proc = _run_watchdog_script(
        tmp_path,
        """
def hang(*args, **kwargs):
    time.sleep(30)

deadline.write_fallback_result = hang
error_policy.set_wall_deadline(time.monotonic() + 0.2)
assert deadline.install(
    0.2, result_path=result, schema_version=3, soft_window=0.2, signal_armed=False
)
time.sleep(20)
""",
    )
    elapsed = time.monotonic() - started
    assert proc.returncode == deadline.HARD_EXIT_CODE, proc.stderr
    assert elapsed < 8, f"hard exit took {elapsed:.1f}s despite the 1s write bound"


def test_fallback_recheck_requires_the_file_to_still_be_absent(tmp_path):
    """The reviewer's repro: a snapshot of None must mean "still absent"."""
    path = tmp_path / "result.json"
    path.write_text(
        json.dumps({"schema_version": 3, "answers": {"flag": "REAL"}}),
        encoding="utf-8",
    )
    assert deadline.write_fallback_result(path, 3, 60, only_if_unchanged=None) is False
    assert json.loads(path.read_text(encoding="utf-8"))["answers"] == {"flag": "REAL"}


def test_fallback_recheck_writes_when_the_file_is_still_absent(tmp_path):
    path = tmp_path / "result.json"
    assert deadline.write_fallback_result(path, 3, 60, only_if_unchanged=None) is True
    assert json.loads(path.read_text(encoding="utf-8"))["answers"] == {}


def test_fallback_skips_the_swap_when_the_generation_moved(tmp_path):
    path = tmp_path / "result.json"
    generation = deadline._generation
    deadline.cancel()
    assert (
        deadline.write_fallback_result(
            path,
            3,
            60,
            only_if_unchanged=None,
            current_generation=generation,
        )
        is False
    )
    assert not path.exists()


def test_install_rolls_back_when_the_watchdog_thread_cannot_start(
    tmp_path, monkeypatch
):
    error_policy.set_wall_deadline(time.monotonic() + 60)
    with monkeypatch.context() as scoped:
        scoped.setattr(
            threading.Thread,
            "start",
            lambda self: (_ for _ in ()).throw(RuntimeError("can't start new thread")),
        )
        assert deadline.install(60, result_path=tmp_path / "a.json") is False
    assert not deadline.is_watching()
    assert deadline.armed() is False
    assert deadline.install(60, result_path=tmp_path / "b.json") is True
    deadline.cancel()


def test_non_positive_budget_cancels_an_existing_watchdog(tmp_path):
    """10. "No budget" must turn an earlier watchdog off, not leave it armed."""
    error_policy.set_wall_deadline(time.monotonic() + 60)
    assert deadline.install(60, result_path=tmp_path / "a.json") is True
    assert deadline.is_watching()
    assert deadline.install(0, result_path=tmp_path / "b.json") is False
    assert not deadline.is_watching()


def test_install_failure_is_reported_and_warns(tmp_path, monkeypatch, capsys):
    """d. No daemon means no soft signal either: report False and warn."""
    error_policy.set_wall_deadline(time.monotonic() + 60)
    monkeypatch.setattr(deadline, "install", lambda *args, **kwargs: False)
    assert agent._install_hard_deadline(60, result_path=tmp_path / "result.json") is False
    out = capsys.readouterr().out
    assert "watchdog not installed" in out


def test_result_is_on_disk_before_the_report_is_published(tmp_path, monkeypatch):
    """b. A slow/failing publisher must not delay the graded artifact."""
    task = {
        "run_mode": "engagement",
        "challenge": {"id": "X", "name": "x", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }
    result = _prepare_main(tmp_path, monkeypatch, task)
    seen: list[dict] = []

    def fake_run_agent(task, answers, qid, **kwargs):
        answers[qid] = "FLAG{real}"
        return 1, {}

    class FakePublisher:
        authored = True
        last_text = "final report"

        def configured(self):
            return True

        def publish(self, text, force=False, source=""):
            # If publish ran first this read would fail and the assertion
            # below would never see the real answers.
            seen.append(json.loads(result.read_text(encoding="utf-8")))
            time.sleep(0.05)
            return True, "ok"

        def snapshot(self):
            return {}

    monkeypatch.setattr(agent, "_run_agent", fake_run_agent)
    monkeypatch.setattr(agent, "_challenge_kind", lambda *args, **kwargs: "engagement")
    monkeypatch.setattr(agent, "_fetch_platform_attachments", lambda *args, **kwargs: [])
    monkeypatch.setattr(agent, "_local_attachments", lambda work: [])
    monkeypatch.setattr(agent, "_make_publisher", lambda task: FakePublisher())

    assert agent.main() == 0
    assert seen, "publisher was never called"
    assert seen[0]["answers"] == {"flag": "FLAG{real}"}
