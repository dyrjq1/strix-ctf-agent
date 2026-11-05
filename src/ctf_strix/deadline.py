"""Wall-clock watchdog: a daemon thread behind the signal-based deadline.

``agent._install_hard_deadline`` used to be a single ``signal.alarm`` call.
That has two structural holes:

1. Windows has no ``SIGALRM``, so a local run had no deadline at all.
2. A signal can only interrupt the main thread between bytecodes.  A main
   thread blocked inside a long C call (native TLS, a locked ``threading``
   primitive) never reaches the handler, and one ``except BaseException``
   on the way up would swallow it.

This module adds a second, independent layer.  A daemon thread waits on the
same deadline the retry policy uses (:func:`error_policy.remaining_wall`),
so there is exactly one clock.  At the deadline it:

* first asks the main thread to finish normally: ``SIGALRM`` via
  ``signal.pthread_kill`` on POSIX, a process-global flag elsewhere;
* then waits :data:`error_policy.WALL_RESERVE_SECONDS` for that to happen;
* if the main thread is still alive, writes a minimal fallback
  ``result.json`` and calls ``os._exit(233)``.

The fallback payload is deliberately minimal: the daemon thread cannot see
``main()``'s local ``answers``/turn counters, and a file with an empty answer
map still beats the platform's ``no_result_file`` verdict.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from ctf_strix import error_policy

#: Process exit status for the hard kill.  Distinct from 0 (normal result)
#: and from a platform SIGKILL so a run's death is attributable.
HARD_EXIT_CODE = 233

#: Fallback ``stop_reason``.  Kept apart from ``wallclock``: the soft path
#: ran ``main()``'s cleanup and may carry answers; this one did not.
HARD_STOP_REASON = "wallclock_hard"

#: How often the daemon re-checks the deadline.  A short poll keeps a long
#: C call from delaying the kill, while staying far below the 20s window.
_POLL_SECONDS = 0.25

_lock = threading.Lock()
_watchdog: threading.Thread | None = None
_generation = 0
_fired = False
_armed = False

#: Set when the soft stage fires on a platform without ``SIGALRM``.  A
#: main-thread loop can poll it; the hard stage does not depend on it.
soft_timeout_flag = threading.Event()


def deadline_seconds() -> float | None:
    """Seconds left on the shared wall clock, or ``None`` when unbounded."""
    return error_policy.remaining_wall()


def armed() -> bool:
    """Whether a soft signal is still welcome.

    ``cancel()`` clears this before returning.  The ``SIGALRM`` handler reads
    it first, so a signal that was already in flight when ``main()`` started
    its cleanup becomes a no-op instead of unwinding the cleanup itself.
    """
    return _armed


def _soft_trigger(signal_armed: bool) -> bool:
    """Ask the main thread to unwind; never raise into the watchdog.

    Returns:
        ``True`` when some soft channel was offered, ``False`` when neither
        a signal handler nor a pollable flag exists.
    """
    alarm = getattr(signal, "SIGALRM", None) if signal_armed else None
    if alarm is not None:
        try:
            signal.pthread_kill(threading.main_thread().ident, alarm)
            return True
        except (AttributeError, OSError, TypeError, ValueError):
            # No pthread_kill (or no main thread id): fall through to the
            # flag, which is the only soft path Windows has.
            pass
    soft_timeout_flag.set()
    return True


def _fallback_payload(schema_version: int, wall_seconds: float) -> dict[str, Any]:
    """Minimal result.json body the daemon can build without main()'s state."""
    return {
        "schema_version": schema_version,
        "answers": {},
        "turns": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "stop_reason": HARD_STOP_REASON,
        "writeup": (
            f"wallclock hard stop: {wall_seconds:.0f}s budget spent and the "
            "main thread did not unwind within the shutdown reserve. "
            "Answers are unavailable because the run never reached main()'s "
            "cleanup."
        ),
    }


def _log_hard_stop(wall_seconds: float) -> None:
    """Best-effort diagnostic, bounded so a full pipe cannot block the exit."""

    def write() -> None:
        try:
            sys.stderr.write(
                f"[ctfy] wallclock hard stop after {wall_seconds:.0f}s; "
                "main thread did not unwind\n"
            )
            sys.stderr.flush()
            sys.stdout.flush()
        except BaseException:  # noqa: BLE001 - logging must never raise
            pass

    try:
        thread = threading.Thread(target=write, name="ctfy-hard-stop-log", daemon=True)
        thread.start()
        thread.join(0.25)
    except BaseException:  # noqa: BLE001
        pass


def _file_identity(path: Path | str) -> tuple[int, int, int] | None:
    """Identity of an existing result file, or ``None`` when absent."""
    try:
        stat = Path(path).stat()
    except (OSError, ValueError):
        return None
    return (int(stat.st_ino), int(stat.st_mtime_ns), int(stat.st_size))


def should_write_fallback(
    result_path: Path | str,
    before_install: tuple[int, int, int] | None,
) -> bool:
    """Whether the hard path should replace the existing result file.

    ``main()`` writes ``result.json`` atomically, so any file newer than the
    watchdog start is a complete result from this run.  The caller snapshots
    the file's identity at install time, so a replacement is detectable even
    on filesystems with coarse mtime granularity.  Replacing a good result
    with an empty-answer fallback would turn a good outcome into a worse one.

    Args:
        result_path: Destination declared by ``task.json``.
        before_install: :func:`_file_identity` captured at install time.

    Returns:
        ``False`` only when a complete file from this run already exists.
    """
    current = _file_identity(result_path)
    if current is None:
        # Nothing to protect; writing the fallback is the whole point.
        return True
    return current == before_install


def write_fallback_result(
    result_path: Path | str,
    schema_version: int,
    wall_seconds: float,
    only_if_unchanged: tuple[int, int, int] | None = None,
) -> bool:
    """Best-effort atomic write of the hard-timeout result file.

    Every failure is swallowed: this runs on the way to ``os._exit``, where
    raising would lose the file *and* the exit.

    Args:
        result_path: Destination declared by ``task.json`` or ``result.json``.
        schema_version: Protocol schema version from the entrypoint.
        wall_seconds: Wall budget, used only for the human-readable writeup.
        only_if_unchanged: When set, re-check the destination's identity just
            before ``os.replace`` and skip the swap if ``main()`` wrote a real
            result while this thread was preparing the fallback.

    Returns:
        ``True`` when the file was replaced, ``False`` on any failure.
    """
    try:
        path = Path(result_path)
        payload = _fallback_payload(schema_version, wall_seconds)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.hard.tmp")
        try:
            tmp.write_text(text, encoding="utf-8")
            if (
                only_if_unchanged is not None
                and _file_identity(path) != only_if_unchanged
            ):
                return False
            os.replace(tmp, path)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
        return True
    except BaseException:  # noqa: BLE001 - contract: never raise here
        return False


def _run(
    wall_seconds: float,
    result_path: Path | str | None,
    schema_version: int,
    soft_window: float,
    signal_armed: bool,
    generation: int,
    before_install: tuple[int, int, int] | None,
) -> None:
    """Watchdog body: wait for the deadline, fire softly, then hard."""
    global _fired  # noqa: PLW0603 - process-wide one-shot state

    def stale() -> bool:
        with _lock:
            return generation != _generation

    while True:
        if stale():
            return
        try:
            remaining = deadline_seconds()
        except BaseException:  # noqa: BLE001 - a broken clock must not kill
            return
        if remaining is None:
            # main() cleared the deadline (normal shutdown).  Never kill.
            return
        if remaining <= 0:
            break
        time.sleep(min(_POLL_SECONDS, remaining))

    if stale():
        return
    _fired = True
    try:
        _soft_trigger(signal_armed)
    except BaseException:  # noqa: BLE001 - the hard stage is the guarantee
        pass

    window_end = time.monotonic() + max(soft_window, 0.0)
    while time.monotonic() < window_end:
        if stale():
            return
        time.sleep(min(_POLL_SECONDS, max(window_end - time.monotonic(), 0.0)))

    if stale():
        return
    if not threading.main_thread().is_alive():
        # main() already ended; there is no stuck thread to kill, and turning
        # a normal exit into 233 would misreport the run.
        return
    try:
        if result_path is not None and should_write_fallback(result_path, before_install):
            write_fallback_result(
                result_path,
                schema_version,
                wall_seconds,
                only_if_unchanged=before_install,
            )
    except BaseException:  # noqa: BLE001 - a failed check must not skip the exit
        pass
    finally:
        _log_hard_stop(wall_seconds)
        os._exit(HARD_EXIT_CODE)


def install(
    wall_seconds: float,
    result_path: Path | str | None = None,
    schema_version: int = 3,
    soft_window: float | None = None,
    signal_armed: bool = False,
) -> bool:
    """Start the daemon watchdog; ``False`` when there is nothing to watch.

    The deadline itself must already be set on :mod:`error_policy`; this
    function does not create a second clock.

    Args:
        wall_seconds: The run's wall budget, used for messages/payload only.
        result_path: Where to write the fallback file on the hard path.
        schema_version: Value for the fallback payload's ``schema_version``.
        soft_window: Grace period before the hard exit.  Defaults to
            :data:`error_policy.WALL_RESERVE_SECONDS`.
        signal_armed: Whether the caller installed a ``SIGALRM`` handler.  The
            daemon refuses to send a signal whose default action kills.

    Returns:
        ``True`` when a new watchdog thread was started, ``False`` for a
        non-positive budget or an unset shared deadline.
    """
    global _watchdog, _generation, _fired, _armed  # noqa: PLW0603 - state
    if wall_seconds <= 0:
        return False
    if deadline_seconds() is None:
        # No shared deadline means main() never set one; inventing one here
        # would be the second clock this design forbids.
        return False

    window = (
        float(error_policy.WALL_RESERVE_SECONDS)
        if soft_window is None
        else float(soft_window)
    )
    with _lock:
        # A watchdog left over from an earlier in-process run is superseded,
        # not reused: it may still point at the previous result path and
        # generation.  It exits on its next stale check.
        _generation += 1
        generation = _generation
        _fired = False
        _armed = True
        soft_timeout_flag.clear()
        thread = threading.Thread(
            target=_run,
            args=(
                float(wall_seconds),
                result_path,
                int(schema_version),
                window,
                bool(signal_armed),
                generation,
                _file_identity(result_path) if result_path is not None else None,
            ),
            name="ctfy-wallclock-watchdog",
            daemon=True,
        )
        _watchdog = thread
        thread.start()
    return True


def cancel() -> None:
    """Stop watching (idempotent).

    The thread is a daemon and checks the shared deadline, so this only
    needs to invalidate its generation; a normal shutdown must never wait
    on it.
    """
    global _watchdog, _generation, _armed  # noqa: PLW0603 - process-wide state
    with _lock:
        _armed = False
        _generation += 1
        _watchdog = None
    soft_timeout_flag.clear()


def is_watching() -> bool:
    """Whether a watchdog thread is currently running (tests/diagnostics)."""
    with _lock:
        return _watchdog is not None and _watchdog.is_alive()


def fired() -> bool:
    """Whether the soft stage has fired in this process (tests/diagnostics)."""
    return _fired


def reset_for_tests() -> None:
    """Clear one-shot state; only tests should call this."""
    global _fired  # noqa: PLW0603
    cancel()
    _fired = False
