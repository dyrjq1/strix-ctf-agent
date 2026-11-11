"""Incrementally persist guard counters so a SIGKILL does not erase them.

The batch harness kills a run at the wall clock (SIGKILL to the process
group).  Every guard summary line is printed *after* the run ends, so a killed
run used to look like "no guard ever fired": ``reach=0`` and
``mount_broken=True`` on a run whose mount was verified at startup.

The usage meter already solved the same problem by writing its snapshot after
every LLM call with a temporary file plus ``os.replace``.  This module does the
same for guard state: one atomic JSON write per LLM call, plus one at install
time so even a run killed before its first paid call leaves a readable file.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

logger = logging.getLogger(__name__)

#: Bumped only if the on-disk shape changes incompatibly.
SCHEMA = 1


def atomic_write_json(path: str | Path, payload: Mapping[str, Any]) -> bool:
    """Write ``payload`` to ``path`` atomically.

    A reader must never observe a half-written JSON document: the file is only
    replaced after the temporary file is fully written and closed.

    Returns:
        True when the file was replaced, False when the write failed.
    """
    target = Path(path)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(dict(payload), ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, target)
        return True
    except (OSError, TypeError, ValueError):
        # Telemetry must never take the run down; worst case the parent falls
        # back to the summary line (or to "no data", which is honest).
        logger.warning("Failed to persist guard state to %s", target, exc_info=True)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


#: v1.1 extension keys, all zero when an older sidecar has only the batch-1
#: shape.  They never touch the summary line; the line parsers are anchored.
_V11_DEFAULTS: dict[str, int] = {
    "endpoint_probe": 0,
    "endpoint_exec": 0,
    "endpoint_window": 0,
    "endpoint_window_probe": 0,
    "endpoint_window_exec": 0,
    "negative_groups": 0,
    "negative_injections": 0,
    "negative_limit": 0,
    "truncation_pointers": 0,
}


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def v11_fields(state: Mapping[str, Any] | dict[str, Any] | None) -> dict[str, int]:
    """Read the v1.1 counters out of a sidecar, tolerating old files.

    ``endpoints`` is written by the restart guard (probe vs shell sources);
    ``negative`` is written by the negative-evidence guard (group and
    injection counts plus truncation pointers).  A missing section yields
    zeros, which is the honest "this run predates the field" reading.
    """
    out = dict(_V11_DEFAULTS)
    if not isinstance(state, dict):
        return out
    endpoints = state.get("endpoints")
    if isinstance(endpoints, dict):
        out.update(
            endpoint_probe=_as_int(endpoints.get("distinct_probe")),
            endpoint_exec=_as_int(endpoints.get("distinct_exec")),
            endpoint_window=_as_int(endpoints.get("window_size")),
            endpoint_window_probe=_as_int(endpoints.get("window_probe")),
            endpoint_window_exec=_as_int(endpoints.get("window_exec")),
        )
    negative = state.get("negative")
    if isinstance(negative, dict):
        out.update(
            negative_groups=_as_int(negative.get("groups")),
            negative_injections=_as_int(negative.get("injections")),
            negative_limit=_as_int(negative.get("limit")),
            truncation_pointers=_as_int(negative.get("truncation_pointers")),
        )
    return out


def read_state(path: str | Path | None) -> dict[str, Any] | None:
    """Read a guard-state file, returning ``None`` when it is absent or broken."""
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


class GuardStateWriter:
    """Renders a snapshot on demand and writes it atomically."""

    def __init__(
        self,
        path: str | Path,
        snapshot: Callable[[], Mapping[str, Any]],
    ) -> None:
        self.path = Path(path)
        self._snapshot = snapshot

    def payload(self) -> dict[str, Any]:
        """Current snapshot with the schema tag added."""
        body = dict(self._snapshot())
        body.setdefault("schema", SCHEMA)
        return body

    def persist(self) -> bool:
        """Snapshot now and write atomically. Never raises."""
        try:
            body = self.payload()
        except Exception:  # noqa: BLE001 - a broken provider is a telemetry bug, not a run failure
            logger.warning("Guard state snapshot failed", exc_info=True)
            return False
        return atomic_write_json(self.path, body)


#: The writer currently feeding the ``on_llm_end`` hook. One run per process.
_active: GuardStateWriter | None = None
_hook_installed = False
_original_hook: Any = None


def persist_now() -> None:
    """Write the active writer's snapshot, if any."""
    writer = _active
    if writer is not None:
        writer.persist()


def install(
    path: str | Path,
    snapshot: Callable[[], Mapping[str, Any]],
) -> GuardStateWriter:
    """Start persisting guard state for this run.

    The write is chained onto ``ReportUsageHooks.on_llm_end`` *after* the usage
    meter installed its own wrapper, so both sidecars move at the same rhythm:
    once per LLM call.  A write also happens immediately, so a run killed
    before its first call still leaves a file with the startup values.
    """
    global _active, _hook_installed, _original_hook

    writer = GuardStateWriter(path, snapshot)
    _active = writer
    if not _hook_installed:
        from strix.core import hooks as strix_hooks

        original = strix_hooks.ReportUsageHooks.on_llm_end
        _original_hook = original

        async def on_llm_end(*args: Any, **kwargs: Any) -> Any:
            try:
                return await original(*args, **kwargs)
            finally:
                # ``finally`` matters: an output-budget trip raises out of the
                # original hook, and that is exactly when the counters matter.
                persist_now()

        strix_hooks.ReportUsageHooks.on_llm_end = on_llm_end  # type: ignore[method-assign]
        _hook_installed = True
    writer.persist()
    return writer


def reset_for_tests() -> None:
    """Restore the pre-install hook and drop the active writer."""
    global _active, _hook_installed, _original_hook

    if _hook_installed and _original_hook is not None:
        try:
            from strix.core import hooks as strix_hooks

            strix_hooks.ReportUsageHooks.on_llm_end = _original_hook  # type: ignore[method-assign]
        except Exception:  # noqa: BLE001 - cleanup must not fail the test
            logger.debug("failed to restore usage hook", exc_info=True)
    _active = None
    _hook_installed = False
    _original_hook = None
