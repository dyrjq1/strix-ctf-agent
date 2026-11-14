"""Per-call LLM token telemetry (C8, observation only).

``strix.log`` has one ``llm_request`` line per call, but it has no run-level
cache field and cannot be joined to our turn counters.  This module wraps the
same ``ReportUsageHooks`` seam as :mod:`ctf_strix.usage_meter` and appends one
JSON object per completed call: turn, input, cache_read, cache_write, hit_rate,
prefix_hash, item_count, capped_items, first_capped_index, capped_hash and
model.  That is enough to answer "which turn and which request shape did the
hit-rate change come from", and whether capping rewrote a mid-history item.

Nothing here mutates messages or budgets, and sink failures are swallowed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
ENV_PATH = "CTF_LLM_TRACE_PATH"
_RECENT_MAX = 2_000
_lock = threading.Lock()
_recent: deque[dict[str, Any]] = deque(maxlen=_RECENT_MAX)
_seq = 0
_installed = False
_originals: tuple[Any, Any] | None = None
#: Hooks fire inside ``gather_with_cancel`` tasks.  A ContextVar set in one task
#: is invisible to the other, so pending state must be shared by agent identity.
_pending: dict[str, dict[str, Any]] = {}


def trace_path() -> Path | None:
    """Sink path; ``None`` keeps records in memory only."""
    raw = os.environ.get(ENV_PATH, "").strip()
    if raw:
        return Path(raw)
    usage = os.environ.get("CTF_USAGE_PATH", "").strip()
    return Path(usage).with_name("llm_calls.jsonl") if usage else None


def _int(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _field(usage: Any, *names: str) -> int:
    for name in names:
        value = _int(getattr(usage, name, None))
        if value:
            return value
    return 0


def cached_tokens(usage: Any) -> int:
    """Read provider cache-read tokens across SDK field spellings."""
    if usage is None:
        return 0
    for holder in (
        getattr(usage, "input_tokens_details", None),
        getattr(usage, "prompt_tokens_details", None),
    ):
        value = _int(getattr(holder, "cached_tokens", None)) if holder is not None else 0
        if value:
            return value
    return _field(usage, "cache_read_input_tokens", "cached_input_tokens")


def cache_write_tokens(usage: Any) -> int:
    """Read provider cache-write tokens (same holder/normalization as reads)."""
    if usage is None:
        return 0
    for holder in (
        getattr(usage, "input_tokens_details", None),
        getattr(usage, "prompt_tokens_details", None),
    ):
        value = _int(getattr(holder, "cache_write_tokens", None)) if holder is not None else 0
        if value:
            return value
    return _field(usage, "cache_write_input_tokens", "cache_creation_input_tokens")


def hit_rate(cache_read: int, input_tokens: int) -> float:
    """Cache-hit ratio, and the accounting convention it assumes.

    Denominator is ``input_tokens`` under the OpenAI convention, where prompt
    tokens already *include* cached tokens, so the value stays in [0, 1].
    Anthropic-style usage reports ``input_tokens`` *excluding* cache reads;
    feeding those numbers into this formula pins the ratio at 0.0 (or pushes it
    above 1 elsewhere), so rows are only comparable when their ``model`` field
    shows the same provider convention.  Read ``model`` before comparing.
    """
    return round(cache_read / input_tokens, 4) if input_tokens else 0.0


def prefix_hash(system_prompt: Any, items: Any) -> str:
    """Fingerprint the stable head of a request (prompt + first item)."""
    parts: list[str] = [system_prompt[:2_000]] if isinstance(system_prompt, str) else []
    for item in list(items or [])[:1]:
        try:
            parts.append(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str))
        except (TypeError, ValueError):
            parts.append(str(item))
    seed = "\x1e".join(parts)[:4_000]
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:16]


def _label(context: Any, agent: Any) -> str:
    ctx = getattr(context, "context", None)
    agent_id = ctx.get("agent_id") if isinstance(ctx, dict) else None
    if isinstance(agent_id, str) and agent_id:
        return agent_id
    name = getattr(agent, "name", None)
    return name if isinstance(name, str) and name else "unknown"


def _turn(context: Any) -> int:
    ctx = getattr(context, "context", None)
    return _int(ctx.get("llm_turn")) if isinstance(ctx, dict) else 0


def _cap_stats() -> dict[str, Any] | None:
    try:
        from ctf_strix import context as ctf_context

        stats = ctf_context.LAST_CAP_STATS.get()
        return dict(stats) if isinstance(stats, dict) else None
    except Exception:  # noqa: BLE001 - telemetry must not break the call
        return None


def _key(context: Any, agent: Any) -> str:
    return f"{_label(context, agent)}:{id(agent)}"


def _write(record: dict[str, Any]) -> None:
    global _seq
    with _lock:
        _seq += 1
        record["seq"] = _seq
        _recent.append(record)
        path = trace_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError:
            logger.warning("cannot append LLM telemetry to %s", path, exc_info=True)


def _record(context: Any, agent: Any, response: Any) -> None:
    # A served response proves the endpoint is alive, so it clears the
    # transport-failure streak that error_policy's breaker counts.
    try:
        from ctf_strix import error_policy

        error_policy.note_model_ok()
    except Exception:  # noqa: BLE001 - telemetry must never break a call
        pass
    with _lock:
        pending = _pending.pop(_key(context, agent), None)
    usage = getattr(response, "usage", None)
    input_tokens = _field(usage, "input_tokens", "prompt_tokens")
    output_tokens = _field(usage, "output_tokens", "completion_tokens")
    cache_read = cached_tokens(usage)
    cache_write = cache_write_tokens(usage)
    model = getattr(agent, "model", None)
    stats = _cap_stats()
    if stats is not None and _int(stats.get("seq")) <= _int((pending or {}).get("cap_seq")):
        stats = None
    record: dict[str, Any] = {
        "ts": round(time.time(), 3),
        "agent": _label(context, agent),
        "turn": _int((pending or {}).get("turn")) or _turn(context),
        "input": input_tokens,
        "output": output_tokens,
        "cache_read": cache_read,
        "cache_write": cache_write,
        "hit_rate": hit_rate(cache_read, input_tokens),
        "model": model if isinstance(model, str) else "",
        "prefix_hash": (pending or {}).get("prefix_hash", ""),
        "item_count": _int((pending or {}).get("item_count")),
        "capped_items": 0,
        "evidence_items": 0,
        "first_capped_index": -1,
        "capped_hash": "",
    }
    if stats is not None:
        record["item_count"] = _int(stats.get("item_count")) or record["item_count"]
        record["capped_items"] = _int(stats.get("capped_items"))
        record["evidence_items"] = _int(stats.get("evidence_items"))
        record["first_capped_index"] = _int(stats.get("first_capped_index"), -1)
        record["capped_hash"] = str(stats.get("capped_hash") or "")
    _write(record)


def recent() -> list[dict[str, Any]]:
    """In-memory copies of recent records (tests and diagnostics)."""
    with _lock:
        return [dict(item) for item in _recent]


def install() -> None:
    """Wrap the usage hooks; idempotent.  Call after ``usage_meter.install``."""
    global _installed, _originals
    if _installed:
        return
    from strix.core import hooks as strix_hooks

    original_end = strix_hooks.ReportUsageHooks.on_llm_end
    original_start = strix_hooks.ReportUsageHooks.on_llm_start

    async def on_llm_start(
        self: Any, context: Any, agent: Any, system_prompt: Any, input_items: Any,
        *args: Any, **kwargs: Any,
    ) -> Any:
        result = await original_start(self, context, agent, system_prompt, input_items, *args, **kwargs)
        try:
            stats = _cap_stats()
            info = {
                "turn": _turn(context),
                "item_count": len(input_items) if isinstance(input_items, list) else 0,
                "prefix_hash": prefix_hash(system_prompt, input_items),
                "cap_seq": _int((stats or {}).get("seq")),
            }
            with _lock:
                _pending[_key(context, agent)] = info
        except Exception:  # noqa: BLE001 - observation only
            pass
        return result

    async def on_llm_end(self: Any, context: Any, agent: Any, response: Any) -> Any:
        try:
            _record(context, agent, response)
        except Exception:  # noqa: BLE001 - observation only
            logger.warning("LLM telemetry record failed", exc_info=True)
        return await original_end(self, context, agent, response)

    strix_hooks.ReportUsageHooks.on_llm_start = on_llm_start  # type: ignore[method-assign]
    strix_hooks.ReportUsageHooks.on_llm_end = on_llm_end  # type: ignore[method-assign]
    _originals = (original_end, original_start)
    _installed = True


def reset_for_tests() -> None:
    """Restore the previous hooks and clear in-memory state."""
    global _installed, _originals, _seq
    originals = _originals
    with _lock:
        _recent.clear()
        _pending.clear()
        _seq = 0
    if originals is not None:
        try:
            from strix.core import hooks as strix_hooks

            strix_hooks.ReportUsageHooks.on_llm_end = originals[0]  # type: ignore[method-assign]
            strix_hooks.ReportUsageHooks.on_llm_start = originals[1]  # type: ignore[method-assign]
        except Exception:  # noqa: BLE001 - cleanup must not raise
            # Keep _installed/_originals so a retry cannot wrap our own wrapper.
            logger.debug("failed to restore telemetry hooks", exc_info=True)
            return
    _originals = None
    _installed = False
