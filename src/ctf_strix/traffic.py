"""Traffic memory: every HTTP exchange stays queryable after it scrolls away.

## Why this exists

A measured failure is canonical here: the agent enumerated a namespace, the
target answered with dozens of ``note_<hex>`` identifiers, and the run ended
without ever fetching a single one.  Nothing in the transcript said "you
have N identifiers and 0 detail reads", so the model could not notice it had
already been handed the attack surface.

The published failure data has the same shape: failed runs sit at p50 551s
while successful ones take 70s.  That is a *direction* problem, not a budget
problem -- and a direction problem is what an externalised state fixes.
PentestGPT (arXiv:2308.06782) names the mechanism: LLM testers "encounter
difficulties maintaining an integrated understanding of the overall testing
scenario".  Its fix is not a bigger model, it is carrying the state outside
the context.  Reflexion (arXiv:2303.11366) shows the same for episodic memory.

Caido gives the upstream strix agent this for free: a proxy keeps every
request and ``traffic_list`` / ``traffic_view`` / ``repeat_request`` read it
back.  Our image has no ``caido-cli``, so ``tool_trim`` drops all six proxy
tools.  What was lost with them is not the proxy UI -- it is the memory.

This module rebuilds the part that matters, without touching vendor:
``http_probe`` appends every exchange to a ledger, and two read-only
primitives read it back.  Nothing here sends a request, so none of it is a
probe tool and none of the guards should count it.

## What is stored, and what is not

Each record keeps the request (method, url, headers, body), the response
(status, headers, body), timing, and the transport phase on failure.  Bodies
are capped per record and the ledger is capped in total, because the failure
mode of a memory is not "too little" but "so much that it drowns the context".

The ledger lives in the working directory and is discarded with the container.
It is not a report; it is the run's own working memory.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final

#: Per-record body cap.  Large enough for a JSON detail page or an HTML error,
#: small enough that 400 records still fit in a few MB.
_BODY_KEEP: Final = 16 * 1024
#: Total records kept.  Old ones fall off the front.
_MAX_RECORDS: Final = 400
#: Ledger file name, inside the working directory.
_FILE_NAME: Final = ".ctf_traffic.jsonl"
#: Request body cap; a payload can be megabytes of base64.
_REQ_KEEP: Final = 4 * 1024

#: Identifiers the target itself handed us.  Two shapes dominate CTFY:
#: ``note_d6e7380c`` (prefixed hex) and ``/api/notes/xxxx`` (path segment).
_ID_PATTERNS: Final = (
    re.compile(r'"([A-Za-z][A-Za-z0-9]{1,20}_[0-9a-fA-F]{6,40})"'),
    re.compile(r'"([0-9a-fA-F]{16,40})"'),
)
_PATH_RE: Final = re.compile(r'"(/api/[A-Za-z0-9_\-./{}$:]{2,120})"')


@dataclass
class Exchange:
    """One request/response pair, as the ledger stores it."""

    id: str
    ts: float
    method: str
    url: str
    req_headers: dict[str, str] = field(default_factory=dict)
    req_body: str = ""
    status: int | None = None
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    size: int = 0
    elapsed: float = 0.0
    phase: str = ""
    note: str = ""

    def brief(self) -> dict[str, Any]:
        """One-line view for ``list_requests``: no bodies."""
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "size": self.size,
            "ms": int(self.elapsed * 1000),
            "phase": self.phase or None,
        }


class TrafficLedger:
    """Thread-safe, bounded, append-only record of this run's exchanges."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._items: list[Exchange] = []
        self._seq = 0
        self._write_failed = False

    def next_id(self) -> str:
        """Reserve a short, stable id (``r12``) before the request is sent.

        Reserving up front means a *failed* request also gets a record: "I
        tried this and it refused" is exactly the observation that stops a
        loop, and losing it is how the same dead end gets tried three times.
        """
        with self._lock:
            self._seq += 1
            return f"r{self._seq}"

    def add(self, exchange: Exchange) -> None:
        """Append one exchange and persist it when a path is configured."""
        with self._lock:
            self._items.append(exchange)
            if len(self._items) > _MAX_RECORDS:
                del self._items[: len(self._items) - _MAX_RECORDS]
            line = json.dumps(asdict(exchange), ensure_ascii=False)
        if self.path is None or self._write_failed:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            # A read-only work dir must not break the run; the in-memory copy
            # still answers both primitives.
            self._write_failed = True

    def items(self) -> list[Exchange]:
        with self._lock:
            return list(self._items)

    def get(self, request_id: str) -> Exchange | None:
        wanted = (request_id or "").strip().lower()
        with self._lock:
            for item in reversed(self._items):
                if item.id.lower() == wanted:
                    return item
        return None

    def reset(self) -> None:
        """Drop everything.  Tests use this; a run never calls it."""
        with self._lock:
            self._items.clear()
            self._seq = 0
            self._write_failed = False
        if self.path is not None:
            try:
                self.path.unlink()
            except OSError:
                pass


def _default_path() -> Path | None:
    """Ledger location: ``CTF_TRAFFIC_LEDGER`` or the working directory.

    ``CTF_TRAFFIC_LEDGER=off`` disables the file entirely -- an in-memory
    ledger is still kept, because the two read primitives should never depend
    on a writable disk.
    """
    raw = os.environ.get("CTF_TRAFFIC_LEDGER", "").strip()
    if raw.lower() in ("off", "0", "none"):
        return None
    if raw:
        return Path(raw).expanduser()
    return Path.cwd() / _FILE_NAME


_LEDGER = TrafficLedger(_default_path())


def ledger() -> TrafficLedger:
    """Return the process-wide ledger (one run, one memory)."""
    return _LEDGER


def _clip_body(text: str, keep: int = _BODY_KEEP) -> str:
    if len(text) <= keep:
        return text
    return text[:keep] + f"\n...[truncated {len(text) - keep} chars; stored prefix only]"


def record(
    *,
    request_id: str,
    method: str,
    url: str,
    req_headers: dict[str, str] | None = None,
    req_body: str = "",
    status: int | None = None,
    resp_headers: dict[str, str] | None = None,
    resp_body: str = "",
    size: int = 0,
    elapsed: float = 0.0,
    phase: str = "",
    note: str = "",
    body_keep: int = _BODY_KEEP,
) -> Exchange:
    """Store one exchange.  Called after every attempt that touches the target.

    ``body_keep`` raises the stored prefix for a caller whose body is the point
    of the request (``route_map`` downloads whole JS bundles to read routes out
    of them; the default 16 KB keeps a header and half a function).  Anything
    ``<= 0`` falls back to the default, so callers that do not care can leave it
    out and get the historical behaviour.
    """
    keep = body_keep if body_keep > 0 else _BODY_KEEP
    item = Exchange(
        id=request_id,
        ts=time.time(),
        method=(method or "GET").upper(),
        url=url or "",
        req_headers=dict(req_headers or {}),
        req_body=_clip_body(req_body, _REQ_KEEP),
        status=status,
        resp_headers=dict(resp_headers or {}),
        resp_body=_clip_body(resp_body, keep),
        size=size,
        elapsed=elapsed,
        phase=phase,
        note=note,
    )
    _LEDGER.add(item)
    return item


def _normalise_path(url: str) -> str:
    """Drop scheme/host/query so "have I asked for this resource" compares paths."""
    tail = url.split("://", 1)[-1]
    slash = tail.find("/")
    path = tail[slash:] if slash >= 0 else "/"
    return path.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"


def pending_targets(limit: int = 20) -> list[str]:
    """Identifiers the target returned that no request has ever addressed.

    This is the direct antidote to the canonical failure above: a response can
    hand over dozens of ``note_*`` ids while the transcript shows one request,
    and nothing in the model's context says "you have N keys and 0 doors
    opened".  Because the ledger keeps every response, the count is decidable
    -- so it can be shown.

    Args:
        limit: cap on how many are listed; ``0`` (or negative) means "all".

    Returns:
        Candidate identifiers/paths, most recently seen first.
    """
    items = _LEDGER.items()
    if not items:
        return []
    asked = " ".join(_normalise_path(item.url) for item in items)

    seen: list[str] = []
    for item in reversed(items):
        body = item.resp_body or ""
        if not body:
            continue
        for pattern in _ID_PATTERNS:
            for match in pattern.finditer(body):
                token = match.group(1)
                if token not in seen:
                    seen.append(token)
        for match in _PATH_RE.finditer(body):
            token = match.group(1)
            if token not in seen:
                seen.append(token)

    out: list[str] = []
    for token in seen:
        if token in asked:
            continue
        out.append(token)
        if limit and limit > 0 and len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------- tools


def traffic_list(limit: int = 25, url_contains: str = "", only_errors: bool = False) -> str:
    """List this run's HTTP exchanges, plus identifiers nobody has fetched yet.

    Read-only: it never touches the target.  Use it when you have lost track of
    what you already asked, or when you need to know which keys the target has
    already handed you.

    Args:
        limit: how many recent exchanges to show, 1-100 (default 25).
        url_contains: only show URLs containing this substring (case-insensitive).
        only_errors: only show non-2xx responses and transport failures.

    Returns:
        One line per exchange (id, method, status, size, ms, url) and a
        ``never requested`` line for identifiers seen only in responses.
    """
    items = _LEDGER.items()
    if not items:
        return (
            "[traffic] nothing recorded yet. This ledger fills itself from "
            "http_probe; a `curl` in exec_command is invisible to it."
        )
    needle = (url_contains or "").strip().lower()
    rows = []
    for item in items:
        if needle and needle not in item.url.lower():
            continue
        if only_errors and item.status is not None and 200 <= item.status < 300:
            continue
        rows.append(item)
    total = len(rows)
    wanted = max(1, min(100, int(limit or 25)))
    shown = rows[-wanted:]

    lines = [f"[traffic] {total} of {len(items)} recorded exchange(s) match"]
    # The *count* is the signal that matters -- "52 ids, 0 fetched" is the 043
    # failure -- so it is computed uncapped and only the display is clipped.
    pending_all = pending_targets(limit=0)
    if pending_all:
        shown_ids = pending_all[:20]
        more = len(pending_all) - len(shown_ids)
        suffix = f", ... +{more} more" if more > 0 else ""
        lines.append(
            f"never requested ({len(pending_all)}): {', '.join(shown_ids)}{suffix}"
        )
        lines.append(
            "these came back IN A RESPONSE -- fetching them is usually the next "
            "step; enumerating more names instead is the known failure mode."
        )
    for item in shown:
        status = item.status if item.status is not None else item.phase or "ERR"
        lines.append(
            f"  {item.id:<5} {item.method:<6} {str(status):<14} "
            f"{item.size:>7}B {int(item.elapsed * 1000):>6}ms  {item.url[:120]}"
        )
    if total > len(shown):
        lines.append(
            f"  ... {total - len(shown)} older; raise limit or filter with url_contains"
        )
    return "\n".join(lines)


def traffic_view(request_id: str = "", part: str = "both", offset: int = 0,
                 length: int = 2000) -> str:
    """Show one recorded exchange in full, without sending it again.

    Read-only.  This is how a body truncated in the original tool result gets
    re-read later -- the old behaviour was to re-send the request and hope the
    server answered the same way.

    Args:
        request_id: id from traffic_list, e.g. ``r7``.
        part: ``request`` / ``response`` / ``both`` (default both).
        offset: character offset into the selected body.
        length: characters to return, 100-8000 (default 2000).

    Returns:
        The stored exchange, or a hint naming the ids that do exist.
    """
    item = _LEDGER.get(request_id)
    if item is None:
        known = ", ".join(entry.id for entry in _LEDGER.items()[-12:]) or "(none)"
        return (
            f"[traffic] no record {request_id!r}. Known recent ids: {known}. "
            "Call traffic_list to see what this run actually sent."
        )

    start = max(0, int(offset or 0))
    span = max(100, min(8000, int(length or 2000)))
    want = (part or "both").strip().lower()

    lines = [
        f"[traffic] {item.id}  {item.method} {item.url}  "
        f"status={item.status if item.status is not None else item.phase or 'ERR'} "
        f"{item.size}B {int(item.elapsed * 1000)}ms"
    ]
    if item.note:
        lines.append(f"note: {item.note}")

    def block(title: str, headers: dict[str, str], body: str) -> None:
        if headers:
            head = ", ".join(f"{k}: {v}" for k, v in list(headers.items())[:12])
            lines.append(f"{title} headers: {head[:400]}")
        if body:
            chunk = body[start : start + span]
            left = len(body) - (start + len(chunk))
            lines.append(f"{title} body[{start}:{start + len(chunk)}] ({len(body)} chars):")
            lines.append(chunk)
            if left > 0:
                lines.append(
                    f"... {left} chars left; continue with offset={start + len(chunk)}"
                )
        else:
            lines.append(f"{title} body: (empty)")

    if want in ("request", "both"):
        block("request", item.req_headers, item.req_body)
    if want in ("response", "both"):
        block("response", item.resp_headers, item.resp_body)
    return "\n".join(lines)


TOOLS: Final = (traffic_list, traffic_view)


def _as_async(func):
    """Run a blocking helper off the event loop, keeping its signature.

    ``function_tool(timeout=...)`` raises at *registration* time for a sync
    handler (``timeout_seconds is only supported for async @function_tool
    handlers``).  Both entrypoints wrap registration in ``try/except`` and print
    one line, so the whole capability would vanish behind a message that looks
    like a transient failure.  ``functools.wraps`` keeps the parameters visible
    to the SDK, which derives the JSON schema from ``inspect.signature``.
    """
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner


def register(register_fn=None) -> list[str]:
    """Register the two read-only traffic primitives.

    Args:
        register_fn: injection point; defaults to
            ``factory.register_agent_tools``.

    Returns:
        Newly registered names (empty when already present).
    """
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=60)(_as_async(fn)) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]
