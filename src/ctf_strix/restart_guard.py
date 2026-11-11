"""Mechanical restart guard: trigger, injection, and fixed budgets.

The guard answers one question with counters that already exist in the run:
has the agent stopped learning?  It never asks the model to assess itself
(C1), never lets prose into the rebuilt ledger (C4), and never grows a
restart budget past the frozen values below (C5).

## Inputs, all read-only

* T1 wall clock -- the same ``time.monotonic`` domain as the deadline guard.
* T2 mechanism coverage -- :func:`ctf_strix.enum_guard._mechanism_of` is
  reused verbatim; the guard only consumes the mapping, it does not change
  enum_guard's counting logic.
* T3 endpoint growth -- the traffic ledger's ``origin + path`` pairs.

## Trigger

``T1 AND T2 AND T3`` where T2/T3 are sliding-window stalls.  A new mechanism
class or a new endpoint is information gain and immediately lifts both stall
signals.  This is deliberately stricter than ``T1 AND (T2 OR T3)``: the
approved design says novelty immediately releases T2/T3, and the slow-but-
correct runs the guard must never touch keep discovering endpoints.  With OR,
one stalled class would fire while the run was still finding new surface.

## Ladder and budgets (frozen; no implicit growth)

* L1 x2 -- mark the current mechanism class refuted, require the next probe
  to use an unused mechanism class.  The guard hard-refuses a violating probe.
* L2 x1 -- mechanisms exhausted: switch to the least-explored discovered
  origin.
* L3 x1 -- both T2 and T3 stalled and more than half the wall budget spent:
  inject a deterministic ledger rebuild block.  New-session infrastructure is
  Phase 4b work, so this build ships the degraded in-context form.

At the ceiling the guard stays silent and lets the run burn out.  Stopping
early would be a disguised budget change.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Final, Sequence
from urllib.parse import urlsplit

from ctf_strix.enum_guard import MECHANISM_NAMES, _mechanism_of
from ctf_strix.probe_surface import is_probe_tool

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: T1: solved-run p75 is 853s and 960-1560s is an empty valley; 900s is the
#: left edge (restart-t1-stats.md).  T1 is only one conjunct.
T1_WALL_SECONDS: Final[float] = 900.0

#: Recent actions/requests considered by T2/T3.  The approved design says to
#: derive the window from existing counters (for example the latest 20
#: actions); no new budget parameter is introduced.
SLIDING_WINDOW: Final[int] = 20

L1: Final[str] = "L1"
L2: Final[str] = "L2"
L3: Final[str] = "L3"

#: Frozen per-challenge ceilings.  Do not derive these from wall time or turns.
LIMITS: Final[dict[str, int]] = {L1: 2, L2: 1, L3: 1}

#: One-sentence description used by the naming test.  No ticket number, IP, or
#: path: it must describe the capability, not the run that prompted it.
CHANGE_SUMMARY: Final[str] = (
    "A mechanical guard nudges a stalled run to change attack mechanism or "
    "surface, and rebuilds its working ledger, under fixed per-run ceilings."
)

_MARK: Final[str] = "_ctf_restart_guarded"
_PROCESS_START: Final[float] = time.monotonic()


@dataclass(frozen=True)
class TriggerState:
    """Point-in-time view of the three mechanical inputs."""

    elapsed_s: float
    wall_s: float
    t1: bool
    t2: bool
    t3: bool
    triggered: bool
    l3_ready: bool


def _origin_path(url: str) -> tuple[str, str]:
    """Split a URL into ``(origin, path)`` without query or fragment."""

    if not url:
        return ("", "/")
    parsed = urlsplit(url if "://" in url else f"//{url}")
    if parsed.scheme and parsed.netloc:
        origin = f"{parsed.scheme}://{parsed.netloc}"
    elif parsed.netloc:
        origin = parsed.netloc
    else:
        origin = url.split("/", 1)[0]
    path = parsed.path or "/"
    return (origin, path)


def _body_signature(status: Any, body: str) -> str:
    raw = f"{status if status is not None else 'ERR'}\n{body or ''}".encode(
        "utf-8", "replace"
    )
    return hashlib.sha256(raw).hexdigest()[:12]


def _item_value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def build_rebuild_block(
    items: Sequence[Any],
    *,
    remaining_s: float,
    max_rows: int = 40,
) -> str:
    """Render a deterministic ledger-only rebuild block (C4).

    Every row has the frozen shape ``conclusion | evidence pointer | class``.
    Only statements the ledger can re-check are emitted: verified responses,
    verified credential headers, negative results of the form "N requests,
    zero information change", and the target/remaining-wall footer.  Model
    prose is never an input.

    Args:
        items: ``traffic.Exchange`` objects (or dicts with the same keys), in
            ledger order.
        remaining_s: seconds left on the wall clock.
        max_rows: hard cap on data rows to keep the insertion near 2k tokens.

    Returns:
        The block text.  The same input sequence always yields identical bytes.
    """

    rows: list[str] = []
    seen_status: set[tuple[str, Any]] = set()
    seen_creds: set[tuple[str, str]] = set()
    by_endpoint: dict[tuple[str, str], list[Any]] = {}
    origins: Counter[str] = Counter()
    paths_by_origin: dict[str, set[str]] = {}

    for item in items:
        request_id = str(_item_value(item, "id", "") or "?")
        origin, path = _origin_path(str(_item_value(item, "url", "") or ""))
        method = str(_item_value(item, "method", "GET") or "GET").upper()
        status = _item_value(item, "status", None)
        body = str(_item_value(item, "resp_body", "") or "")
        size = _item_value(item, "size", len(body))

        if origin:
            origins[origin] += 1
            paths_by_origin.setdefault(origin, set()).add(path)

        response_key = (origin, status)
        if origin and status is not None and response_key not in seen_status:
            seen_status.add(response_key)
            conclusion = (
                f"{method} {origin}{path} -> {status} "
                f"size={size}B sha={_body_signature(status, body)}"
            )
            rows.append(f"- {conclusion} | {request_id} | verified-response")

        req_headers = _item_value(item, "req_headers", {}) or {}
        if isinstance(req_headers, dict):
            for name in sorted(req_headers):
                low = name.lower()
                if low not in {"authorization", "cookie", "x-api-key"}:
                    continue
                value = str(req_headers[name])
                key = (low, value)
                if key in seen_creds:
                    continue
                seen_creds.add(key)
                rows.append(
                    f"- verified credential header {name}: {value} | "
                    f"{request_id} | verified-credential"
                )

        resp_headers = _item_value(item, "resp_headers", {}) or {}
        if isinstance(resp_headers, dict):
            for name in sorted(resp_headers):
                if name.lower() != "set-cookie":
                    continue
                value = str(resp_headers[name])
                key = ("set-cookie", value)
                if key in seen_creds:
                    continue
                seen_creds.add(key)
                rows.append(
                    f"- verified credential header {name}: {value} | "
                    f"{request_id} | verified-credential"
                )

        by_endpoint.setdefault((origin, path), []).append(item)

    for (origin, path), group in by_endpoint.items():
        if len(group) < 3:
            continue
        signatures = {
            _body_signature(
                _item_value(item, "status", None),
                str(_item_value(item, "resp_body", "") or ""),
            )
            for item in group
        }
        if len(signatures) != 1:
            continue
        pointer = ",".join(
            str(_item_value(item, "id", "?") or "?") for item in group[:5]
        )
        rows.append(
            f"- {origin}{path} {len(group)} requests, zero information change "
            f"(sha={next(iter(signatures))}) | {pointer} | negative"
        )

    for origin in sorted(origins):
        rows.append(
            f"- target {origin}: requests={origins[origin]} "
            f"paths={len(paths_by_origin.get(origin, ()))} | ledger | target"
        )

    rows.append(
        f"- remaining wall clock {max(0.0, float(remaining_s)):.0f}s | "
        "deadline | wallclock"
    )

    if len(rows) > max_rows:
        omitted = len(rows) - max_rows
        rows = rows[: max_rows - 1] + [f"- {omitted} more rows omitted | ledger | cap"]

    header = (
        "[RESTART GUARD L3] ledger rebuild (degraded in-context mode; "
        "new-session infrastructure is Phase 4b)\n"
        "format: conclusion | evidence pointer | class\n"
    )
    return header + "\n".join(rows)


class RestartGuard:
    """Sliding-window stall detector with a fixed L1/L2/L3 response ladder."""

    def __init__(
        self,
        *,
        elapsed: Callable[[], float] | None = None,
        wall: Callable[[], float] | None = None,
        mechanism_of: Callable[[str], str | None] | None = None,
        ledger_items: Callable[[], Sequence[Any]] | None = None,
        window: int = SLIDING_WINDOW,
    ) -> None:
        self._lock = threading.RLock()
        self._window = max(1, int(window))
        self._elapsed = elapsed or (lambda: time.monotonic() - _PROCESS_START)
        self._wall = wall or _default_wall
        self._mechanism_of = mechanism_of or _mechanism_of
        self._ledger_items = ledger_items or _default_ledger_items

        self._mech_seen: set[str] = set()
        self._mech_window: deque[bool] = deque(maxlen=self._window)
        self._last_mechanism: str | None = None

        self._ep_seen: set[tuple[str, str]] = set()
        self._ep_window: deque[bool] = deque(maxlen=self._window)
        self._ep_ids: set[str] = set()
        self._last_origin: str | None = None

        self._issued: Counter[str] = Counter()
        self._requests: Counter[str] = Counter()
        self._l1_policy: frozenset[str] | None = None

    # -------------------------------------------------------------- inputs
    def note_mechanism(self, mechanism: str | None) -> None:
        """Record one classified probe into the T2 window."""

        if mechanism is None:
            return
        with self._lock:
            novel = mechanism not in self._mech_seen
            self._mech_seen.add(mechanism)
            self._mech_window.append(novel)
            self._last_mechanism = mechanism

    def note_endpoint(self, origin: str, path: str, request_id: str = "") -> None:
        """Record one request into the T3 window."""

        with self._lock:
            key = (origin, path)
            novel = key not in self._ep_seen
            self._ep_seen.add(key)
            self._ep_window.append(novel)
            if origin:
                self._last_origin = origin
            if request_id and request_id not in self._ep_ids:
                self._ep_ids.add(request_id)

    def sync_ledger(self) -> None:
        """Consume new exchanges from the traffic ledger (read-only)."""

        try:
            items = list(self._ledger_items())
        except Exception:  # noqa: BLE001 - a memory outage must not break the run
            logger.warning("restart guard ledger read failed", exc_info=True)
            return
        for item in items:
            request_id = str(_item_value(item, "id", "") or "")
            if request_id and request_id in self._ep_ids:
                continue
            origin, path = _origin_path(str(_item_value(item, "url", "") or ""))
            if not origin:
                continue
            self.note_endpoint(origin, path, request_id)

    # -------------------------------------------------------------- trigger
    def _window_full(self) -> bool:
        return (
            len(self._mech_window) >= self._window
            and len(self._ep_window) >= self._window
        )

    def evaluate(self) -> TriggerState:
        """Compute the three mechanical inputs and the combined trigger."""

        with self._lock:
            elapsed = float(self._elapsed())
            wall = max(1.0, float(self._wall()))
            full = self._window_full()
            t2 = full and not any(self._mech_window)
            t3 = full and not any(self._ep_window)
            t1 = elapsed > T1_WALL_SECONDS
            triggered = t1 and t2 and t3
            l3_ready = triggered and elapsed >= wall / 2.0
            return TriggerState(
                elapsed_s=elapsed,
                wall_s=wall,
                t1=t1,
                t2=t2,
                t3=t3,
                triggered=triggered,
                l3_ready=l3_ready,
            )

    def unused_mechanisms(self) -> list[str]:
        """Mechanism classes not yet seen, in the frozen CAPEC order."""

        with self._lock:
            return [name for name in MECHANISM_NAMES if name not in self._mech_seen]

    # -------------------------------------------------------------- ladder
    def _pick_level(self, state: TriggerState) -> str | None:
        if not state.triggered:
            return None
        unused = self.unused_mechanisms()
        if unused and self._issued[L1] < LIMITS[L1]:
            return L1
        if not unused and self._issued[L2] < LIMITS[L2]:
            return L2
        if state.l3_ready and self._issued[L3] < LIMITS[L3]:
            return L3
        return None

    def request_injection(self, level: str | None = None) -> str | None:
        """Request one injection; return ``None`` when denied or not ready.

        The budget check happens before any text is built, so a denied request
        is both refused and non-injecting.
        """

        with self._lock:
            state = self.evaluate()
            if level is None:
                level = self._pick_level(state)
            if level is None:
                return None
            if level not in LIMITS:
                raise ValueError(f"unknown restart guard level: {level!r}")
            self._requests[level] += 1
            if self._issued[level] >= LIMITS[level]:
                return None

            if level == L2:
                text = self._build_l2_text()
            elif level == L3:
                if not state.l3_ready:
                    return None
                text = self._build_l3_text(state)
            else:
                text = self._build_l1_text()
            if text is None:
                return None
            self._issued[level] += 1
            return text

    def issued(self, level: str) -> int:
        """How many injections of ``level`` were actually emitted."""

        return int(self._issued[level])

    def requests(self, level: str) -> int:
        """How many injection requests for ``level`` were made."""

        return int(self._requests[level])

    def _build_l1_text(self) -> str | None:
        unused = self.unused_mechanisms()
        if not unused:
            return None
        current = self._last_mechanism or "unclassified"
        self._l1_policy = frozenset(unused)
        return (
            f"\n\n[RESTART GUARD L1] Mechanism class '{current}' is now marked "
            "REFUTED: it has produced no new mechanism or endpoint inside the "
            "recent window. Your next probe MUST use one of these unused "
            f"classes: {', '.join(unused)}. A classified probe outside that set "
            "will be refused by the guard. Name the exact value you expect, "
            "then send one probe that tests it."
        )

    def _build_l2_text(self) -> str | None:
        items = list(self._ledger_items())
        counts: Counter[str] = Counter()
        paths: dict[str, set[str]] = {}
        for item in items:
            origin, path = _origin_path(str(_item_value(item, "url", "") or ""))
            if not origin:
                continue
            counts[origin] += 1
            paths.setdefault(origin, set()).add(path)
        candidates = sorted(
            (count, origin)
            for origin, count in counts.items()
            if origin != self._last_origin
        )
        if not candidates:
            return None
        count, origin = candidates[0]
        discovered = ", ".join(sorted(paths.get(origin, ()))[:8]) or "(no paths yet)"
        return (
            "\n\n[RESTART GUARD L2] Every mechanism class has been used without "
            "new information. Switch attack surface: move to the least-explored "
            f"origin already discovered in the ledger: {origin} "
            f"({count} requests so far; paths: {discovered}). Do not enumerate "
            "the same origin again. Pick one unexplored path there and send a "
            "probe whose response would disconfirm your current hypothesis."
        )

    def _build_l3_text(self, state: TriggerState) -> str:
        items = list(self._ledger_items())
        remaining = max(0.0, state.wall_s - state.elapsed_s)
        return "\n\n" + build_rebuild_block(items, remaining_s=remaining)

    # -------------------------------------------------------------- probe gate
    def check_call(self, tool_name: str, args: str) -> str | None:
        """Hard-validate the next classified probe after an L1 instruction.

        Returns:
            A refusal string when the probe violates the L1 mechanism set;
            ``None`` otherwise.  Unclassifiable calls are left alone so local
            work does not get blocked by a rule about attack mechanisms.
        """

        with self._lock:
            if self._l1_policy is None or not is_probe_tool(tool_name):
                return None
            mechanism = self._mechanism_of(args or "")
            if mechanism is None:
                return None
            if mechanism in self._l1_policy:
                self._l1_policy = None
                return None
            allowed = ", ".join(
                name for name in MECHANISM_NAMES if name in self._l1_policy
            )
            return (
                "ERROR: [RESTART GUARD] The previous L1 instruction marked "
                f"'{self._last_mechanism or 'the current mechanism'}' refuted. "
                f"This probe uses '{mechanism}', which is outside the allowed "
                f"set: {allowed}. Change mechanism before sending another probe."
            )

    # -------------------------------------------------------------- observe
    def observe(self, tool_name: str, args: str, result: Any = None) -> str | None:
        """Feed one completed tool call; return an injection for its tail."""

        if not is_probe_tool(tool_name):
            return None
        try:
            mechanism = self._mechanism_of(args or "")
        except Exception:  # noqa: BLE001 - classification is best effort
            mechanism = None
        if mechanism is not None:
            self.note_mechanism(mechanism)
        self.sync_ledger()
        return self.request_injection()


def _default_wall() -> float:
    """Wall budget from the process deadline, else two T1 thresholds."""

    try:
        from ctf_strix import error_policy

        deadline = getattr(error_policy, "_deadline", None)
        if isinstance(deadline, (int, float)):
            return max(60.0, float(deadline) - _PROCESS_START)
    except Exception:  # noqa: BLE001
        pass
    return T1_WALL_SECONDS * 2.0


def _default_ledger_items() -> Sequence[Any]:
    from ctf_strix import traffic

    return traffic.ledger().items()


_GUARD: RestartGuard | None = None
_GUARD_LOCK = threading.Lock()


def current() -> RestartGuard:
    """Return the process-wide guard, creating it on first use."""

    global _GUARD  # noqa: PLW0603 - one guard per run
    with _GUARD_LOCK:
        if _GUARD is None:
            _GUARD = RestartGuard()
        return _GUARD


def reset_for_tests() -> None:
    """Drop the singleton so a test starts from a clean run state."""

    global _GUARD  # noqa: PLW0603 - test hook
    with _GUARD_LOCK:
        _GUARD = None


def attach(tool: "FunctionTool") -> "FunctionTool":
    """Wrap one tool with the restart guard, idempotently."""

    if getattr(tool, _MARK, False):
        return tool
    inner = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        guard = current()
        try:
            refusal = guard.check_call(tool.name, raw_input)
        except Exception:  # noqa: BLE001 - a guard fault must not break tools
            logger.warning("restart guard check failed", exc_info=True)
            refusal = None
        if refusal is not None:
            return refusal
        result = await inner(ctx, raw_input)
        try:
            hint = guard.observe(tool.name, raw_input, result)
        except Exception:  # noqa: BLE001
            logger.warning("restart guard observe failed", exc_info=True)
            return result
        if hint:
            return f"{result}{hint}"
        return result

    tool.on_invoke_tool = invoke
    setattr(tool, _MARK, True)
    return tool


def stats() -> dict[str, Any]:
    """Read-only snapshot for diagnostics."""

    guard = current()
    state = guard.evaluate()
    return {
        "elapsed_s": round(state.elapsed_s, 1),
        "wall_s": round(state.wall_s, 1),
        "t1": state.t1,
        "t2": state.t2,
        "t3": state.t3,
        "triggered": state.triggered,
        "l3_ready": state.l3_ready,
        "issued": {level: guard.issued(level) for level in (L1, L2, L3)},
        "limits": dict(LIMITS),
    }
