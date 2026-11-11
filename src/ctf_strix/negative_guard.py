"""Mechanical response to negative evidence, plus a truncation read-back pointer.

Two failures share one seam: the text appended after an ``exec_command`` result.

G4 -- negative evidence never changes direction.  Replaying the transcripts
showed the same command returning the same response for three or more rounds
while the model kept waiting.  Evalscope's no-progress streak of three is the
reference point.  The guard is deliberately mechanical: a group is exactly
``(normalized arguments, sha1(visible output))``.  There is no word list, no
model self-assessment, and no semantic merging of near-duplicate commands.

G5 -- truncation without a pointer.  The vendor bounded-result wrapper keeps a
head and a tail and replaces the middle with a notice.  A 998-byte response
that carried the only useful anomaly arrived as a preview and the run never
read it back.  The pointer below tells the model how to retrieve the dropped
range; it is advice, never a block.

Budgets are frozen.  ``L4: 2`` sits beside the restart guard's ``L1/L2/L3``
ceilings and is not derived from wall clock or turns.  Timing is independent:
G4 does not look at the T1 threshold.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from ctf_strix.command_tokens import command_text, segments

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: Same-command / same-response repetitions that earn one direction change.
#: Three is the autopsy's "3+ rounds" and evalscope's no-progress streak.
K: Final[int] = 3

#: The injection ceiling, declared in the same shape as the restart guard's
#: frozen ``LIMITS``.  ``L4: 2`` per run; after that the guard only counts.
L4: Final[str] = "L4"
LIMITS: Final[dict[str, int]] = {L4: 2}

CHANGE_SUMMARY_G4: Final[str] = (
    "A command that repeats its exact visible output three times gets one "
    "direction-change instruction that requires a read-back path, capped per run."
)
CHANGE_SUMMARY_G5: Final[str] = (
    "Truncated tool output carries a retrieval pointer that says how to read "
    "the dropped range back in slices."
)

#: The injected direction change.  Generic on purpose: it names no challenge,
#: path, ticket, or port, and it closes the group so it cannot nag twice.
_NEGATIVE_HINT: Final[str] = (
    "\n\n[NEGATIVE EVIDENCE GUARD] This command has now produced the same "
    "output {n} times in a row: repeating it adds no new information, so this "
    "group is closed and will not be reported again. Change direction now. "
    "State a new hypothesis in one line, and before running anything write the "
    "read-back path: which command or tool you will use, against which source, "
    "and what evidence it returns. Then run that one command. If you cannot "
    "name a read-back path, do not repeat this command."
)

#: Anchored to the vendor notice in ``strix.tools.output_store``:
#: ``[... {lines} lines ({bytes} bytes) truncated ...]`` (and the spill form).
_TRUNCATION_RE: Final[re.Pattern[str]] = re.compile(
    r"\[\.\.\. \d+ lines \(\d+ bytes\) truncated"
)
_SPILL_RE: Final[re.Pattern[str]] = re.compile(
    r"full output saved to (?P<path>\S+) in the sandbox"
)

_TRUNCATION_POINTER: Final[str] = (
    "\n\n[TOOL OUTPUT TRUNCATED] Only the head and tail of this result were "
    "shown; the middle was dropped. Do not conclude from the preview alone: "
    "read the dropped range back from the same source in slices (for example "
    "`sed -n 'START,ENDp'`, `head -n`, `tail -n`, or `grep -n` for the exact "
    "pattern) before drawing a conclusion."
)
_TRUNCATION_POINTER_WITH_PATH: Final[str] = (
    "\n\n[TOOL OUTPUT TRUNCATED] Only the head and tail of this result were "
    "shown; the middle was dropped. The full output is saved at {path}. Do not "
    "conclude from the preview alone: read the dropped range back from that "
    "file in slices (for example `sed -n 'START,ENDp' {path}` or "
    "`grep -n '<pattern>' {path}`) before drawing a conclusion."
)


def normalize_args(args: str) -> str:
    """Collapse a tool call's command to shlex tokens joined by one space.

    Deliberately literal: one changed character makes a new group, because
    "this command is the same probe" is what the counter is deciding.
    """
    text = command_text(args)
    tokens = [token for segment in segments(text) for token in segment]
    if tokens:
        return " ".join(tokens)
    return " ".join((text or "").split())


def response_signature(result: str) -> str:
    """SHA-1 of exactly what the model could see (post-truncation)."""
    return hashlib.sha1(result.encode("utf-8", "replace")).hexdigest()


def truncation_pointer(result: str) -> str | None:
    """Return a read-back pointer when ``result`` carries a truncation notice."""
    if not isinstance(result, str) or _TRUNCATION_RE.search(result) is None:
        return None
    spill = _SPILL_RE.search(result)
    if spill is not None:
        return _TRUNCATION_POINTER_WITH_PATH.format(path=spill.group("path"))
    return _TRUNCATION_POINTER


@dataclass
class _Group:
    count: int = 0
    closed: bool = False


class NegativeEvidenceGuard:
    """Counts ``(normalized args, response sha1)`` repeats; hints at K."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._groups: dict[tuple[str, str], _Group] = {}
        self._injections = 0
        self._pointers = 0

    def observe(self, tool_name: str, args: str, result: Any) -> str | None:
        """Feed one tool result; return text for its tail, or ``None``.

        Order in the returned tail is defined: the G4 direction change first,
        then the G5 truncation pointer, so the concrete retrieval instruction
        is the last thing the model reads.  Both are appended; the result
        itself is never replaced or withheld.
        """
        if tool_name != "exec_command" or not isinstance(result, str):
            return None

        key = (normalize_args(args), response_signature(result))
        parts: list[str] = []
        with self._lock:
            group = self._groups.get(key)
            if group is None:
                group = _Group()
                self._groups[key] = group
            group.count += 1
            if group.count >= K and not group.closed:
                # The group closes on threshold whether or not the global
                # ceiling still allows an injection: "count but do not nag".
                group.closed = True
                if self._injections < LIMITS[L4]:
                    self._injections += 1
                    parts.append(_NEGATIVE_HINT.format(n=group.count))

        pointer = truncation_pointer(result)
        if pointer is not None:
            with self._lock:
                self._pointers += 1
            parts.append(pointer)
        return "".join(parts) if parts else None

    def stats(self) -> dict[str, int]:
        """Read-only counters for the guard-state sidecar."""
        with self._lock:
            return {
                "groups": len(self._groups),
                "injections": self._injections,
                "limit": LIMITS[L4],
                "truncation_pointers": self._pointers,
            }


_GUARD: NegativeEvidenceGuard | None = None
_GUARD_LOCK = threading.Lock()

_MARK: Final[str] = "_ctf_negative_guarded"


def current() -> NegativeEvidenceGuard:
    """Return the process-wide guard, creating it on first use."""
    global _GUARD  # noqa: PLW0603 - one guard per run
    with _GUARD_LOCK:
        if _GUARD is None:
            _GUARD = NegativeEvidenceGuard()
        return _GUARD


def reset_for_tests() -> None:
    """Drop the singleton so a test starts from a clean run state."""
    global _GUARD  # noqa: PLW0603 - test hook
    with _GUARD_LOCK:
        _GUARD = None


def install() -> NegativeEvidenceGuard:
    """Wrap ``exec_command`` only, on the same mount seam as the other guards.

    Install it immediately after ``guard_mount.install_mount_hook()`` so it is
    the innermost guard: it sees the bounded (truncated) result before any
    other guard appends advice, which keeps the response signature stable.
    """
    from strix.agents import factory

    guard = NegativeEvidenceGuard()
    global _GUARD  # noqa: PLW0603 - the singleton shares the installed state
    with _GUARD_LOCK:
        _GUARD = guard

    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if tool.name != "exec_command":
            return tool
        if getattr(tool, _MARK, False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            try:
                hint = guard.observe(tool.name, raw_input, result)
            except Exception:  # noqa: BLE001 - a guard fault must not break tools
                logger.warning("negative evidence guard failed", exc_info=True)
                return result
            if hint:
                return f"{result}{hint}"
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard