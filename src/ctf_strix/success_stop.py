"""Success-stop discipline: finish the run as soon as the answer is confirmed.

## Why a run has to stop itself

The vendored runner treats a turn that ends without a lifecycle tool call as
an unfinished turn: it appends a "call a tool" message and runs the agent
again.  Interactive runs cap that at three nudges; autonomous runs use
``max_turns`` as the cap (``execution.py:897-923``).  In a scored container
``max_turns`` is large, so a model that writes its final summary in prose
without calling ``finish_scan`` is restarted from turn one until the budget
or the process dies.  Two measured runs lost an already-scored answer that
way.

The guard here is deliberately one-directional: nothing in this module reads
page bodies or model prose to decide that a run succeeded.  A success is
recorded only from a structured signal:

* a flag the run actually retrieved (``flag_extract``) and that the finish
  guard accepted;
* a direct JSON verdict from a submit/verify/check call *this* run made.

Once one of those arrives, :class:`SolvedStop` unwinds the run so the normal
``main`` cleanup writes ``result.json`` and exits 0.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

logger = logging.getLogger(__name__)

#: Recovery nudges before an answerless run is stopped.
#:
#: This is not a budget knob: it mirrors the limit the vendored runner already
#: applies to interactive agents (``_INTERACTIVE_TOOL_RECOVERY_LIMIT = 3``).
#: Autonomous runs were given ``max_turns`` instead, which is what turned one
#: prose-only ending into a restart loop.
RECOVERY_LIMIT = 3

#: Top-level response fields that mean "the platform graded this as solved".
#: Values must be the JSON boolean ``True``; the string ``"true"`` in a page
#: body is not a verdict.
_SUCCESS_FIELDS = ("correct", "passed", "challenge_fully_solved", "fully_solved")


class SolvedStop(BaseException):
    """The answer is confirmed; unwind the whole run now.

    ``BaseException`` for the same reason as ``WallclockExceeded``: the runner
    and the tool wrappers are full of ``except Exception``, and a swallowed
    stop would hand control back to the very loop this exists to break.
    """


class RecoveryExhausted(BaseException):
    """The agent kept ending turns without a lifecycle call.

    Raised instead of re-entering the runner, so the run ends with a
    ``result.json`` rather than a turn loop that only ``max_turns`` or OOM can
    finish.
    """


class SuccessLedger:
    """Structured evidence that this run solved the challenge.

    There is intentionally no text-entry method.  Callers can only record an
    answer that already passed the extraction/placeholders gate, or a mapping
    that came back directly from a platform call made by this run.
    """

    __slots__ = ("solved", "source", "detail", "answer")

    def __init__(self) -> None:
        self.solved = False
        self.source = ""
        self.detail = ""
        #: The confirmed answer, when the signal carries one.  A platform
        #: verdict alone (``passed: true``) has no flag to record here.
        self.answer = ""

    def mark(self, source: str, detail: str = "", *, answer: str = "") -> bool:
        """Record a success once; later signals do not overwrite the first.

        Args:
            source: short protocol-level label (``flag_extract``, ``checker``,
                ``platform_verify``, ``platform_submit``).
            detail: human-readable corroboration for diagnostics.
            answer: the confirmed answer, when known.

        Returns:
            True when the ledger is solved after this call.
        """
        if not self.solved:
            self.solved = True
            self.source = source
            self.detail = detail
            self.answer = answer
            logger.info("ctf success: %s (%s)", source, detail)
        return True

    def observe_answer(self, value: str | None, *, source: str = "flag_extract") -> bool:
        """Record a flag/value that the caller already validated.

        Args:
            value: the confirmed answer.
            source: where the confirmation came from.

        Returns:
            True when ``value`` is non-empty (and is now recorded).
        """
        if not value:
            return False
        return self.mark(source, str(value), answer=str(value))

    def observe_structured(
        self,
        response: Any,
        *,
        source: str,
        answer: str | None = None,
    ) -> bool:
        """Record a success from a platform response mapping.

        Only the top level of a mapping is inspected, and only the JSON
        boolean ``True`` counts.  Nested page content, prose, and the string
        ``"true"`` never reach this method from a text scanner because none
        exists.

        Args:
            response: the object a platform call returned.
            source: the endpoint that returned it.
            answer: the answer this call used, when the response confirms it.

        Returns:
            True when the mapping states success.
        """
        if not isinstance(response, Mapping):
            return False
        for field in _SUCCESS_FIELDS:
            if response.get(field) is True:
                return self.mark(source, f"{field}=true", answer=answer or "")
        return False

    def snapshot(self) -> dict[str, Any]:
        """Compact state for ``result.json`` diagnostics."""
        return {"solved": self.solved, "source": self.source, "detail": self.detail}


# The runner is a module-level singleton in vendor; guarding it needs module
# state rather than per-instance wrapping.  ``install_recovery_guard`` keeps
# this idempotent and restores the original on uninstall.
_ACTIVE_LIMIT = RECOVERY_LIMIT
_ACTIVE_CHECKER: Callable[[], Awaitable[bool] | bool] | None = None
_ACTIVE_LEDGER: SuccessLedger | None = None


async def _probe_once() -> bool:
    """Ask the active checker whether the challenge is solved.

    Returns:
        True when a direct structured verdict says solved.
    """
    checker = _ACTIVE_CHECKER
    if checker is None:
        return False
    try:
        result = checker()
        if isinstance(result, Awaitable):
            result = await result
        return bool(result)
    except Exception:  # noqa: BLE001 -- a probe failure must not mask the loop guard
        logger.warning("ctf checker probe failed", exc_info=True)
        return False


def install_recovery_guard(
    *,
    limit: int = RECOVERY_LIMIT,
    checker: Callable[[], Awaitable[bool] | bool] | None = None,
    ledger: SuccessLedger | None = None,
) -> bool:
    """Bound the runner's "no lifecycle call" recovery loop.

    The wrapper counts *consecutive* recovery nudges per agent, exactly like
    the runner's own counter (which resets on a lifecycle tool).  At the first
    nudge it asks our own checker, because a turn can end in prose right after
    the answer was scored.  At ``limit`` it raises instead of starting another
    cycle.

    Args:
        limit: consecutive nudges allowed.  Defaults to the runner's own
            interactive limit; tests use small values.
        checker: optional async/sync callable that performs *our* structured
            platform check and returns whether it passed.
        ledger: optional ledger to mark when the checker confirms success.

    Returns:
        True when the guard is installed (idempotent).
    """
    global _ACTIVE_LIMIT, _ACTIVE_CHECKER, _ACTIVE_LEDGER
    from strix.core.agents import AgentCoordinator

    _ACTIVE_LIMIT = max(1, int(limit))
    _ACTIVE_CHECKER = checker
    _ACTIVE_LEDGER = ledger

    original = getattr(AgentCoordinator, "_ctf_original_record_recovery", None)
    if original is not None:
        return True

    original = AgentCoordinator.record_recovery
    AgentCoordinator._ctf_original_record_recovery = original  # type: ignore[attr-defined]

    async def record_recovery(self: Any, agent_id: str) -> int:
        # Only the root agent restarts the whole run; a child ending in prose
        # is its parent's problem and is already bounded by the runner.
        is_root = self.parent_of.get(agent_id) is None
        if not is_root:
            return await original(self, agent_id)

        count = await original(self, agent_id)
        # A success recorded during the turn (flag read or a platform verdict)
        # must win immediately: the runner is about to restart the session, and
        # there is nothing left for a new cycle to discover.
        if _ACTIVE_LEDGER is not None and _ACTIVE_LEDGER.solved:
            raise SolvedStop(f"solved via {_ACTIVE_LEDGER.source}: {_ACTIVE_LEDGER.detail}")
        if count == 1 and _ACTIVE_CHECKER is not None:
            if await _probe_once():
                if _ACTIVE_LEDGER is not None:
                    _ACTIVE_LEDGER.mark("checker", "recovery probe")
                raise SolvedStop("checker confirmed the challenge before recovery")
        if count >= _ACTIVE_LIMIT:
            raise RecoveryExhausted(
                f"agent ended {count} turns without a lifecycle tool call"
            )
        return count

    AgentCoordinator.record_recovery = record_recovery  # type: ignore[method-assign]
    return True


def uninstall_recovery_guard() -> None:
    """Restore the vendored ``record_recovery`` (tests and rollback)."""
    global _ACTIVE_CHECKER, _ACTIVE_LEDGER
    from strix.core.agents import AgentCoordinator

    original = getattr(AgentCoordinator, "_ctf_original_record_recovery", None)
    if original is not None:
        AgentCoordinator.record_recovery = original  # type: ignore[method-assign]
        del AgentCoordinator._ctf_original_record_recovery  # type: ignore[attr-defined]
    _ACTIVE_CHECKER = None
    _ACTIVE_LEDGER = None
