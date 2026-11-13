"""Opt-in parallel hypothesis racing for CTF runs.

The vendored runner already supports child agents, but its default prompt tells
the root to delegate everything.  Measured runs spent 22% of their calls on
coordination, so the CTF toolset removes the agent-graph tools by default.

This module adds a narrow, CTF-specific protocol instead of restoring that
behaviour:

* the root may spawn at most two children for the whole run;
* children may not spawn grandchildren;
* a flag seen in a child's tool output is a race win: the root is woken and
  every other child is stopped;
* a structured platform verdict (``exec_verdict``) seen in a child's shell
  output is the same win; #4b's observer already validated it, this module only
  forwards the notification to the root;
* a root ``finish_scan`` that carries a proven flag stops live children before
  the vendored tool's "no active agents" check can reject it.

All of this is installed by wrapping ``factory._with_bounded_result``, the same
seam the other CTF guards use.  Vendor files stay untouched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

from ctf_strix.flag_extract import CANDIDATE_RE, is_placeholder

logger = logging.getLogger(__name__)

#: Hard ceiling from the run constraints: container memory is the limiting
#: resource and a single runaway agent has already produced exit 137.  This is
#: deliberately a constant, not an environment-tunable budget.
MAX_SUBAGENTS = 2

#: 取宽集（``CANDIDATE_RE``）：这里只判"子 agent 的输出里有没有答案形状"，
#: 宽一点不会漏掉竞速取胜的机会；窄集留给落盘与提交。
_FLAG_RE = CANDIDATE_RE
_LOCK = threading.Lock()
_INSTALLED = False
#: Strong references to race-stop tasks.  ``asyncio`` keeps only a weak
#: reference to a task, so a short-lived stop could be garbage-collected
#: before it wakes the root or stops a sibling.
_STOP_TASKS: set[asyncio.Task[Any]] = set()
_ORIGINAL: Any = None
_SPAWNED = 0
_ANNOUNCED = False
_RACE_STOPPED = False
_SUCCESS: Any = None
_EVIDENCE: Any = None
_COORDINATOR: Any = None
_ROOT_ID: str | None = None
_BRIDGE_INSTALLED = False
_BRIDGE_ORIGINAL: Any = None
_BRIDGE_PATCHED: Any = None


def enabled() -> bool:
    """Return whether the caller asked for the opt-in sub-agent path.

    Delegates to :func:`ctf_strix.tool_trim.subagents_allowed` so the tool
    surface, the prompt, the runtime guard and the tests cannot disagree about
    what "on" means (``1`` / ``true`` / ``yes`` / ``on``).
    """
    from ctf_strix.tool_trim import subagents_allowed

    return subagents_allowed()


def configure(
    *,
    success: Any = None,
    evidence: Any = None,
    coordinator: Any = None,
) -> None:
    """Bind per-run state used by the guards.

    Args:
        success: the run's ``SuccessLedger``.
        evidence: the run's ``EvidenceLedger``; a finish argument only counts
            when the same string was already seen in a tool output.
        coordinator: the attempt's ``AgentCoordinator``.  It lets the sink stop
            children and wake the root without waiting for the next turn.
    """
    global _SUCCESS, _EVIDENCE, _COORDINATOR
    _SUCCESS = success
    _EVIDENCE = evidence
    _COORDINATOR = coordinator


def reset_run() -> None:
    """Reset per-run counters.  The guard patch itself stays installed."""
    global _SPAWNED, _ANNOUNCED, _RACE_STOPPED, _COORDINATOR, _ROOT_ID
    global _SUCCESS, _EVIDENCE
    with _LOCK:
        _SPAWNED = 0
        _ANNOUNCED = False
        _RACE_STOPPED = False
        _ROOT_ID = None
        # A later run gets fresh bindings.  Keeping the previous coordinator or
        # ledger would let a race stop address agents from a closed session, or
        # report a success that belongs to a finished attempt.
        _COORDINATOR = None
        _SUCCESS = None
        _EVIDENCE = None


def bind_attempt(coordinator: Any) -> None:
    """Point the guard at a new attempt's coordinator.

    Each ``run_strix_scan`` attempt owns a separate ``AgentCoordinator``.  The
    spawn count and the announced flag are per run and must survive, but the
    previous attempt's root id and graph are closed; keeping them would make
    ``root_id`` label the new root as a child.
    """
    global _COORDINATOR, _ROOT_ID
    with _LOCK:
        _COORDINATOR = coordinator
        _ROOT_ID = None


def root_id() -> str | None:
    """Return the run's root agent id, or ``None`` when it is not known yet.

    The coordinator graph is authoritative: on a resumed run the vendored
    runner respawns children before the root's first event, so "first agent id
    seen by the sink" is not a safe definition of the root.  ``_ROOT_ID`` is
    only a fallback recorded from a race win or a test binding.
    """
    coordinator = _COORDINATOR
    if coordinator is not None:
        try:
            for aid, parent in coordinator.parent_of.items():
                if parent is None:
                    return aid
        except Exception:  # noqa: BLE001 - fall through to the recorded id
            pass
    return _ROOT_ID


def bind_root(agent_id: str) -> None:
    """Remember a root id when the coordinator graph is not available."""
    global _ROOT_ID
    if _ROOT_ID is None and agent_id:
        _ROOT_ID = agent_id


def is_root(agent_id: str) -> bool:
    """Whether `agent_id` is the root of the current run.

    The sink raises `SolvedStop` to unwind the run, but a child task is not
    caught by the vendored runner (it only handles budget errors), so a child
    raising it would surface as an unhandled task exception.  Only the root is
    allowed to stop the whole process; a child just sees its stop request.
    """
    rid = root_id()
    if rid is None:
        return True
    return agent_id == rid


def stats() -> dict[str, Any]:
    """Compact state for ``result.json`` diagnostics."""
    with _LOCK:
        return {
            "enabled": enabled(),
            "max_subagents": MAX_SUBAGENTS,
            "spawned": _SPAWNED,
            "race_announced": _ANNOUNCED,
            "race_stopped": _RACE_STOPPED,
            "exec_bridge": _BRIDGE_INSTALLED,
        }


def usage_summary(
    *,
    root_turns: int,
    before: dict[str, int] | None,
    after: dict[str, int] | None,
) -> dict[str, int]:
    """Aggregate root and child LLM usage for one parallel run.

    ``usage_meter`` is process-wide and already counts every agent, so child
    calls are the run delta minus the root's own request count.  The result is
    only accounting: it does not feed back into any budget.
    """
    before = before or {}
    after = after or {}
    total = max(int(after.get("llm_calls", 0)) - int(before.get("llm_calls", 0)), 0)
    input_tokens = max(
        int(after.get("input_tokens", 0)) - int(before.get("input_tokens", 0)), 0
    )
    output_tokens = max(
        int(after.get("output_tokens", 0)) - int(before.get("output_tokens", 0)), 0
    )
    child = max(total - max(int(root_turns), 0), 0)
    return {
        "root_turns": max(int(root_turns), 0),
        "child_llm_calls": child,
        "total_llm_calls": total,
        # A vendor run result can report more requests than the meter observed
        # (e.g. an aborted attempt).  Never publish a total below the root's
        # own count; that would make a parallel run look cheaper than its
        # parent.
        "turns": max(total, max(int(root_turns), 0)),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def note_success(agent_id: str, flag: str, *, root_id: str | None = None) -> None:
    """Announce a flag-based race win and stop the other agents.

    Called from the synchronous event sink.  The actual coordinator work is
    scheduled on the running loop; the sink can then return and let the runner
    deliver the next event, where ``success.solved`` raises ``SolvedStop``.
    """
    note_race_win(agent_id, flag, source="flag_extract", root_id=root_id)


def note_race_win(
    agent_id: str,
    flag: str,
    *,
    source: str,
    root_id: str | None = None,
) -> None:
    """Announce a validated race win and stop the other agents.

    Two producers feed this: the text flag extractor (``flag_extract``) and
    #4b's shell observer, which records a platform verdict (``exec_verdict``)
    only after parsing a complete ``/check`` or ``/submissions`` response.  The
    verdict arrives with no flag string, so the message carries the ledger
    detail instead; both paths wake the root the same way.

    Args:
        agent_id: the child that won (or the root for a root-side win).
        flag: the confirmed flag, or the verdict detail when no flag exists.
        source: ledger source label, carried into diagnostics.
        root_id: the root agent id, when already known.
    """
    global _ANNOUNCED, _ROOT_ID
    if not flag:
        return
    if root_id is not None and _ROOT_ID is None:
        _ROOT_ID = root_id
    # Record the win in the run's structured ledger before scheduling any
    # coordinator work.  `SolvedStop` is driven by `success.solved`; without
    # this the root could receive the message and still finish as completed.
    if _SUCCESS is not None:
        if source == "flag_extract":
            _SUCCESS.observe_answer(flag, source=source)
        else:
            _SUCCESS.mark(source, flag)
    with _LOCK:
        if _ANNOUNCED:
            return
        _ANNOUNCED = True
    coordinator = _COORDINATOR
    if coordinator is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.warning("parallel race: no running loop to stop agents")
        return
    task = loop.create_task(
        _stop_for_race(
            coordinator,
            root_id=root_id,
            winner_id=agent_id,
            flag=flag,
            source=source,
        ),
        name="ctf-parallel-stop",
    )
    _STOP_TASKS.add(task)
    task.add_done_callback(_STOP_TASKS.discard)


async def _stop_for_race(
    coordinator: Any,
    *,
    root_id: str | None,
    winner_id: str,
    flag: str,
    source: str,
) -> None:
    global _RACE_STOPPED
    try:
        if root_id is None:
            root_id = next(
                (aid for aid, parent in coordinator.parent_of.items() if parent is None),
                None,
            )
        if root_id is not None and winner_id != root_id:
            if source == "flag_extract":
                outcome = f"The answer seen in tool output was: {flag}"
            else:
                outcome = (
                    "The platform verdict was already recorded by the shell "
                    f"observer ({flag}); retrieve the answer if one exists"
                )
            await coordinator.send(
                root_id,
                {
                    "from": winner_id,
                    "type": "success",
                    "priority": "high",
                    "content": (
                        "A parallel sub-agent retrieved the answer. Stop all work now; "
                        "do not wait, do not spawn another agent, and do not restart the "
                        f"search. {outcome}"
                    ),
                },
                interrupt=True,
            )
        active = await coordinator.active_agents_except(root_id or "")
        for info in active:
            await coordinator.request_stop(info["agent_id"])
        _RACE_STOPPED = True
        logger.info(
            "parallel race: winner=%s stopped=%d root=%s",
            winner_id,
            len(active),
            root_id or "-",
        )
    except Exception:  # noqa: BLE001 - a race stop must never crash the run
        logger.exception("parallel race: stopping agents failed")


def install() -> bool:
    """Install the guard on ``factory._with_bounded_result``.

    Idempotent for the process.  Per-run state is replaced by
    :func:`configure` and :func:`reset_run`.
    """
    global _INSTALLED, _ORIGINAL
    if _INSTALLED:
        return True
    try:
        from strix.agents import factory
    except Exception:  # noqa: BLE001 - vendor unavailable in some unit tests
        return False

    _ORIGINAL = factory._with_bounded_result

    def patched(tool: Any) -> Any:
        return wrap_tool(_ORIGINAL(tool))

    factory._with_bounded_result = patched
    _INSTALLED = True
    return True


def uninstall() -> None:
    """Restore the previous mount function (tests and rollback)."""
    global _INSTALLED, _ORIGINAL
    uninstall_exec_bridge()
    if not _INSTALLED:
        return
    try:
        from strix.agents import factory

        if _ORIGINAL is not None:
            factory._with_bounded_result = _ORIGINAL
    finally:
        _INSTALLED = False
        _ORIGINAL = None


def install_exec_bridge() -> bool:
    """Forward a child's structured shell verdict to the race protocol.

    #4b's exec observer validates a ``/check`` or ``/submissions`` response and
    then raises ``SolvedStop``.  On the root that unwinds the run correctly; on
    a child the exception escapes its detached task, so the root is never
    woken and the other children keep burning turns.  This wrapper sits
    outside the observer and turns that already-validated verdict into the same
    race win a text flag produces.

    It deliberately does **not** re-validate or widen anything: the solve must
    already be in ``SuccessLedger``.  Text flags normally go through
    ``note_success`` directly; the bridge only matters when a later shell call
    would otherwise raise a second ``SolvedStop`` in the same child.

    On the root the exception is re-raised so ``agent.main`` unwinds as before.
    On a child it is consumed: that task is detached from the runner's
    ``except Exception`` handling, and a ``BaseException`` escaping it would
    only surface as ``Task exception was never retrieved``.  The race stop
    scheduled by ``note_race_win`` is what ends the child.

    Must be installed *after* ``success_stop.install_exec_observer`` so the
    bridge is the outer wrapper on ``exec_command`` / ``write_stdin``.
    """
    global _BRIDGE_INSTALLED, _BRIDGE_ORIGINAL, _BRIDGE_PATCHED
    if _BRIDGE_INSTALLED:
        return True
    try:
        from strix.agents import factory
    except Exception:  # noqa: BLE001 - vendor unavailable in some unit tests
        return False

    original = factory._with_bounded_result
    _BRIDGE_ORIGINAL = original

    def patched(tool: Any) -> Any:
        tool = original(tool)
        if getattr(tool, "name", "") not in ("exec_command", "write_stdin"):
            return tool
        if getattr(tool, "_ctf_parallel_bridge", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            try:
                return await inner(ctx, raw_input)
            except BaseException as exc:
                from ctf_strix.success_stop import SolvedStop

                if not isinstance(exc, SolvedStop):
                    raise
                success = _SUCCESS
                if success is None or not getattr(success, "solved", False):
                    raise
                source = str(getattr(success, "source", "") or "")
                context = _context(ctx)
                agent_id = str(context.get("agent_id") or "")
                root = _ROOT_ID or root_id()
                # A child is proven either by the graph or by its parent_id.
                # With neither signal we cannot tell, so leave the original
                # exception alone rather than stopping a random agent.
                is_child = context.get("parent_id") is not None or (
                    root is not None and agent_id != root
                )
                if not is_child:
                    raise
                detail = str(getattr(success, "detail", "") or "verdict recorded")
                # A child must never propagate SolvedStop: its task is detached
                # from the runner's handler.  If the win was already announced
                # by the flag path this call is a no-op; otherwise it wakes the
                # root exactly once.
                payload = str(getattr(success, "answer", "") or "") or detail
                note_race_win(agent_id, payload, source=source, root_id=root)
                return json.dumps(
                    {
                        "success": True,
                        "note": "platform verdict recorded; race stop requested",
                    }
                )

        tool.on_invoke_tool = invoke
        tool._ctf_parallel_bridge = True  # type: ignore[attr-defined]
        return tool

    _BRIDGE_PATCHED = patched
    factory._with_bounded_result = patched  # type: ignore[assignment]
    _BRIDGE_INSTALLED = True
    return True


def uninstall_exec_bridge() -> None:
    """Remove the bridge wrapper when it is still the outermost one."""
    global _BRIDGE_INSTALLED, _BRIDGE_ORIGINAL, _BRIDGE_PATCHED
    if not _BRIDGE_INSTALLED:
        return
    try:
        from strix.agents import factory

        # Only undo our own layer.  If another guard was installed after us,
        # replacing the attribute here would silently unhook it.
        if _BRIDGE_PATCHED is not None and factory._with_bounded_result is _BRIDGE_PATCHED:
            factory._with_bounded_result = _BRIDGE_ORIGINAL  # type: ignore[assignment]
    except Exception:  # noqa: BLE001 - a missing runtime has nothing to restore
        pass
    finally:
        _BRIDGE_INSTALLED = False
        _BRIDGE_ORIGINAL = None
        _BRIDGE_PATCHED = None


def wrap_tool(tool: Any) -> Any:
    """Apply the parallel protocol to one built tool."""
    name = getattr(tool, "name", "")
    if name == "create_agent":
        return _wrap_create_agent(tool)
    if name == "agent_finish":
        return _wrap_agent_finish(tool)
    if name == "finish_scan":
        return _wrap_finish_scan(tool)
    return tool


def _wrap_create_agent(tool: Any) -> Any:
    if getattr(tool, "_ctf_parallel_create", False):
        return tool
    inner = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        context = _context(ctx)
        if context.get("coordinator") is not None:
            _bind_coordinator(context["coordinator"])
        if context.get("parent_id") is not None:
            return _json(
                {
                    "success": False,
                    "error": (
                        "REFUSED: nested sub-agents are disabled in CTF mode. "
                        "Do your assigned direction yourself and report back."
                    ),
                }
            )
        with _LOCK:
            global _SPAWNED
            if _SPAWNED >= MAX_SUBAGENTS:
                return _json(
                    {
                        "success": False,
                        "error": (
                            f"REFUSED: this run allows at most {MAX_SUBAGENTS} sub-agents. "
                            "Work with the agents already running, or stop one and continue "
                            "yourself."
                        ),
                        "subagent_limit": MAX_SUBAGENTS,
                        "spawned": _SPAWNED,
                    }
                )
            _SPAWNED += 1
        try:
            result = await inner(ctx, raw_input)
        except BaseException:
            _rollback_spawn()
            raise
        if not _succeeded(result):
            _rollback_spawn()
        return result

    tool.on_invoke_tool = invoke
    tool._ctf_parallel_create = True  # type: ignore[attr-defined]
    return tool


def _rollback_spawn() -> None:
    global _SPAWNED
    with _LOCK:
        _SPAWNED = max(0, _SPAWNED - 1)


def _wrap_agent_finish(tool: Any) -> Any:
    if getattr(tool, "_ctf_parallel_finish", False):
        return tool
    inner = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        context = _context(ctx)
        # The coordinator is only reachable from the running agent context.
        # Binding it here (once, per tool call) is what lets a child's success
        # stop its siblings without waiting for the root's next turn.
        if context.get("coordinator") is not None:
            _bind_coordinator(context["coordinator"])
        _observe_lifecycle_claim(ctx, raw_input, source="agent_finish")
        return await inner(ctx, raw_input)

    tool.on_invoke_tool = invoke
    tool._ctf_parallel_finish = True  # type: ignore[attr-defined]
    return tool


def _wrap_finish_scan(tool: Any) -> Any:
    if getattr(tool, "_ctf_parallel_scan", False):
        return tool
    inner = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        context = _context(ctx)
        if context.get("coordinator") is not None:
            _bind_coordinator(context["coordinator"])
        if _should_stop_children(raw_input):
            await _stop_children(ctx)
        return await inner(ctx, raw_input)

    tool.on_invoke_tool = invoke
    tool._ctf_parallel_scan = True  # type: ignore[attr-defined]
    return tool


def _observe_lifecycle_claim(ctx: Any, raw_input: str, *, source: str) -> None:
    context = _context(ctx)
    agent_id = str(context.get("agent_id") or "")
    for flag in _flags(raw_input):
        if _EVIDENCE is not None and not _EVIDENCE.supports(flag):
            continue
        if _SUCCESS is not None:
            _SUCCESS.observe_answer(flag, source=source)
        note_success(agent_id, flag)
        return


def _should_stop_children(raw_input: str) -> bool:
    if _SUCCESS is not None and getattr(_SUCCESS, "solved", False):
        return True
    flags = _flags(raw_input)
    if not flags:
        return False
    if _EVIDENCE is None:
        return True
    return any(_EVIDENCE.supports(flag) for flag in flags)


async def _stop_children(ctx: Any) -> None:
    global _RACE_STOPPED
    coordinator = _context(ctx).get("coordinator") or _COORDINATOR
    if coordinator is None:
        return
    root_id = _context(ctx).get("agent_id")
    try:
        active = await coordinator.active_agents_except(str(root_id or ""))
        for info in active:
            await coordinator.request_stop(info["agent_id"])
        if active:
            _RACE_STOPPED = True
            logger.info("parallel: stopped %d child agent(s) before finish_scan", len(active))
    except Exception:  # noqa: BLE001 - finish must still be attempted
        logger.exception("parallel: stopping children before finish_scan failed")


def _context(ctx: Any) -> dict[str, Any]:
    value = getattr(ctx, "context", None)
    return value if isinstance(value, dict) else {}


def _bind_coordinator(coordinator: Any) -> None:
    global _COORDINATOR, _ROOT_ID
    _COORDINATOR = coordinator
    if _ROOT_ID is None:
        try:
            _ROOT_ID = next(
                (aid for aid, parent in coordinator.parent_of.items() if parent is None),
                None,
            )
        except Exception:  # noqa: BLE001 - an unknown graph keeps the fallback
            _ROOT_ID = None


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)


def _flags(text: str) -> list[str]:
    return [
        match.group(0)
        for match in _FLAG_RE.finditer(text or "")
        if not is_placeholder(match.group(0))
    ]


def flags_in_text(text: str) -> list[str]:
    """Public, placeholder-free flag scan used by the entrypoint's sink."""
    return _flags(text)


def _succeeded(result: Any) -> bool:
    if isinstance(result, dict):
        return bool(result.get("success"))
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except (TypeError, ValueError):
            return '"success": true' in result.lower()
        return bool(parsed.get("success")) if isinstance(parsed, dict) else True
    return True
