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

import json
import logging
import re
import shlex
import threading
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

#: Recovery nudges before an answerless run is stopped.
#:
#: This is not a budget knob: it mirrors the limit the vendored runner already
#: applies to interactive agents (``_INTERACTIVE_TOOL_RECOVERY_LIMIT = 3``).
#: Autonomous runs were given ``max_turns`` instead, which is what turned one
#: prose-only ending into a restart loop.
RECOVERY_LIMIT = 3

#: Generic ledger fields.  Endpoint callers use :func:`check_verdict` and
#: :func:`answer_verdict` instead; this tuple only backs the deliberately
#: generic ``observe_structured`` helper.
_SUCCESS_FIELDS = ("correct", "passed", "challenge_fully_solved", "fully_solved")

#: Shell-envelope lines emitted by ``exec_command`` before the real output.
_SHELL_META_RE = re.compile(
    r"^(?:Chunk ID:|Wall time:|Process exited with code|Output:\s*$)"
)

#: curl/wget options that can redirect a request away from the parsed URL.
_FORBIDDEN_OPTIONS = {
    "--resolve",
    "--connect-to",
    "--unix-socket",
    "--proxy",
    "--proxy-user",
    "--interface",
    "--dns-servers",
    "--config",
    "-k",
    "--insecure",
    "-x",
}

_CURL_DATA_OPTIONS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--json",
    "--form",
}


def _as_question_id(value):
    """Normalise a question id without inventing one."""
    return str(value).strip() if value is not None else ""


def check_verdict(response, question_id, *, multiple=False):
    """Validate a ``POST /check`` response for one known question.

    ``/check`` is not the same contract as ``/submissions``: it reports
    ``passed`` plus a timeout flag, and a multi-question challenge is only
    complete when the platform says so explicitly.

    Args:
        response: parsed JSON response.
        question_id: the id this request asked about.
        multiple: whether this run has more than one question id.

    Returns:
        True only for a complete, non-timed-out verdict for ``question_id``.
    """
    if not isinstance(response, Mapping):
        return False
    if response.get("passed") is not True:
        return False
    if response.get("timed_out") is not False:
        return False
    if _as_question_id(response.get("question_id")) != _as_question_id(question_id):
        return False
    if multiple and response.get("challenge_fully_solved") is not True:
        return False
    return True


def answer_verdict(
    response: Any,
    question_id: str,
    *,
    multiple: bool = False,
) -> bool:
    """Validate a ``/submissions`` or ``/verify-answer`` response.

    Args:
        response: parsed JSON response.
        question_id: the id this request answered.
        multiple: whether this run has more than one question.  ``/submissions``
            then also has to say ``challenge_fully_solved``;
            ``/verify-answer`` has no such field, so it cannot prove a whole
            multi-question challenge on its own.

    Returns:
        True only when the platform marked this exact question correct and,
        for a multi-question submission, the whole challenge complete.
    """
    if not isinstance(response, Mapping):
        return False
    if response.get("correct") is not True:
        return False
    if _as_question_id(response.get("question_id")) != _as_question_id(question_id):
        return False
    if multiple and response.get("challenge_fully_solved") is not True:
        return False
    return True


def question_correct(response: Any, question_id: str) -> bool:
    """Per-question correctness, ignoring whether the whole challenge is done.

    A multi-question challenge reports one ``correct`` per submission; that is
    useful progress and belongs in the summary, but it must not set the
    run-wide solved flag on its own.
    """
    if not isinstance(response, Mapping):
        return False
    if response.get("correct") is not True:
        return False
    return _as_question_id(response.get("question_id")) == _as_question_id(question_id)


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


def _command_text(raw_input: str) -> str:
    """Command-like text from a shell tool's arguments.

    Only the actual command fields are the command anchor.  Scanning the whole
    JSON payload would let an unrelated field (for example `workdir`) supply
    the platform host and turn a local `cat` into a false verdict.
    """
    text = raw_input or ""
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return text
    if not isinstance(parsed, dict):
        return text
    for key in ("cmd", "command", "chars"):
        value = parsed.get(key)
        if isinstance(value, str):
            return value
    return ""


def _single_json_object(output: Any) -> dict[str, Any] | None:
    """Return the one JSON object a shell call printed, or ``None``.

    The SDK prefixes shell output with a short metadata envelope.  Only those
    known lines are dropped; everything after them must parse as one complete
    JSON object.  A page body, a log line, or two concatenated objects are not
    a verdict, so there is deliberately no "find the object in prose" fallback.
    """
    if isinstance(output, Mapping):
        return dict(output)
    if not isinstance(output, str):
        return None
    lines = output.splitlines()
    while lines and (not lines[0].strip() or _SHELL_META_RE.match(lines[0].strip())):
        lines.pop(0)
    body = "\n".join(lines).strip()
    if not body:
        return None
    try:
        value = json.loads(body)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


#: Options whose following token is a value, not the request URL.
_VALUE_OPTIONS = {
    "-X",
    "--request",
    "-H",
    "--header",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--json",
    "-F",
    "--form",
    "-u",
    "--user",
    "-A",
    "--user-agent",
    "-e",
    "--referer",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-o",
    "--output",
    "-m",
    "--max-time",
    "--connect-timeout",
    "--url",
    "--method",
    "-O",
    "--output-document",
    "--post-data",
    "--post-file",
    "--body-data",
    "--header",
    "--user-agent",
}


def _command_tokens(command_text: str) -> list[str] | None:
    """Split a command into one simple curl/wget invocation.

    Shell syntax is rejected rather than modelled: only a single command whose
    program is curl/wget is accepted.  This keeps ``cat``/``echo``/heredoc and
    redirection tricks out of the trust path.
    """
    text = (command_text or "").strip()
    if not text:
        return None
    if any(token in text for token in (";", "&&", "||", "|", ">", "<", "`", "$(")):
        return None
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return None
    if not tokens:
        return None
    program = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if program.endswith(".exe"):
        program = program[:-4]
    if program not in ("curl", "wget"):
        return None
    return tokens


def _request_url(tokens: list[str]) -> tuple[str, str] | None:
    """Return ``(method, url)`` for a simple curl/wget command.

    Method and URL are both read structurally.  A data flag means curl's
    implicit POST; otherwise the explicit request method is required.
    """
    program = tokens[0].lower()
    positional: list[str] = []
    method = ""
    has_data = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("--") and "=" in token:
            name, value = token.split("=", 1)
            # ``--resolve=...`` is the long-option spelling of the same
            # redirection and used to slip past the token-list check.  Reject
            # the whole family before looking at the value.
            if name in _FORBIDDEN_OPTIONS or name in ("--post-file", "--config"):
                return None
            if name == "--url":
                positional.append(value)
            elif name in ("--method", "--request"):
                method = value.strip().upper()
            elif name in ("--post-data", "--body-data"):
                has_data = True
            index += 1
            continue
        if token in _FORBIDDEN_OPTIONS:
            return None
        if token in ("-X", "--request"):
            if index + 1 >= len(tokens):
                return None
            method = tokens[index + 1].strip().upper()
            index += 2
            continue
        if token in ("--url",):
            if index + 1 >= len(tokens):
                return None
            positional.append(tokens[index + 1])
            index += 2
            continue
        if token in ("--method",):
            if index + 1 >= len(tokens):
                return None
            method = tokens[index + 1].strip().upper()
            index += 2
            continue
        if token in ("--post-file", "--config"):
            return None
        if token in _CURL_DATA_OPTIONS:
            has_data = True
            index += 2
            continue
        if token in _VALUE_OPTIONS:
            index += 2
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        positional.append(token)
        index += 1

    if len(positional) != 1:
        return None
    url = positional[0]
    if not method:
        method = "POST" if has_data and program in ("curl", "wget") else ""
    if method not in ("POST", "GET"):
        return None
    return method, url


def _request_body(tokens: list[str]) -> dict[str, Any]:
    """Return the inline JSON request body, or ``{}``.

    A body read from ``@file`` or stdin is not an independent anchor, so it is
    deliberately ignored rather than trusted.
    """
    raw = ""
    index = 1
    while index < len(tokens):
        token = tokens[index]
        value = ""
        if token in ("-d", "--data", "--data-raw", "--data-binary", "--json"):
            value = tokens[index + 1] if index + 1 < len(tokens) else ""
        elif token.startswith(("--data=", "--data-raw=", "--data-binary=", "--json=")):
            value = token.split("=", 1)[1]
        elif token.startswith("-d") and len(token) > 2:
            value = token[2:]
        if value and not value.startswith("@"):
            raw = value
        index += 1
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _verdict_endpoint(url: str, platform_url: str, instance: str) -> str:
    """Classify a URL by exact scheme/host/port/path match.

    Returns ``check``, ``verify``, ``submit``, ``qa``, or an empty string.
    Substring matching is intentionally absent: ``evilctfy.io`` and
    ``/check.json`` are different hosts and paths.
    """
    try:
        target = urlsplit(url)
        base = urlsplit(platform_url if "://" in platform_url else f"//{platform_url}")
    except ValueError:
        return ""
    if target.scheme.lower() not in ("http", "https"):
        return ""
    if base.scheme and target.scheme.lower() != base.scheme.lower():
        return ""
    if target.username or target.password or target.query or target.fragment:
        return ""
    if target.hostname is None or base.hostname is None:
        return ""
    if target.hostname.lower() != base.hostname.lower():
        return ""
    if target.port != base.port:
        return ""
    path = target.path.rstrip("/")
    prefix = base.path.rstrip("/")
    instance = str(instance or "").strip()
    if instance and path == f"{prefix}/api/v1/instances/{instance}/check":
        return "check"
    if instance and path == f"{prefix}/api/v1/instances/{instance}/verify-answer":
        return "verify"
    if path == f"{prefix}/api/v1/submissions":
        return "submit"
    if path == f"{prefix}/api/v1/qa/submissions":
        return "qa"
    return ""


def observe_platform_output(
    success: SuccessLedger,
    command_text: str,
    output: Any,
    *,
    platform_url: str = "",
    instance: str = "",
    question_ids: tuple[str, ...] = (),
) -> bool:
    """Record a solve only when the command and output both carry the verdict.

    Args:
        success: ledger to update.
        command_text: the command that produced ``output``.
        output: the tool result.
        platform_url: platform root URL, used for exact scheme/host/port match.
        instance: this run's instance id, used to pin ``/instances/{id}/...``.
        question_ids: this run's question ids; the response must name one.

    Returns:
        True when a validated endpoint verdict was recorded.
    """
    if not platform_url or not instance or not question_ids:
        return False
    tokens = _command_tokens(command_text)
    if tokens is None:
        return False
    parsed = _request_url(tokens)
    if parsed is None:
        return False
    method, url = parsed
    if method != "POST":
        return False
    endpoint = _verdict_endpoint(url, platform_url, instance)
    if not endpoint:
        return False
    response = _single_json_object(output)
    if response is None:
        return False
    body = _request_body(tokens)
    body_qid = _as_question_id(body.get("question_id"))
    body_instance = _as_question_id(body.get("instance_id"))
    if body_instance and body_instance != str(instance):
        return False
    qid = _as_question_id(response.get("question_id"))
    known = {_as_question_id(q) for q in question_ids if _as_question_id(q)}
    if not qid or qid not in known:
        return False
    if body_qid and body_qid != qid:
        return False
    response_instance = _as_question_id(response.get("instance_id"))
    if response_instance and response_instance != str(instance):
        return False
    multiple = len(known) > 1
    if endpoint == "check":
        if not check_verdict(response, qid, multiple=multiple):
            return False
        detail = "passed=true"
    else:
        if not answer_verdict(response, qid, multiple=multiple):
            return False
        detail = "correct=true"
    return success.mark("exec_verdict", detail)


#: Active shell-observer binding for this run:
#: ``(ledger, platform URL, instance, question ids)``.  The wrapper is
#: installed once per process; each run rebinds the tuple so a later task
#: cannot resurrect a previous run's success.
_ACTIVE_EXEC_OBSERVER: (
    tuple[SuccessLedger, str, str, tuple[str, ...]] | None
) = None

#: Shell session id -> command text that opened it.  ``write_stdin`` only has a
#: ``session_id``, so a long-running curl that yields and is polled later would
#: lose the command anchor without this.  Bounded: sessions are short-lived and
#: a run issues only a handful; keep the most recent to bound memory.
_EXEC_SESSION_COMMANDS: dict[str, str] = {}
_EXEC_SESSION_LIMIT = 64
_EXEC_SESSION_LOCK = threading.Lock()


def _remember_exec_session(raw_input: str, output: Any) -> None:
    """Remember the command behind a newly opened shell session.

    The SDK reports a long-running process as ``Process running with session ID
    <n>``; a later ``write_stdin`` carries only that id.  Keying the command by
    session keeps the two-anchor rule intact across that hand-off.

    Args:
        raw_input: exec_command arguments (JSON).
        output: its result; only the session id line is read.
    """
    if not isinstance(output, str):
        return
    match = re.search(r"session ID\s+(\d+)", output)
    if not match:
        return
    command = _command_text(raw_input)
    session = match.group(1)
    with _EXEC_SESSION_LOCK:
        _EXEC_SESSION_COMMANDS[session] = command
        while len(_EXEC_SESSION_COMMANDS) > _EXEC_SESSION_LIMIT:
            _EXEC_SESSION_COMMANDS.pop(next(iter(_EXEC_SESSION_COMMANDS)))


def _session_command_text(raw_input: str) -> str:
    """Look up the command that opened this ``write_stdin`` session.

    Only a pure poll inherits the opening command.  If the model typed new
    input, that input is the command text -- otherwise it could open a real
    ``curl .../check`` session, then type ``cat forged.json`` into it and have
    the forged body attributed to the original command.

    Args:
        raw_input: write_stdin arguments (JSON).

    Returns:
        The opening command text for a poll, or an empty string.
    """
    try:
        parsed = json.loads(raw_input or "")
    except (TypeError, ValueError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    if str(parsed.get("chars") or "").strip():
        return ""
    session = str(parsed.get("session_id") or "").strip()
    if not session:
        return ""
    with _EXEC_SESSION_LOCK:
        return _EXEC_SESSION_COMMANDS.get(session, "")


def install_exec_observer(
    success: SuccessLedger,
    *,
    platform_url: str = "",
    instance: str = "",
    question_ids: tuple[str, ...] = (),
) -> bool:
    """Watch shell tool output for a structured platform verdict.

    ``exec_command`` / ``write_stdin`` are the only tools that actually reach
    the platform from inside the run.  This observer is read-only: it never
    changes the result, it only records a verdict and then raises the existing
    :class:`SolvedStop` root stop.

    Args:
        success: ledger to update.
        platform_url: platform root URL; the command URL must match it
            exactly (scheme, host, port, path).
        instance: this run's instance id; pins ``/instances/{id}/check``.
        question_ids: this run's question ids; a verdict must name one.

    Returns:
        True when the observer is armed (idempotent; a missing platform URL,
        instance, or question id disarms it for the current run rather than
        leaving stale state).
    """
    global _ACTIVE_EXEC_OBSERVER
    with _EXEC_SESSION_LOCK:
        _EXEC_SESSION_COMMANDS.clear()
    if not platform_url or not instance or not question_ids:
        _ACTIVE_EXEC_OBSERVER = None
        return False

    from strix.agents import factory

    _ACTIVE_EXEC_OBSERVER = (
        success,
        str(platform_url).rstrip("/"),
        str(instance),
        tuple(str(q) for q in question_ids if str(q)),
    )
    if getattr(factory, "_ctf_exec_observer_installed", False):
        return True

    original = factory._with_bounded_result
    factory._ctf_original_bounded_result = original  # type: ignore[attr-defined]

    def patched(tool: Any) -> Any:
        tool = original(tool)
        if getattr(tool, "name", "") not in ("exec_command", "write_stdin"):
            return tool
        if getattr(tool, "_ctf_exec_observer", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            active = _ACTIVE_EXEC_OBSERVER
            if active is None:
                return result
            ledger, active_platform, active_instance, active_qids = active
            try:
                command = _command_text(raw_input)
                if getattr(tool, "name", "") == "exec_command":
                    _remember_exec_session(raw_input, result)
                else:
                    # write_stdin carries no cmd; the opening exec_command is
                    # the only truthful source of what this output belongs to.
                    command = _session_command_text(raw_input) or command
                marked = observe_platform_output(
                    ledger,
                    command,
                    result,
                    platform_url=active_platform,
                    instance=active_instance,
                    question_ids=active_qids,
                )
            except Exception:  # noqa: BLE001 -- observing must never break the tool
                logger.warning("ctf exec verdict observer failed", exc_info=True)
                marked = False
            if marked:
                raise SolvedStop(f"solved via {ledger.source}: {ledger.detail}")
            return result

        tool.on_invoke_tool = invoke
        tool._ctf_exec_observer = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    factory._ctf_exec_observer_installed = True  # type: ignore[attr-defined]
    return True


def uninstall_exec_observer() -> None:
    """Restore the wrapped factory method (tests and rollback)."""
    global _ACTIVE_EXEC_OBSERVER
    _ACTIVE_EXEC_OBSERVER = None
    with _EXEC_SESSION_LOCK:
        _EXEC_SESSION_COMMANDS.clear()
    try:
        from strix.agents import factory
    except Exception:  # noqa: BLE001 -- no runtime means nothing to restore
        return
    original = getattr(factory, "_ctf_original_bounded_result", None)
    if original is not None:
        factory._with_bounded_result = original  # type: ignore[assignment]
        del factory._ctf_original_bounded_result  # type: ignore[attr-defined]
    if hasattr(factory, "_ctf_exec_observer_installed"):
        del factory._ctf_exec_observer_installed  # type: ignore[attr-defined]


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
