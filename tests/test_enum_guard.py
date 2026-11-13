"""Hard reject when one family keeps returning the identical observation.

## Why this file exists

2026-11-06 CTFARENA-043: ``EnumerationGuard.finish`` saw 95 ``exec_command``
curls get the same Go-style ``404 page not found`` and appended "Stop now"
text, but the model kept probing for another 20 minutes.  A warning below the
hard threshold is useful; at the threshold it has to become an error and the
family has to be refused before the tool runs.

These tests pin the three boundaries: the block is hard (inner tool not
called), it is scoped (another tool or family still runs), and it never fires
on new information.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix import agent as agent_mod  # noqa: E402
from ctf_strix import enum_guard  # noqa: E402
import strix.core.runner as runner_mod  # noqa: E402

BLOCK_ARGS = '{"cmd": "curl -s https://x.test/api/notes/note_a"}'
#: Three distinct leaves of one family.  The hard block is about enumeration,
#: so a family only qualifies once several *different* paths were asked for.
BLOCK_PATHS = [
    f'{{"cmd": "curl -s https://x.test/api/notes/note_{leaf}"}}'
    for leaf in ("a", "b", "c")
]


class FakeTool:
    """Minimal stand-in for a FunctionTool: only what install() touches."""

    def __init__(self, name: str, result: str) -> None:
        self.name = name
        self.result = result
        self.calls = 0

    async def on_invoke_tool(self, ctx, raw_input: str) -> str:  # noqa: ANN001, ARG002
        self.calls += 1
        return self.result


@pytest.fixture
def factory(monkeypatch):
    """Give each test a clean mount point; install() creates a fresh guard."""
    pytest.importorskip("strix.agents")
    from strix.agents import factory as strix_factory

    monkeypatch.setattr(strix_factory, "_with_bounded_result", lambda tool: tool)
    return strix_factory


def _install(factory, tools):
    guard = enum_guard.install()
    wrapped = [factory._with_bounded_result(tool) for tool in tools]
    return guard, wrapped


def _run(tool, args):
    return asyncio.run(tool.on_invoke_tool(None, args))


def test_hard_threshold_returns_error_and_refuses_without_running(factory):
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])

    outputs = []
    for index in range(enum_guard._HARD_REPEATS + 1):
        outputs.append(_run(wrapped, BLOCK_PATHS[index % len(BLOCK_PATHS)]))

    error = outputs[-1]
    assert error.startswith("ERROR: [ENUMERATION GUARD]")
    assert "notes" in error, "the error must name the blocked family"
    assert len(error) < 400
    calls_at_error = tool.calls
    assert calls_at_error == enum_guard._HARD_REPEATS + 1

    refused = _run(wrapped, BLOCK_PATHS[0])
    assert refused.startswith("ERROR: [ENUMERATION GUARD]")
    assert tool.calls == calls_at_error, "blocked call must not run the inner tool"
    assert guard.blocked_calls == 1


def test_same_host_with_another_tool_is_still_allowed(factory):
    shell = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    probe = FakeTool("http_probe", "[HTTP 404] 404 page not found")
    guard, (shell_wrapped, probe_wrapped) = _install(factory, [shell, probe])

    for index in range(enum_guard._HARD_REPEATS + 2):
        _run(shell_wrapped, BLOCK_PATHS[index % len(BLOCK_PATHS)])

    assert shell.calls == enum_guard._HARD_REPEATS + 1
    assert guard.blocked_calls == 1

    out = _run(probe_wrapped, '{"url": "https://x.test/api/notes/note_a"}')

    assert not out.startswith("ERROR:")
    assert probe.calls == 1


def test_another_family_on_the_same_tool_is_still_allowed(factory):
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    _, (wrapped,) = _install(factory, [tool])

    for index in range(enum_guard._HARD_REPEATS + 2):
        _run(wrapped, BLOCK_PATHS[index % len(BLOCK_PATHS)])
    calls_after_block = tool.calls

    out = _run(wrapped, '{"cmd": "curl -s https://x.test/api/users/user_a"}')

    assert not out.startswith("ERROR:")
    assert tool.calls == calls_after_block + 1


def test_non_identical_observations_are_never_blocked(factory):
    tool = FakeTool("exec_command", "[HTTP 200] alpha")
    guard, (wrapped,) = _install(factory, [tool])

    outputs = []
    for word in "alpha bravo charlie delta echo foxtrot golf hotel".split():
        tool.result = f"[HTTP 200] body {word}"
        outputs.append(_run(wrapped, BLOCK_ARGS))

    assert tool.calls == 8
    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.blocked
    assert guard.blocked_calls == 0


def test_error_stays_short_for_a_pathological_family_name(factory):
    long_segment = "a" * 300
    paths = [
        f'{{"cmd": "curl -s https://x.test/api/{long_segment}/leaf{leaf}"}}'
        for leaf in ("a", "b", "c")
    ]
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    _, (wrapped,) = _install(factory, [tool])

    out = ""
    for index in range(enum_guard._HARD_REPEATS + 1):
        out = _run(wrapped, paths[index % len(paths)])

    assert out.startswith("ERROR: [ENUMERATION GUARD]")
    assert len(out) < 400


# ---------------------------------------------------------------------------
# BLOCKER regressions: family key, path diversity, disarm, escalation
# ---------------------------------------------------------------------------


def test_two_segment_paths_are_single_endpoints_not_a_family(factory):
    """B4: ``/api/login`` and ``/api/flag`` must not share the ``api`` family.

    Both were folded into ``api``; five identical 401s then blocked the whole
    ``/api/*`` tree, including the login that carried the right password.
    """
    login = '{"cmd": "curl -s https://x.test/api/login"}'
    flag = '{"cmd": "curl -s https://x.test/api/flag"}'

    assert enum_guard._fingerprint("exec_command", login).endswith("|api/login")
    assert enum_guard._fingerprint("exec_command", flag).endswith("|api/flag")

    tool = FakeTool("exec_command", "[HTTP 401] invalid credentials")
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, login) for _ in range(5)]
    outputs += [_run(wrapped, flag) for _ in range(5)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.blocked
    assert guard.blocked_calls == 0


def test_same_path_retries_are_warned_but_never_hard_blocked(factory):
    """B4: retrying one path is guessing/polling, not enumeration."""
    tool = FakeTool("exec_command", "[HTTP 403] forbidden")
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, BLOCK_ARGS) for _ in range(10)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.blocked
    # The soft warning is unchanged: the model is still told the response
    # repeats.  Only the hard block is withheld.
    assert any("[ENUMERATION GUARD]" in out for out in outputs)


def test_path_diversity_alone_unlocks_the_hard_block(factory):
    """B4: three distinct paths in one family are enumeration again."""
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, BLOCK_PATHS[index % 3]) for index in range(5)]

    assert outputs[-1].startswith("ERROR: [ENUMERATION GUARD]")
    assert guard.blocked


def test_note_answer_lifts_every_block_and_counter(factory):
    """B5: an answer on the table means no block may stand in its way."""
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])

    for index in range(5):
        _run(wrapped, BLOCK_PATHS[index % 3])
    assert guard.blocked

    guard.note_answer()

    assert not guard.blocked
    assert not guard.counts
    assert not guard.exhausted_family
    assert not guard.exhausted
    out = _run(wrapped, BLOCK_PATHS[0])
    assert not out.startswith("ERROR:")


def test_refusal_limit_escalates_to_exhausted(factory):
    """B5: retrying a blocked family is not free forever."""
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])

    for index in range(5):
        _run(wrapped, BLOCK_PATHS[index % 3])
    assert guard.blocked
    assert not guard.exhausted

    refused = []
    for _ in range(enum_guard._ENUM_REFUSAL_LIMIT):
        refused.append(_run(wrapped, BLOCK_PATHS[0]))

    assert all(out.startswith("ERROR: [ENUMERATION GUARD]") for out in refused)
    assert guard.exhausted
    assert guard.exhausted_family in guard.blocked
    assert guard.refusal_count(guard.exhausted_family) == enum_guard._ENUM_REFUSAL_LIMIT
    assert "enumeration exhausted" in guard.exhausted_detail()


# ---------------------------------------------------------------------------
# Run-level wiring: EnumExhausted maps to its own stop reason
# ---------------------------------------------------------------------------


def _task(tmp_path) -> dict:
    return {
        "run_mode": "instance",
        "challenge": {
            "id": "ENUM",
            "name": "enum-exhausted",
            "description": "",
            "difficulty": "easy",
        },
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }


def test_enum_exhausted_maps_to_its_own_stop_reason(tmp_path, monkeypatch, capsys):
    """B5: the stop reason and the blocked_call counters reach result.json."""
    stub = types.ModuleType("ctf_strix.local_backend")
    stub.install = lambda: None
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    (tmp_path / "task.json").write_text(
        json.dumps(_task(tmp_path)), encoding="utf-8"
    )

    async def _run(**kwargs) -> types.SimpleNamespace:  # noqa: ARG001
        raise enum_guard.EnumExhausted(
            "enumeration exhausted: 'notes' kept being retried",
            family="exec_command|x.test|notes",
            refusals=enum_guard._ENUM_REFUSAL_LIMIT,
        )

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["stop_reason"] == "enum_exhausted"
    # The counters used to be written and never read; the run summary prints
    # them so an operator can see a family was hard-blocked.
    out = capsys.readouterr().out
    assert "enum guard: blocked_calls=" in out
    assert agent_mod.EnumExhausted in agent_mod._STOP_TYPES
    assert not issubclass(agent_mod.EnumExhausted, Exception)


# ---------------------------------------------------------------------------
# fix4: sink ordering (BLOCKER) + per-attempt escalation + diagnostics
# ---------------------------------------------------------------------------

FAMILY_KEY = "exec_command|127.0.0.1|notes"
SIBLING_FLAG = "flag{fix4_sibling_output_7c1e}"
#: The flag extractor scores candidates by proximity to the challenge host, so
#: the sibling output has to mention it.
SIBLING_OUTPUT = f"200 OK from http://127.0.0.1:9/body -> {SIBLING_FLAG}"


def _blocked_guard() -> enum_guard.EnumerationGuard:
    """A guard whose family is hard-blocked, as the tool wrapper leaves it."""
    guard = enum_guard.EnumerationGuard()
    guard.blocked.add(FAMILY_KEY)
    return guard


def _exhaust(guard: enum_guard.EnumerationGuard) -> None:
    """Count ``_ENUM_REFUSAL_LIMIT`` refusals, as the wrapper does in a round.

    Must run *inside* the round: the attempt boundary soft-resets the counters,
    so state prepared before ``main()`` starts would be gone by the first event
    (that is exactly what the reset is for).
    """
    for _ in range(enum_guard._ENUM_REFUSAL_LIMIT):
        assert guard.refusal((FAMILY_KEY, BLOCK_ARGS)) is not None
    assert guard.exhausted


def _call_event(call_id: str, args: str):
    """A ``tool_call_item`` run event, shaped like the SDK's."""
    return types.SimpleNamespace(
        type="run_item_stream_event",
        item=types.SimpleNamespace(
            type="tool_call_item",
            call_id=call_id,
            raw_item=types.SimpleNamespace(
                name="exec_command", arguments=args, call_id=call_id
            ),
        ),
    )


def _output_event(call_id: str, text: str):
    """A ``tool_call_output_item`` run event."""
    return types.SimpleNamespace(
        type="run_item_stream_event",
        item=types.SimpleNamespace(
            type="tool_call_output_item",
            output=text,
            call_id=call_id,
            raw_item={"call_id": call_id},
        ),
    )


def _boundary_event():
    """``response.completed``: the only event that closes one model round."""
    return types.SimpleNamespace(
        type="raw_response_event",
        data=types.SimpleNamespace(type="response.completed"),
    )


def _prepare_run(tmp_path, monkeypatch, guard) -> None:
    """Write task.json and make ``_run_agent`` install ``guard``."""
    stub = types.ModuleType("ctf_strix.local_backend")
    stub.install = lambda: None
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    monkeypatch.delenv("CTF_ATTEMPTS", raising=False)
    (tmp_path / "task.json").write_text(
        json.dumps(_task(tmp_path)), encoding="utf-8"
    )
    # agent.py imports ``install`` inside ``_run_agent``, so replacing the
    # module attribute is enough to hand the sink this exact instance.
    monkeypatch.setattr(enum_guard, "install", lambda: guard)


def _payload(tmp_path) -> dict:
    return json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))


def test_enum_escalation_is_raised_at_the_round_boundary(tmp_path, monkeypatch):
    """BLOCKER/RISK 6: the stop must not be evaluated on an output event.

    Tool calls of one round run concurrently and their outputs are queued as a
    batch in plan order, so raising on the first event of that round drops the
    siblings' outputs.  The stop belongs on ``response.completed``, which
    arrives after every output of the round.
    """
    guard = _blocked_guard()
    _prepare_run(tmp_path, monkeypatch, guard)
    steps: list[str] = []

    async def _run(**kwargs) -> types.SimpleNamespace:
        _exhaust(guard)
        sink = kwargs["event_sink"]
        sink("root", _call_event("c1", BLOCK_ARGS))
        sink("root", _output_event("c1", "404 page not found"))
        steps.append("output-processed")
        sink("root", _boundary_event())
        steps.append("boundary-processed")
        raise AssertionError("the boundary event must stop the run")

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    assert steps == ["output-processed"], (
        "the run stopped before the round boundary; an in-flight output of "
        "this round would have been discarded"
    )
    assert _payload(tmp_path)["stop_reason"] == "enum_exhausted"


def test_refused_output_before_a_sibling_still_captures_its_flag(
    tmp_path, monkeypatch
):
    """BLOCKER: a refused call ordered first must not cost a sibling's output."""
    guard = _blocked_guard()
    _prepare_run(tmp_path, monkeypatch, guard)

    async def _run(**kwargs) -> types.SimpleNamespace:
        _exhaust(guard)
        sink = kwargs["event_sink"]
        # Plan order puts the retry of the blocked family first; the sibling
        # call is the one that actually reads the flag.
        sink("root", _call_event("c-refused", BLOCK_ARGS))
        sink(
            "root",
            _output_event("c-refused", "ERROR: [ENUMERATION GUARD] family 'notes'"),
        )
        sink("root", _call_event("c-sibling", '{"cmd": "cat /flag"}'))
        sink("root", _output_event("c-sibling", SIBLING_OUTPUT))
        sink("root", _boundary_event())
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["answers"] == {"flag": SIBLING_FLAG}, (
        "the sibling output (which carried the flag) never reached the sink's "
        "capture path"
    )
    assert payload["stop_reason"] == "solved"


def test_enum_guard_counters_reach_result_json(tmp_path, monkeypatch):
    """RISK 4: the guard's counters must be queryable, not stdout-only."""
    guard = _blocked_guard()
    _prepare_run(tmp_path, monkeypatch, guard)

    async def _run(**kwargs) -> types.SimpleNamespace:
        _exhaust(guard)
        raise enum_guard.EnumExhausted(
            "enumeration exhausted: 'notes' kept being retried",
            family=FAMILY_KEY,
            refusals=guard.refusal_count(FAMILY_KEY),
        )

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "enum_exhausted"
    assert payload["enum_guard"]["blocked_calls"] == enum_guard._ENUM_REFUSAL_LIMIT
    assert payload["enum_guard"]["blocked"] == [FAMILY_KEY]
    assert payload["enum_guard"]["exhausted"] is True
    assert payload["enum_guard"]["exhausted_family"] == FAMILY_KEY


def test_new_attempt_does_not_inherit_the_refusal_count(tmp_path, monkeypatch):
    """RISK 3: escalation state is per-attempt; a hard block is not."""
    guard = _blocked_guard()
    _prepare_run(tmp_path, monkeypatch, guard)
    monkeypatch.setenv("CTF_ATTEMPTS", "2")
    seen: list[tuple[bool, bool]] = []

    async def _run(**kwargs) -> types.SimpleNamespace:
        if not seen:
            # Two refusals of the blocked family during attempt 1: below the
            # limit, so the attempt runs on.
            for _ in range(enum_guard._ENUM_REFUSAL_LIMIT - 1):
                assert guard.refusal((FAMILY_KEY, BLOCK_ARGS)) is not None
            sink = kwargs["event_sink"]
            sink("root", _call_event("c1", BLOCK_ARGS))
            sink("root", _output_event("c1", "404 page not found"))
            seen.append((guard.exhausted, bool(guard.blocked)))
            # Name-matched by ``_is_turn_exhausted``: this attempt ran and
            # simply spent its turn budget.
            raise type("MaxTurnsExceeded", (Exception,), {})("turns spent")
        # First call of the new attempt: the model retries the family the
        # previous attempt left blocked, which is exactly what an inherited
        # count would turn into an immediate stop.
        guard.refusal((FAMILY_KEY, BLOCK_ARGS))
        seen.append((guard.exhausted, bool(guard.blocked)))
        raise enum_guard.EnumExhausted(
            "stopped after the second attempt",
            family=FAMILY_KEY,
            refusals=guard.refusal_count(FAMILY_KEY),
        )

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    assert len(seen) == 2, "the second attempt never started"
    assert seen[0] == (False, True)
    # Count cleared (a retry of the old family no longer ends the attempt on
    # its own first call) but the block itself still stands.
    assert seen[1] == (False, True)


def test_soft_reset_drops_escalation_but_keeps_the_block(factory):
    """RISK 3: what a new attempt may and may not inherit."""
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])

    for index in range(5):
        _run(wrapped, BLOCK_PATHS[index % 3])
    for _ in range(enum_guard._ENUM_REFUSAL_LIMIT):
        _run(wrapped, BLOCK_PATHS[0])
    assert guard.exhausted
    blocked = set(guard.blocked)

    guard.soft_reset()

    assert not guard.exhausted
    assert not guard.refusal_counts
    assert guard.blocked == blocked, "a hard block is not an escalation counter"

    out = _run(wrapped, BLOCK_PATHS[0])
    assert out.startswith("ERROR: [ENUMERATION GUARD]")
    assert guard.refusal_count(next(iter(guard.blocked))) == 1


def test_request_path_ignores_trailing_shell_punctuation():
    """RISK 2: quoting a URL differently must not fake path diversity."""
    paths = {
        enum_guard._request_path('{"cmd": "curl -s https://x.test/api/x/1"}'),
        enum_guard._request_path('{"cmd": "curl -s https://x.test/api/x/1;"}'),
        enum_guard._request_path('{"cmd": "curl -s https://x.test/api/x/1,"}'),
        enum_guard._request_path('{"cmd": "echo $(curl -s https://x.test/api/x/1)"}'),
        enum_guard._request_path('{"cmd": "curl -s `https://x.test/api/x/1`"}'),
    }

    assert paths == {"/api/x/1"}
    # Only the tail is punctuation: a separator inside the path is the path.
    assert (
        enum_guard._request_path('{"cmd": "curl -s https://x.test/a;b/c"}')
        == "/a;b/c"
    )


def test_request_path_strips_json_and_shell_residue():
    """fix5 R3: JSON-escaped tail and piped command are the same path.

    A URL in a shell command can trail a JSON-escaped quote, ``|jq``
    or ``&&echo``.  All three are residue, not a different path: counting them
    apart would fake path diversity and let the diversity gate block one
    endpoint.
    """
    paths = {
        enum_guard._request_path('{"cmd": "curl -s https://x.test/api/x/1"}'),
        enum_guard._request_path('{"cmd": "curl -s https://x.test/api/x/1\\""}'),
        enum_guard._request_path('{"cmd": "curl -s https://x.test/api/x/1|jq"}'),
        enum_guard._request_path('{"cmd": "curl -s https://x.test/api/x/1&&echo"}'),
    }

    assert paths == {"/api/x/1"}


# ---------------------------------------------------------------------------
# WEB-3 / WEB-6: a block covers one request cell, not the whole path family
# ---------------------------------------------------------------------------
#
# The key used to be ``tool|host|family``, so once a GET family was blocked
# every method on it -- and every future call carrying a session -- was refused
# before the tool ran.  "This route has no new information" was being read as
# "this route may never be used again", which is false the moment the request
# changes method or identity.


def _block_notes_family(wrapped) -> None:
    """Drive one unauthenticated GET family past the hard threshold."""
    for index in range(enum_guard._HARD_REPEATS + 1):
        _run(wrapped, BLOCK_PATHS[index % len(BLOCK_PATHS)])


def test_switching_method_reopens_a_blocked_family(factory):
    """Same URL, different verb: the block was counted on a different request."""
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])
    _block_notes_family(wrapped)
    assert guard.blocked

    assert _run(wrapped, BLOCK_PATHS[0]).startswith("ERROR: [ENUMERATION GUARD]")
    calls = tool.calls

    out = _run(wrapped, '{"cmd": "curl -s -X POST https://x.test/api/notes/note_a"}')

    assert not out.startswith("ERROR: [ENUMERATION GUARD]")
    assert tool.calls == calls + 1, "a different method is a different request"


def test_bringing_a_session_reopens_a_blocked_family(factory):
    """Same URL and verb, but authenticated: a new identity gets a fresh count."""
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])
    _block_notes_family(wrapped)
    assert guard.blocked
    calls = tool.calls

    out = _run(
        wrapped, '{"cmd": "curl -s -b jar.txt https://x.test/api/notes/note_a"}'
    )

    assert not out.startswith("ERROR: [ENUMERATION GUARD]")
    assert tool.calls == calls + 1


def test_the_same_unauthenticated_method_stays_blocked(factory):
    """Reverse control: widening the key must not lift the original block."""
    tool = FakeTool("exec_command", "[HTTP 404] 404 page not found")
    guard, (wrapped,) = _install(factory, [tool])
    _block_notes_family(wrapped)
    calls = tool.calls

    for _ in range(2):
        refused = _run(wrapped, BLOCK_PATHS[0])
        assert refused.startswith("ERROR: [ENUMERATION GUARD]")

    assert tool.calls == calls, "an unchanged request must still be refused"


@pytest.mark.parametrize(
    ("tool_name", "args", "expected"),
    [
        # shell form: method from an explicit flag, then from what a body flag
        # implies, then from a head flag.
        ("exec_command", BLOCK_ARGS, "exec_command|x.test|GET|anon|notes"),
        (
            "exec_command",
            '{"cmd": "curl -s -X POST https://x.test/api/notes/note_a"}',
            "exec_command|x.test|POST|anon|notes",
        ),
        (
            "exec_command",
            '{"cmd": "curl -s -d a=b https://x.test/api/notes/note_a"}',
            "exec_command|x.test|POST|anon|notes",
        ),
        (
            "exec_command",
            '{"cmd": "curl -s -G -d a=b https://x.test/api/notes/note_a"}',
            "exec_command|x.test|GET|anon|notes",
        ),
        (
            "exec_command",
            '{"cmd": "curl -s -I https://x.test/api/notes/note_a"}',
            "exec_command|x.test|HEAD|anon|notes",
        ),
        # wget's ``-X`` is --exclude-directories, not a request method.
        (
            "exec_command",
            '{"cmd": "wget -q -X /tmp https://x.test/api/notes/note_a"}',
            "exec_command|x.test|GET|anon|notes",
        ),
        (
            "exec_command",
            '{"cmd": "wget -q --method=PUT https://x.test/api/notes/note_a"}',
            "exec_command|x.test|PUT|anon|notes",
        ),
        # session carried by a cookie jar, and by an explicit header
        (
            "exec_command",
            '{"cmd": "curl -s -b jar.txt https://x.test/api/notes/note_a"}',
            "exec_command|x.test|GET|auth|notes",
        ),
        (
            "exec_command",
            '{"cmd": "curl -s -H \'Cookie: sid=abc\' https://x.test/api/notes/note_a"}',
            "exec_command|x.test|GET|auth|notes",
        ),
        # http_probe takes method/cookies/headers_json as parameters, not flags
        (
            "http_probe",
            '{"url": "https://x.test/api/notes/note_a", "method": "POST"}',
            "http_probe|x.test|POST|anon|notes",
        ),
        (
            "http_probe",
            '{"url": "https://x.test/api/notes/note_a", "cookies": "sid=abc"}',
            "http_probe|x.test|GET|auth|notes",
        ),
        (
            "http_probe",
            '{"url": "https://x.test/api/notes/note_a",'
            ' "headers_json": "{\\"Cookie\\": \\"sid=abc\\"}"}',
            "http_probe|x.test|GET|auth|notes",
        ),
        # a sweep over several methods is its own cell, not the first method's
        (
            "http_probe",
            '{"url": "https://x.test/api/notes/note_a", "methods": "POST,GET"}',
            "http_probe|x.test|GET+POST|anon|notes",
        ),
    ],
)
def test_fingerprint_names_the_request_cell(tool_name, args, expected):
    """Family stays last so every ``rsplit``/``endswith`` on the key still works."""
    key = enum_guard._fingerprint(tool_name, args)

    assert key == expected
    assert key.rsplit("|", 1)[-1] == "notes"


def test_blocked_error_reads_the_family_from_the_key_tail():
    """The widened key must not leak method/auth segments into the error text."""
    key = "exec_command|127.0.0.1|POST|auth|api/login"

    assert "'api/login'" in enum_guard.EnumerationGuard._blocked_error(key)
    assert "127.0.0.1" not in enum_guard.EnumerationGuard._blocked_error(key)

    guard = enum_guard.EnumerationGuard()
    guard.exhausted_family = key
    assert "'api/login'" in guard.exhausted_detail()
