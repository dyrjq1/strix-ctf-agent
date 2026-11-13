"""Target-absent fast fail: distinct paths, one identical uninformative body.

2026-11-06 CTFARENA-043 sent 95 ``exec_command`` curls at a host that answered
the same Go-style ``404 page not found`` to every path.  ``EnumerationGuard``
counted per path family, so 95 distinct paths produced 95 empty families and
zero warnings; the run burned the wall clock.  SAMPLE-003 / SAMPLE-012 were
placeholders and the agent guessed for 23 minutes.

These tests pin the new rule and, just as importantly, its edges: the body hash
must match, one 2xx anywhere disarms the guard, a recorded answer disarms it,
and the verdict is a hard stop (the crossing call gets an ``ERROR:`` line and
later calls never reach the tool) rather than another hint.
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

from ctf_strix import target_absent  # noqa: E402

BASE = "https://absent.test"
OTHER = "https://other.test"
GO_404 = "404 page not found"


def _exec_result(body: str, chunk: str = "000001") -> str:
    """One exec_command result, in the shape the shell capability prints."""
    return (
        f"Chunk ID: {chunk}\n"
        "Wall time: 0.11 seconds\n"
        "Process exited with code 0\n"
        "Output:\n"
        f"{body}\n"
    )


def _args(path: str, host: str = BASE) -> str:
    return json.dumps({"cmd": f"curl -s {host}{path}"})


class FakeTool:
    """Minimal stand-in for a FunctionTool: only what install() touches."""

    def __init__(self, name: str, results: list[str]) -> None:
        self.name = name
        self.results = results
        self.calls = 0

    async def on_invoke_tool(self, ctx, raw_input: str) -> str:  # noqa: ANN001, ARG002
        body = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        # A different Chunk ID on every call: hashing must strip it, or the
        # same body would look different every time (the enum_guard lesson).
        return _exec_result(body, chunk=f"{self.calls:06x}")


@pytest.fixture
def factory(monkeypatch):
    """Give each test a clean mount point; install() creates a fresh guard."""
    pytest.importorskip("strix.agents")
    from strix.agents import factory as strix_factory

    monkeypatch.setattr(strix_factory, "_with_bounded_result", lambda tool: tool)
    return strix_factory


def _install(factory, tools):
    guard = target_absent.install()
    wrapped = [factory._with_bounded_result(tool) for tool in tools]
    return guard, wrapped


def _run(tool, args):
    return asyncio.run(tool.on_invoke_tool(None, args))


def test_six_distinct_paths_with_one_body_fire_once(factory):
    tool = FakeTool("exec_command", [GO_404])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(6)]

    assert not any(out.startswith("ERROR:") for out in outputs[:-1]), (
        "nothing fires before the sixth distinct path"
    )
    error = outputs[-1]
    assert error.startswith("ERROR: [TARGET ABSENT]")
    assert len(error) < 400
    assert guard.tripped
    assert tool.calls == 6


def test_five_distinct_paths_do_not_fire(factory):
    tool = FakeTool("exec_command", [GO_404])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(5)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped


def test_one_2xx_anywhere_disarms_the_guard(factory):
    alive = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body>real application</body></html>"
    )
    tool = FakeTool("exec_command", [GO_404, GO_404, alive] + [GO_404] * 10)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(10)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped, "a host that answered 2xx is never 'absent'"


def test_six_different_bodies_do_not_fire(factory):
    bodies = [f"404 page not found -- probe-{index}" for index in range(6)]
    tool = FakeTool("exec_command", bodies)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(6)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped, "an identical body hash is required, not just a 404"


def test_calls_after_the_verdict_are_refused_without_running(factory):
    tool = FakeTool("exec_command", [GO_404])
    guard, (wrapped,) = _install(factory, [tool])
    for index in range(6):
        _run(wrapped, _args(f"/probe-{index}"))
    calls_at_verdict = tool.calls

    refused = _run(wrapped, _args("/probe-after"))

    assert refused.startswith("ERROR: [TARGET ABSENT]")
    assert tool.calls == calls_at_verdict, "the blocked call must not run the tool"
    assert guard.blocked_calls == 1

    # The verdict is per origin: another target must still be reachable, or a
    # process running several challenges would be poisoned by the first one.
    out = _run(wrapped, _args("/probe", host=OTHER))
    assert not out.startswith("ERROR:")
    assert tool.calls == calls_at_verdict + 1


def test_recorded_answer_disarms_the_guard(factory):
    tool = FakeTool("exec_command", [GO_404])
    guard, (wrapped,) = _install(factory, [tool])
    guard.note_answer()

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(9)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped, "an answer already recorded must never be discarded"


def test_target_absent_is_a_registered_stop_type() -> None:
    from ctf_strix import agent as agent_mod

    assert agent_mod.TargetAbsent in agent_mod._STOP_TYPES
    assert not issubclass(agent_mod.TargetAbsent, Exception)


# ---------------------------------------------------------------------------
# end-to-end: the run ends with stop_reason="target_absent", not "completed"
# ---------------------------------------------------------------------------


def _round_end() -> object:
    """``response.completed``: the event that closes one model round.

    The sink evaluates the target-absent stop on the round boundary only: the
    tool calls of one round run concurrently and their outputs are queued as a
    batch, so stopping on an output event would discard a sibling output.
    """
    return types.SimpleNamespace(
        type="raw_response_event",
        data=types.SimpleNamespace(type="response.completed"),
    )


def _event(kind: str, *, call_id: str = "", output: str = "", args: str = "{}") -> object:
    return types.SimpleNamespace(
        item=types.SimpleNamespace(
            type=kind,
            output=output,
            call_id=call_id,
            raw_item=types.SimpleNamespace(
                name="exec_command", arguments=args, call_id=call_id
            ),
        )
    )


@pytest.fixture()
def run_env(tmp_path, monkeypatch):
    """Point main at an isolated work dir and neutralize other watchdogs."""
    stub = types.ModuleType("ctf_strix.local_backend")
    stub.install = lambda: None
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)
    monkeypatch.delenv("CTF_IDLE_SECONDS", raising=False)
    return stub


def _task(tmp_path) -> dict:
    return {
        "run_mode": "instance",
        "challenge": {
            "id": "ABSENT",
            "name": "target-absent",
            "description": "",
            "difficulty": "easy",
        },
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }


def _write_task(tmp_path) -> None:
    (tmp_path / "task.json").write_text(json.dumps(_task(tmp_path)), encoding="utf-8")


def _payload(tmp_path) -> dict:
    return json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))


def test_run_stops_with_target_absent_after_six_identical_404s(
    tmp_path, run_env, monkeypatch
) -> None:
    """Drive the real guard through the real wrappers, then the real sink."""
    import strix.core.runner as runner_mod

    from ctf_strix import agent as agent_mod

    from strix.agents import factory as live_factory  # noqa: PLC0415

    monkeypatch.setattr(live_factory, "_with_bounded_result", lambda tool: tool)
    _write_task(tmp_path)
    host = "https://absent-e2e.test"
    seen = {"calls": 0}

    async def _run(**kwargs) -> types.SimpleNamespace:
        sink = kwargs["event_sink"]
        tool = FakeTool("exec_command", [GO_404])
        wrapped = live_factory._with_bounded_result(tool)
        # More than six: without the stop the loop would finish cleanly and the
        # run would report "completed", which is exactly what must not happen.
        for index in range(12):
            call_id = f"call-{index}"
            args = _args(f"/page-{index}", host=host)
            sink("root", _event("tool_call_item", call_id=call_id, args=args))
            out = await wrapped.on_invoke_tool(None, args)
            seen["calls"] += 1
            sink(
                "root",
                _event("tool_call_output_item", call_id=call_id, output=out, args=args),
            )
            sink("root", _round_end())
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "target_absent"
    assert payload["turns"] >= 1
    assert seen["calls"] == 6, "the seventh call must never be sent"
    assert payload["success"]["solved"] is False


# ---------------------------------------------------------------------------
# BLOCKER regressions: liveness latch, curl -i header block, IPv6 safety
# ---------------------------------------------------------------------------


class RawTool:
    """Return pre-built result strings verbatim (for ``curl -i`` shapes)."""

    def __init__(self, name: str, results: list[str]) -> None:
        self.name = name
        self.results = results
        self.calls = 0

    async def on_invoke_tool(self, ctx, raw_input: str) -> str:  # noqa: ANN001, ARG002
        out = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return out


def _exec_curl_i(body: str, *, date: str, cookie: str, chunk: str = "000001") -> str:
    """One ``exec_command`` result from ``curl -i``: status line + header block."""
    return (
        f"Chunk ID: {chunk}\n"
        "Wall time: 0.11 seconds\n"
        "Process exited with code 0\n"
        "Output:\n"
        "HTTP/1.1 404 Not Found\r\n"
        f"Date: {date}\r\n"
        f"Set-Cookie: {cookie}\r\n"
        "Content-Length: 19\r\n"
        "\r\n"
        f"{body}\n"
    )


def test_live_200_then_six_404s_does_not_fire(factory):
    """A 200 HTML root (no status line) keeps a live target alive."""
    root = "<html><body>real application</body></html>"
    tool = FakeTool("exec_command", [root, GO_404])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args("/"))]
    outputs += [_run(wrapped, _args(f"/word-{index}")) for index in range(6)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped, "a marker body proves the target is alive"


def test_curl_dash_i_date_drift_hashes_equal(factory):
    """``curl -i`` header noise must not change the body hash."""
    results = [
        _exec_curl_i(
            GO_404,
            date=f"Mon, 0{index} Jan 2026 00:00:0{index} GMT",
            cookie=f"session={index}",
            chunk=f"{index:06x}",
        )
        for index in range(1, 7)
    ]
    tool = RawTool("exec_command", results)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(6)]

    assert outputs[-1].startswith("ERROR: [TARGET ABSENT]")
    assert guard.tripped

    probe_a = (
        "[HTTP 404] https://absent.test/x\n"
        "hdr: content-type: text/plain\n"
        "hdr: x-request-id: aaaa\n"
        "body: 404 page not found\n"
        "next: -\n"
    )
    probe_b = probe_a.replace("aaaa", "bbbb")
    hash_a = target_absent._body_hash(target_absent._body_of(probe_a))
    hash_b = target_absent._body_hash(target_absent._body_of(probe_b))
    assert hash_a == hash_b, "http_probe id drift must not change the hash"


def test_origin_and_path_ipv6_and_brackets_do_not_raise():
    """Malformed/IPv6 URLs are ignored, never raised from the guard."""
    cases = [
        '{"cmd": "curl -s http://[::1]:8080/x"}',
        '{"cmd": "curl -s http://[::ffff:127.0.0.1]/x"}',
        '{"cmd": "curl -s \\"http://[::1]:8080/a]b\\""}',
    ]
    for raw in cases:
        assert target_absent._origin_and_path(raw) is None

    # refusal() only consults _origin_and_path once the guard has tripped.
    tripped = target_absent.TargetAbsentGuard()
    tripped.tripped_origin = "http://[::1]:8080"
    # finish() takes the fresh-guard path.
    fresh = target_absent.TargetAbsentGuard()
    for raw in cases:
        assert tripped.refusal(raw) is None
        assert fresh.finish("exec_command", raw, GO_404) is None


def test_curl_dash_i_empty_body_head_only_hashes_equal(factory):
    """``curl -i`` with no body: the header block *is* the whole response."""
    results = [
        _exec_curl_i(
            "",
            date=f"Mon, 0{index} Jan 2026 00:00:0{index} GMT",
            cookie=f"session={index}",
            chunk=f"{index:06x}",
        )
        for index in range(1, 7)
    ]
    tool = RawTool("exec_command", results)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(6)]

    assert outputs[-1].startswith("ERROR: [TARGET ABSENT]")
    assert guard.tripped


# ---------------------------------------------------------------------------
# BLOCKER regression: a guard's own refusal is not a target response
# ---------------------------------------------------------------------------

#: Verbatim shape of ``EnumerationGuard._blocked_error``: the whole tool result
#: is replaced by this string, so it arrives here as the ``result``.
ENUM_REFUSAL = (
    "ERROR: [ENUMERATION GUARD] 'api' returned the IDENTICAL response too many "
    "times; this family is blocked. Change mechanism now: auth bypass, "
    "injection, SSRF pivot, file read, or use existing access. Do not resend "
    "this family."
)


def test_guard_refusal_text_is_never_counted_as_a_target_response(factory):
    """B3: six paths refused by the enum guard must not declare the target dead.

    ``target_absent`` is installed outermost, so an enum hard block returns its
    ERROR string straight into ``finish``.  The old code hashed that text as the
    target's body: six distinct origins/paths -> identical "uninformative"
    response -> trip.  A live target was killed by its own guard.
    """
    tool = RawTool("exec_command", [ENUM_REFUSAL])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(8)]

    assert not any(out.startswith("ERROR: [TARGET ABSENT]") for out in outputs)
    assert not guard.tripped
    assert guard.observations == 0


def test_appended_guard_hints_still_count_as_a_real_response(factory):
    """journey/sweep append their hint after the real result; that is not a refusal."""
    hinted = GO_404 + "\n\n[JOURNEY GUARD] change mechanism"
    tool = RawTool("exec_command", [hinted])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(6)]

    assert outputs[-1].startswith("ERROR: [TARGET ABSENT]")
    assert guard.tripped


# ---------------------------------------------------------------------------
# fix5: the target-absent stop belongs on the *next* round boundary
# ---------------------------------------------------------------------------

#: The flag a sibling call reads in the same round that trips the guard.
SIBLING_FLAG = "flag{fix5_target_absent_sibling_5a2c}"
#: The extractor scores a candidate by proximity to the challenge host, so the
#: sibling output has to mention it (same shape as the enum-guard test).
SIBLING_OUTPUT = f"200 OK from http://127.0.0.1:9/body -> {SIBLING_FLAG}"


def test_target_absent_stop_waits_for_the_next_round_boundary(
    tmp_path, run_env, monkeypatch
) -> None:
    """A flag from a sibling call in the tripping round still reaches answers.

    Vendor queue order is ``tool_call_item -> response.completed(N) ->
    [tools run] -> output batch``: each event is queued as it is produced, so
    boundary N arrives *before* round N's outputs and this stop lands on
    boundary N+1, after the FIFO queue delivered every output of round N.
    Drop the ``round_boundary`` gate and the sixth output event (the guard's
    own hard error) raises immediately: the sibling flag never reaches
    ``captured`` and ``answers`` stays empty.
    """
    import strix.core.runner as runner_mod

    from ctf_strix import agent as agent_mod
    from ctf_strix import target_absent

    from strix.agents import factory as live_factory  # noqa: PLC0415

    monkeypatch.setattr(live_factory, "_with_bounded_result", lambda tool: tool)
    _write_task(tmp_path)
    host = "https://absent-fix5.test"

    steps: list[str] = []

    async def _run(**kwargs) -> types.SimpleNamespace:
        sink = kwargs["event_sink"]
        tool = FakeTool("exec_command", [GO_404])
        wrapped = live_factory._with_bounded_result(tool)
        # Six distinct paths, one body: the sixth result is the hard error.
        out = ""
        for index in range(6):
            call_id = f"c{index}"
            args = _args(f"/probe-{index}", host=host)
            sink("root", _event("tool_call_item", call_id=call_id, args=args))
            out = await wrapped.on_invoke_tool(None, args)
            sink(
                "root",
                _event("tool_call_output_item", call_id=call_id, output=out, args=args),
            )
            steps.append(f"output-{index}")
        assert out.startswith("ERROR: [TARGET ABSENT]")
        # A sibling call in the same round is the one that reads the flag.
        sibling_args = '{"cmd": "cat /flag"}'
        sink("root", _event("tool_call_item", call_id="c-sibling", args=sibling_args))
        sink(
            "root",
            _event(
                "tool_call_output_item",
                call_id="c-sibling",
                output=SIBLING_OUTPUT,
                args=sibling_args,
            ),
        )
        steps.append("sibling-output")
        sink("root", _round_end())
        steps.append("boundary")
        return types.SimpleNamespace()

    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert payload["answers"] == {"flag": SIBLING_FLAG}, (
        "the sibling output (which carried the flag) never reached the sink's "
        "capture path -- the raise fired on an output event, not the boundary"
    )
    assert payload["stop_reason"] == "solved"
    assert steps[-1] == "sibling-output", steps
    assert "boundary" not in steps


# ---------------------------------------------------------------------------
# WEB-3: an auth wall is a live application, not an absent target
# ---------------------------------------------------------------------------

UNAUTHORIZED = '{"error":"unauthorized"}'


def _probe_result(status: int, body: str, *, path: str = "/x") -> str:
    """One ``http_probe`` result: status head, ``hdr:`` lines, ``body:`` line."""
    return (
        f"[HTTP {status}] GET https://absent.test{path} | 0.11s | 27B | "
        "application/json\n"
        "hdr: content-type=application/json\n"
        f"body: {body}\n"
        "next: 鉴权被拒：先走注册/登录拿会话，别继续盲试参数。\n"
    )


def test_401_on_six_paths_does_not_declare_the_target_absent(factory):
    """WEB-3: six paths behind one login wall must not kill a live target.

    ``{"error":"unauthorized"}`` has no application marker (its only key is in
    ``_ERROR_KEYS``) and 401 is not in ``_DEAD_STATUSES``, so before the auth
    branch every one of these counted as "uninformative" and the sixth tripped
    the guard -- on a target whose routing layer had just answered.
    """
    results = [_probe_result(401, UNAUTHORIZED, path=f"/p{i}") for i in range(8)]
    tool = RawTool("http_probe", results)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/p{index}")) for index in range(8)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped, "an auth wall means the application is up"
    assert guard.observations == 0


def test_403_on_six_paths_does_not_declare_the_target_absent(factory):
    """403 is the same signal: something answered and refused on purpose."""
    results = [_probe_result(403, UNAUTHORIZED, path=f"/p{i}") for i in range(6)]
    tool = RawTool("http_probe", results)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/p{index}")) for index in range(6)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped


def test_hidden_status_with_auth_body_does_not_fire(factory):
    """``curl -s`` prints only the body: the auth phrase is the only signal."""
    tool = FakeTool("exec_command", [UNAUTHORIZED])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(8)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped


def test_auth_wall_latches_the_origin_alive(factory):
    """One 401 proves liveness: later identical 404s cannot resurrect the verdict."""
    wall = _probe_result(401, UNAUTHORIZED, path="/login")
    results = [wall] + [_probe_result(404, GO_404, path=f"/p{i}") for i in range(10)]
    tool = RawTool("http_probe", results)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args("/login"))]
    outputs += [_run(wrapped, _args(f"/probe-{index}")) for index in range(10)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped


def test_generic_error_body_still_fires(factory):
    """Reverse control: the auth regex must not rescue a dead host.

    ``{"error":"not found"}`` says nothing about authentication, so six
    distinct paths answering it still declare the target absent.
    """
    tool = FakeTool("exec_command", ['{"error":"not found"}'])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(6)]

    assert outputs[-1].startswith("ERROR: [TARGET ABSENT]")
    assert guard.tripped


def test_present_non_auth_status_ignores_auth_words_in_the_body(factory):
    """A printed status decides on its own: 500 + "unauthorized" prose still counts."""
    results = [
        _probe_result(500, "internal error: unauthorized middleware failed")
        for _ in range(6)
    ]
    tool = RawTool("http_probe", results)
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _args(f"/probe-{index}")) for index in range(6)]

    assert outputs[-1].startswith("ERROR: [TARGET ABSENT]")
    assert guard.tripped


# ---------------------------------------------------------------------------
# PWN-8: tcp / tcp_batch get their own dead-target channel
# ---------------------------------------------------------------------------
#
# ``target_absent`` used to read only http(s) URLs out of the arguments, so a
# socket tool was invisible to it: a dead service could absorb every retry and
# the run burned the wall clock.  The rule added here is deliberately narrower
# than the http one, because "the port refused" is *not* "the host is gone":
#
#   * three failed connects to the same ``host:port``      -> refuse that origin
#   * three DNS failures for the same ``host:port``        -> end the run
#   * anything that proves the socket opened (banner, TLS or send failure) resets
#
# A refused port is the common wrong-port mistake, so it must never end the run
# -- only stop the agent from re-dialling the same address.

REFUSED = (
    "[tcp] connection refused by tcp-absent.test:9. next: confirm the port from "
    "the task statement; a refused port on a running box usually means the wrong "
    "port, not a dead box."
)
TIMEOUT = (
    "[tcp] connect timed out to tcp-absent.test:9 after 5s. next: retry once; a "
    "host that keeps timing out on this exact port is not answering."
)
NO_ROUTE = (
    "[tcp] cannot reach tcp-absent.test:9 (OSError: Network is unreachable). "
    "next: no route to that address -- check the VPN/tunnel before assuming the "
    "service is down."
)
DNS_FAIL = (
    "[tcp] DNS failed for tcp-absent.test: [Errno 11001] getaddrinfo failed. next: "
    "check the hostname from the task statement."
)
LIVE = "[tcp] tcp-absent.test:9 connected in 3 ms; banner=12 B ascii='ctf ready'\n> "
TLS_FAIL = (
    "[tcp] TLS handshake failed (SSLError: wrong version number). next: retry "
    "without tls=True; the port answered TCP but not TLS."
)
SEND_FAIL = "[tcp] send failed: [Errno 32] Broken pipe. The peer closed after the banner."
PARAM_ERROR = "[tcp] host is empty. Format: tcp(host='node1.ctfy.run', port=1337)"


def _tcp_args(port: int = 9, host: str = "tcp-absent.test") -> str:
    return json.dumps({"host": host, "port": port})


def test_three_refused_connects_block_that_host_port(factory):
    tool = RawTool("tcp", [REFUSED])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(3)]

    assert not any(out.startswith("ERROR:") for out in outputs[:2])
    blocked = outputs[2]
    assert blocked.startswith("ERROR: [TCP UNREACHABLE]")
    assert len(blocked) < 400
    assert tool.calls == 3
    # A refused port is a wrong-port hint, not a dead host: the run must go on.
    assert not guard.tripped
    assert guard.tripped_origin is None

    calls_at_verdict = tool.calls
    refused = _run(wrapped, _tcp_args())
    assert refused.startswith("ERROR: [TCP UNREACHABLE]")
    assert tool.calls == calls_at_verdict, "a blocked tcp call must not dial again"
    assert guard.blocked_calls == 1


def test_three_dns_failures_end_the_run(factory):
    tool = RawTool("tcp", [DNS_FAIL])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(3)]

    assert outputs[-1].startswith("ERROR: [TCP UNREACHABLE]")
    assert guard.tripped
    assert guard.tripped_origin == "tcp-absent.test:9"
    detail = guard.stop_detail()
    assert "did not resolve as a hostname" in detail
    # The http wording would be a lie here: there were no paths and no response.
    assert "uninformative response" not in detail


def test_two_failures_are_not_enough(factory):
    tool = RawTool("tcp", [REFUSED])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(2)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard.tripped
    assert not guard._tcp_dead


def test_mixed_failure_kinds_accumulate_on_one_origin(factory):
    """Refused + timeout + no-route is still "three connects that never opened"."""
    tool = RawTool("tcp", [REFUSED, TIMEOUT, NO_ROUTE])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(3)]

    assert outputs[-1].startswith("ERROR: [TCP UNREACHABLE]")


def test_a_completed_handshake_resets_the_counts(factory):
    tool = RawTool("tcp", [REFUSED, REFUSED, LIVE, REFUSED, REFUSED])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(5)]

    assert not any(out.startswith("ERROR:") for out in outputs), (
        "the live call in the middle must clear the two failures before it"
    )
    assert not guard._tcp_dead


@pytest.mark.parametrize("proof_of_life", [LIVE, TLS_FAIL, SEND_FAIL])
def test_anything_that_opened_the_socket_is_alive(factory, proof_of_life):
    """TLS/send failures happen *after* accept: the box is up, the port is right."""
    tool = RawTool("tcp", [proof_of_life])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(6)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard._tcp_dead
    assert guard.observations == 6


def test_a_different_port_is_a_different_origin(factory):
    tool = RawTool("tcp", [REFUSED])
    guard, (wrapped,) = _install(factory, [tool])

    # Two failures each on two ports: four failures, zero verdicts.
    for port in (9, 1337):
        for _ in range(2):
            out = _run(wrapped, _tcp_args(port=port))
            assert not out.startswith("ERROR:")

    assert not guard._tcp_dead
    # ... and a port that has not burned its attempts still runs after another
    # one is dead.  (1337 has two failures banked, so the third would verdict.)
    for _ in range(3):
        _run(wrapped, _tcp_args(port=9))
    assert _run(wrapped, _tcp_args(port=1338)).startswith("[tcp]")


def test_argument_errors_never_reach_the_network_and_never_count(factory):
    tool = RawTool("tcp", [PARAM_ERROR, "[tcp] invalid port 'x'. It must be 1-65535."])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(6)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert guard.observations == 0
    assert not guard._tcp_fail


def test_a_host_without_a_usable_port_is_not_counted(factory):
    """No port in the arguments -> no origin -> nothing to blame."""
    tool = RawTool("tcp", [REFUSED])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, json.dumps({"host": "tcp-absent.test"})) for _ in range(5)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert guard.observations == 0


def test_a_recorded_answer_stops_tcp_counting_too(factory):
    tool = RawTool("tcp", [REFUSED])
    guard, (wrapped,) = _install(factory, [tool])
    guard.note_answer()

    outputs = [_run(wrapped, _tcp_args()) for _ in range(6)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard._tcp_dead


def test_tcp_batch_refusals_are_counted_as_well(factory):
    """``tcp_batch`` is the other tool that dials; it must be covered too."""
    tool = RawTool("tcp_batch", [REFUSED])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(3)]

    assert outputs[-1].startswith("ERROR: [TCP UNREACHABLE]")
    assert not guard.tripped, "a refused port must not end the run"


def test_tcp_batch_success_header_is_read_as_alive(factory):
    """A batch that reached the service must never be counted as a dead one."""
    live = "[tcp_batch] tcp-absent.test:9 2 payload(s) same_conn=True in 0.3s\n#0 ok\n#1 ok"
    tool = RawTool("tcp_batch", [live])
    guard, (wrapped,) = _install(factory, [tool])

    outputs = [_run(wrapped, _tcp_args()) for _ in range(4)]

    assert not any(out.startswith("ERROR:") for out in outputs)
    assert not guard._tcp_dead
    assert guard.observations == 4


def test_an_http_trip_does_not_poison_tcp_origins(factory):
    """The two channels share counters only through the run-level stop."""
    tool = RawTool("tcp", [REFUSED])
    guard, (wrapped,) = _install(factory, [tool])

    for _ in range(3):
        _run(wrapped, _tcp_args())
    assert not guard.tripped

    # One http 404 is not "six distinct paths", and the http path must not be
    # blocked by a tcp verdict.
    assert guard.refusal(_args("/probe")) is None
