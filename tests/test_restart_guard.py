"""restart_guard: mechanical trigger, fixed ceilings, deterministic rebuild."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import restart_guard as rg  # noqa: E402
from ctf_strix.traffic import Exchange  # noqa: E402


def _guard(elapsed: float = 950.0, wall: float = 1800.0, window: int = 20) -> rg.RestartGuard:
    return rg.RestartGuard(
        elapsed=lambda: elapsed,
        wall=lambda: wall,
        ledger_items=lambda: [],
        window=window,
    )


def _stall(guard: rg.RestartGuard, actions: int = 21) -> None:
    for index in range(actions):
        guard.note_mechanism("information-collection")
        guard.note_endpoint("http://target", "/", request_id=f"r{index + 1}")


def test_trigger_fires_on_wall_plus_mechanism_and_endpoint_stall() -> None:
    guard = _guard()
    _stall(guard)

    state = guard.evaluate()

    assert state.t1 and state.t2 and state.t3
    assert state.triggered
    assert guard.request_injection() is not None


def test_new_endpoint_immediately_vetoes_the_trigger() -> None:
    guard = _guard()
    _stall(guard)
    assert guard.evaluate().triggered

    guard.note_endpoint("http://target", "/new", request_id="r99")

    state = guard.evaluate()
    assert not state.t3
    assert not state.triggered
    assert guard.request_injection() is None


def test_slow_but_correct_run_with_continuous_new_endpoints_never_triggers() -> None:
    guard = _guard(elapsed=1900.0, wall=2000.0)
    for index in range(40):
        guard.note_mechanism("information-collection")
        guard.note_endpoint("http://target", f"/item/{index}", request_id=f"r{index + 1}")

    state = guard.evaluate()
    assert not state.t3
    assert not state.triggered
    assert guard.request_injection() is None


def test_fourth_l1_request_is_refused_without_injection() -> None:
    guard = _guard()
    _stall(guard)

    first = guard.request_injection(rg.L1)
    second = guard.request_injection(rg.L1)
    third = guard.request_injection(rg.L1)
    fourth = guard.request_injection(rg.L1)

    assert first and second
    assert third is None
    assert fourth is None
    assert guard.issued(rg.L1) == rg.LIMITS[rg.L1] == 2
    assert guard.requests(rg.L1) == 4


def test_l1_policy_advises_but_never_refuses_a_repeat_of_the_refuted_mechanism() -> None:
    guard = _guard()
    _stall(guard)
    assert guard.request_injection(rg.L1)

    note = guard.check_call("exec_command", "curl -s http://target/robots.txt")
    assert note is not None
    assert "[RESTART GUARD L1]" in note
    assert not note.startswith("ERROR:")
    assert "advisory" in note

    # The first classified probe consumes the policy, so the note is shown once.
    again = guard.check_call("exec_command", "curl -s http://target/robots.txt")
    assert again is None


def test_l1_policy_is_silent_when_the_probe_uses_an_unused_class() -> None:
    guard = _guard()
    _stall(guard)
    assert guard.request_injection(rg.L1)

    unused = guard.check_call(
        "exec_command", "curl -s 'http://target/api?id=1 union select 1'"
    )
    assert unused is None

    # Consumed here too: a later repeat draws no note either.
    assert guard.check_call("exec_command", "curl -s http://target/robots.txt") is None


def test_l1_policy_survives_an_unclassifiable_call() -> None:
    guard = _guard()
    _stall(guard)
    assert guard.request_injection(rg.L1)

    assert guard.check_call("exec_command", "pwd") is None

    note = guard.check_call("exec_command", "curl -s http://target/robots.txt")
    assert note is not None and "[RESTART GUARD L1]" in note


class _FakeTool:
    """Minimal stand-in for ``agents.FunctionTool`` at the attach layer."""

    def __init__(self) -> None:
        self.name = "exec_command"
        self.calls = 0
        self.on_invoke_tool = self._invoke

    async def _invoke(self, ctx: Any, raw_input: str) -> str:
        self.calls += 1
        return "OUTPUT"


def test_attach_runs_the_probe_and_appends_the_note(monkeypatch) -> None:
    guard = _guard()
    _stall(guard)
    assert guard.request_injection(rg.L1)
    monkeypatch.setattr(rg, "current", lambda: guard)

    tool = rg.attach(_FakeTool())
    result = asyncio.run(
        tool.on_invoke_tool(
            None, json.dumps({"command": "curl -s http://target/robots.txt"})
        )
    )

    assert tool.calls == 1
    assert result.startswith("OUTPUT")
    assert "[RESTART GUARD L1]" in result


def _ledger() -> list[Exchange]:
    return [
        Exchange(
            id="r1",
            ts=0.0,
            method="GET",
            url="http://target/login",
            status=200,
            resp_body="<title>login</title>",
            size=19,
            resp_headers={"set-cookie": "sid=abc"},
        ),
        Exchange(
            id="r2",
            ts=1.0,
            method="GET",
            url="http://target/login",
            status=200,
            resp_body="<title>login</title>",
            size=19,
        ),
        Exchange(
            id="r3",
            ts=2.0,
            method="GET",
            url="http://target/login",
            status=200,
            resp_body="<title>login</title>",
            size=19,
        ),
        Exchange(
            id="r4",
            ts=3.0,
            method="POST",
            url="http://target/api/login",
            status=401,
            resp_body="no",
            size=2,
            req_headers={"Authorization": "Basic dXNlcjpwYXNz"},
        ),
    ]


def test_rebuild_block_is_byte_identical_for_the_same_ledger() -> None:
    first = rg.build_rebuild_block(_ledger(), remaining_s=321.4)
    second = rg.build_rebuild_block(_ledger(), remaining_s=321.4)

    assert first.encode("utf-8") == second.encode("utf-8")
    assert "\n".join(first.splitlines()) == first
    assert " | verified-response" in first
    assert " | verified-credential" in first
    assert " | negative" in first
    assert " | target" in first


def test_naming_statement_has_no_ticket_ip_or_path() -> None:
    text = rg.CHANGE_SUMMARY
    assert text.count(". ") <= 0
    assert not re.search(r"\b(?:CTF|S|r)\d{2,4}\b", text, re.I)
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    assert "/" not in text and chr(92) not in text
