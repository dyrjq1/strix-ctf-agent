"""Mechanism-class hard block + transport failures are not observations.

Two mechanisms from the deterministic planning core:

* a class-level hard refusal once one CAPEC class keeps returning the same
  answer -- the class hint already fires there, but text did not stop the run;
* a call that never reached the target must not advance any counter, or a
  jittery target blocks a healthy family.

Both ship **off** (``CTF_CLASS_BLOCK``); the off-mode tests pin that the
switch adds no refusals and no state.
"""

from __future__ import annotations

import asyncio
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix import enum_guard  # noqa: E402

#: One information-collection probe, repeated verbatim.  A single path keeps
#: the family's diversity gate at 1, so any block here is the class block.
INFO_ARGS = '{"cmd": "curl -s https://x.test/.git/config"}'
INFO_BODY = "[HTTP 404] no such file"

#: A different class on another path: the "should not fire" control.
ACCESS_ARGS = '{"cmd": "curl -s https://x.test/admin/panel"}'
ACCESS_BODY = "[HTTP 403] forbidden"


@pytest.fixture(autouse=True)
def _class_block_off(monkeypatch):
    """Never inherit the switch from the developer's shell."""
    monkeypatch.delenv("CTF_CLASS_BLOCK", raising=False)


@pytest.fixture
def class_block_on(monkeypatch):
    monkeypatch.setenv("CTF_CLASS_BLOCK", "1")


def _observe(guard, args, body, tool="exec_command"):
    return guard.observe(tool, args, body)


def test_off_switch_never_blocks_a_class():
    guard = enum_guard.EnumerationGuard()
    outputs = [_observe(guard, INFO_ARGS, INFO_BODY) for _ in range(20)]

    assert guard.blocked_classes == set()
    assert guard.class_blocked_calls == 0
    assert all("is exhausted" not in (out or "") for out in outputs)
    assert all(not (out or "").startswith("ERROR:") for out in outputs)


def test_off_switch_stats_keys_are_neutral():
    stats = enum_guard.EnumerationGuard().stats()
    assert stats["blocked_classes"] == []
    assert stats["class_blocked_calls"] == 0


def test_on_switch_blocks_the_class_from_the_ninth_call(class_block_on):
    guard = enum_guard.EnumerationGuard()
    for _ in range(enum_guard._CLASS_BLOCK_AFTER - 1):
        _observe(guard, INFO_ARGS, INFO_BODY)

    assert "information-collection" not in guard.blocked_classes

    threshold = _observe(guard, INFO_ARGS, INFO_BODY)
    assert threshold.startswith("ERROR: [MECHANISM GUARD]")
    assert "information-collection" in guard.blocked_classes

    token = guard.begin("exec_command", INFO_ARGS)
    refused = guard.refusal(token)
    assert refused is not None
    assert refused.startswith("ERROR: [MECHANISM GUARD]")
    assert "information-collection" in refused
    assert guard.class_blocked_calls == 1


def test_on_switch_family_state_is_untouched(class_block_on):
    guard = enum_guard.EnumerationGuard()
    for _ in range(enum_guard._CLASS_BLOCK_AFTER):
        _observe(guard, INFO_ARGS, INFO_BODY)

    assert guard.blocked == set()
    assert guard.exhausted is False
    # Same-path retries never had path diversity, so the family rules stay put.
    assert guard.counts


def test_on_switch_other_classes_still_run(class_block_on):
    guard = enum_guard.EnumerationGuard()
    for _ in range(enum_guard._CLASS_BLOCK_AFTER):
        _observe(guard, INFO_ARGS, INFO_BODY)
    assert "information-collection" in guard.blocked_classes

    token = guard.begin("exec_command", ACCESS_ARGS)
    assert guard.refusal(token) is None
    _observe(guard, ACCESS_ARGS, ACCESS_BODY)
    assert "access-control" in guard.mechanisms


def test_on_switch_unclassifiable_calls_are_not_refused(class_block_on):
    guard = enum_guard.EnumerationGuard()
    for _ in range(enum_guard._CLASS_BLOCK_AFTER):
        _observe(guard, INFO_ARGS, INFO_BODY)

    token = guard.begin("exec_command", '{"cmd": "ls -la /tmp"}')
    assert guard.refusal(token) is None


@pytest.mark.parametrize(
    "text",
    [
        "[Errno 111] Connection refused",
        "ConnectionResetError: [Errno 104] Connection reset by peer",
        "curl: (28) Operation timed out after 5001 milliseconds",
        "curl: (6) Could not resolve host: Temporary failure in name resolution",
        "SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number",
        "[tcp] connection closed",
    ],
)
def test_unreachable_is_not_an_observation(text, class_block_on):
    guard = enum_guard.EnumerationGuard()

    first = _observe(guard, INFO_ARGS, text)
    assert first is not None
    assert "目标不可达" in first
    assert guard.stall == 0
    assert guard.max_stall == 0
    assert guard.counts == Counter()
    assert dict(guard.mechanisms) == {}
    assert guard._global == set()
    assert guard._family_paths == {}
    assert guard.new_path_streak == 0
    assert guard.blocked_classes == set()

    second = _observe(guard, INFO_ARGS, text)
    assert second is None, "the notice is per kind, once per run"


def test_unreachable_does_not_clear_an_earlier_stall(class_block_on):
    guard = enum_guard.EnumerationGuard()
    _observe(guard, INFO_ARGS, INFO_BODY)
    _observe(guard, INFO_ARGS, INFO_BODY)
    stall_before = guard.stall
    counts_before = Counter(guard.counts)

    _observe(guard, INFO_ARGS, "curl: (28) Operation timed out")

    assert guard.stall == stall_before
    assert guard.counts == counts_before


def test_off_switch_keeps_the_old_unreachable_behaviour():
    """Equivalence arm: with the switch off a dead call counts like before."""
    guard = enum_guard.EnumerationGuard()
    key, _args = guard.begin("exec_command", INFO_ARGS)

    _observe(guard, INFO_ARGS, "curl: (7) Failed to connect: Connection refused")
    _observe(guard, INFO_ARGS, "curl: (7) Failed to connect: Connection refused")

    assert key is not None
    assert guard.stall == 1
    assert guard.counts[key] == 1


@pytest.mark.parametrize("status", ["[HTTP 200] ok", "[HTTP 404] not found"])
def test_real_responses_still_count(status):
    guard = enum_guard.EnumerationGuard()
    key, _args = guard.begin("exec_command", INFO_ARGS)

    assert _observe(guard, INFO_ARGS, status) != "目标不可达"
    _observe(guard, INFO_ARGS, status)

    assert key is not None
    assert guard.counts[key] == 1


def test_note_answer_clears_the_class_block(class_block_on):
    guard = enum_guard.EnumerationGuard()
    for _ in range(enum_guard._CLASS_BLOCK_AFTER):
        _observe(guard, INFO_ARGS, INFO_BODY)
    assert guard.blocked_classes

    guard.note_answer()

    assert guard.blocked_classes == set()
    assert guard.refusal(guard.begin("exec_command", INFO_ARGS)) is None


def test_soft_reset_keeps_the_class_block_but_drops_the_run(class_block_on):
    guard = enum_guard.EnumerationGuard()
    for _ in range(enum_guard._CLASS_BLOCK_AFTER):
        _observe(guard, INFO_ARGS, INFO_BODY)

    guard.soft_reset()

    assert guard.blocked_classes == {"information-collection"}
    assert guard._class_misses == 0
    assert guard._class_run is None


def test_class_refusal_text_is_deterministic(class_block_on):
    guard = enum_guard.EnumerationGuard()
    for _ in range(enum_guard._CLASS_BLOCK_AFTER):
        _observe(guard, INFO_ARGS, INFO_BODY)

    first = guard._class_blocked_error("information-collection")
    second = guard._class_blocked_error("information-collection")
    assert first == second
    assert len(first) < 400
    assert "information-collection" not in first.split("Switch mechanism to")[-1]


class FakeTool:
    def __init__(self, name: str, result: str) -> None:
        self.name = name
        self.result = result
        self.calls = 0

    async def on_invoke_tool(self, ctx, raw_input: str) -> str:
        self.calls += 1
        return self.result


@pytest.fixture
def factory(monkeypatch):
    pytest.importorskip("strix.agents")
    from strix.agents import factory as strix_factory

    monkeypatch.setattr(strix_factory, "_with_bounded_result", lambda tool: tool)
    return strix_factory


def test_blocked_class_never_reaches_the_inner_tool(class_block_on, factory):
    tool = FakeTool("exec_command", INFO_BODY)
    guard = enum_guard.install()
    wrapped = factory._with_bounded_result(tool)

    for _ in range(enum_guard._CLASS_BLOCK_AFTER):
        asyncio.run(wrapped.on_invoke_tool(None, INFO_ARGS))

    assert tool.calls == enum_guard._CLASS_BLOCK_AFTER
    assert "information-collection" in guard.blocked_classes

    refused = asyncio.run(wrapped.on_invoke_tool(None, INFO_ARGS))
    assert refused.startswith("ERROR: [MECHANISM GUARD]")
    assert tool.calls == enum_guard._CLASS_BLOCK_AFTER
    assert guard.class_blocked_calls == 1
