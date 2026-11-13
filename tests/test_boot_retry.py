"""A start that never reached the model is retried once, on a fresh sandbox.

``CTF_ATTEMPTS`` defaults to 1, so ``budgets`` is a single-element list and the
one attempt is also the last one.  When ``run_strix_scan`` raises *before* the
first tool call and before any completed model call, that attempt never ran:
``runs_ok`` stays 0 and ``main`` writes ``stop_reason="error"``, which the
platform counts as "errored" even though no question was ever asked of the
model.  The fix retries that dead start exactly once, with the unspent rest of
the same turn budget (``max_turns - turns_total``), so the whole-question turn
ceiling is provably unchanged.

The retry must use a **new** scan id.  The dead start is the last attempt, so
its ``finally`` already ran ``session_manager.cleanup`` (the sandbox is gone),
and vendor treats an existing ``agents.json`` as a resume signal while
``agents.db`` is only created later by ``open_agent_session`` -- reusing the id
would hit "missing SDK session database" instead of starting the question.

The real runner needs an LLM key and a sandbox; the fake below records what
each call was handed and drives the same event sink the vendor runner does.
"""

from __future__ import annotations

import json
import sys
import types

import pytest

import strix.core.runner as runner_mod

from ctf_strix import agent as agent_mod

#: Tool calls a fake attempt emits when it is meant to look like real work.
CALLS = 3

#: Turn ceiling the retry-budget test drives the run with.
TURNS = 30


def _event(kind: str, *, call_id: str, output: str = "") -> object:
    return types.SimpleNamespace(
        item=types.SimpleNamespace(
            type=kind,
            output=output,
            call_id=call_id,
            raw_item=types.SimpleNamespace(
                name="exec_command", arguments="{}", call_id=call_id
            ),
        )
    )


def _emit(sink, count: int) -> None:
    for index in range(count):
        call_id = f"call-{index}"
        sink("root", _event("tool_call_item", call_id=call_id))
        sink(
            "root",
            _event("tool_call_output_item", call_id=call_id, output=f"output {index}"),
        )


@pytest.fixture()
def run_env(tmp_path, monkeypatch):
    """Point ``main`` at an isolated work dir with the default attempt count."""
    stub = types.ModuleType("ctf_strix.local_backend")
    stub.install = lambda: None
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    for name in (
        "CTFY_EVAL_DRY_RUN",
        "CTFY_SOFT_DEADLINE",
        # Default ``CTF_ATTEMPTS=1`` is the configuration the retry exists for.
        "CTF_ATTEMPTS",
        "CTF_ATTEMPT_SPLIT",
        "CTFY_EVAL_MAX_TURNS",
        "CTF_MAX_TURNS",
    ):
        monkeypatch.delenv(name, raising=False)
    return stub


def _task(tmp_path) -> dict:
    return {
        "run_mode": "instance",
        "challenge": {
            "id": "BOOT",
            "name": "boot-retry",
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


def test_dead_start_is_retried_once(tmp_path, run_env, monkeypatch) -> None:
    """Zero calls + zero completed model calls on attempt 1 -> one fresh retry."""
    seen = {"n": 0}

    async def _run(**kwargs):
        seen["n"] += 1
        if seen["n"] == 1:
            raise RuntimeError("sandbox backend refused the session")
        return types.SimpleNamespace()

    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert seen["n"] == 2
    assert payload["stop_reason"] == "completed"
    assert "no_attempt_ran" not in payload
    # ``main`` consumes ``no_attempt_ran`` into ``stop_reason`` and result.json is
    # a whitelist, so the retry marker's observable home is the writeup text.
    assert "boot_retry:" in payload["writeup"]


def test_a_start_that_produced_a_call_is_not_retried(
    tmp_path, run_env, monkeypatch
) -> None:
    """A run that reached a tool is a real result, not a failed boot."""
    seen = {"n": 0}

    async def _run(**kwargs):
        seen["n"] += 1
        _emit(kwargs["event_sink"], CALLS)
        raise RuntimeError("runner died mid-question")

    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert seen["n"] == 1
    assert payload["stop_reason"] == "error"
    assert "boot_retry:" not in payload["writeup"]


def test_a_dead_start_is_retried_only_once(tmp_path, run_env, monkeypatch) -> None:
    """Two dead starts in a row: the second one is reported, not retried again."""
    seen = {"n": 0}

    async def _run(**kwargs):
        seen["n"] += 1
        raise RuntimeError("sandbox backend refused the session")

    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    payload = _payload(tmp_path)
    assert seen["n"] == 2
    assert payload["stop_reason"] == "error"
    # The retry happened (marker present) but the failure still stands.
    assert "boot_retry:" in payload["writeup"]


def test_retry_uses_a_fresh_scan_id_and_resends_attachments(
    tmp_path, run_env, monkeypatch
) -> None:
    """The retry starts a new sandbox and pays for it out of the same budget.

    Reusing the id would resume a snapshot written by the dead start (empty
    graph, no ``agents.db``).  The extra turn budget is the unspent remainder,
    so the whole-question ceiling does not move.
    """
    (tmp_path / "chal.txt").write_text("attachment payload\n", encoding="utf-8")
    monkeypatch.setenv("CTF_MAX_TURNS", str(TURNS))
    seen = {"n": 0}
    calls: list[dict] = []

    async def _run(**kwargs):
        seen["n"] += 1
        calls.append(
            {
                "scan_id": kwargs["scan_id"],
                "max_turns": kwargs["max_turns"],
                "extra_files": kwargs["extra_files"],
                "cleanup_on_exit": kwargs["cleanup_on_exit"],
            }
        )
        if seen["n"] == 1:
            raise RuntimeError("sandbox backend refused the session")
        return types.SimpleNamespace()

    _write_task(tmp_path)
    monkeypatch.setattr(runner_mod, "run_strix_scan", _run)

    assert agent_mod.main() == 0

    assert len(calls) == 2
    first, second = calls
    assert first["scan_id"] != second["scan_id"]
    assert second["scan_id"] == first["scan_id"] + "-r1"
    # Nothing was spent before the dead start, so the retry gets exactly the
    # unspent remainder of the same ceiling.
    assert first["max_turns"] == TURNS
    assert second["max_turns"] == TURNS - 0
    # The first sandbox gets the attachments; the fresh one must too, or the
    # retry would start with the challenge files missing.
    # ``_local_attachments`` mounts them under /workspace/.
    assert [f["workspace_path"] for f in first["extra_files"]] == ["/workspace/chal.txt"]
    assert [f["workspace_path"] for f in second["extra_files"]] == ["/workspace/chal.txt"]
    # Both calls tear down their own sandbox: each is the last attempt of its
    # ``budgets`` list, and the dead one's sandbox was already destroyed.
    assert first["cleanup_on_exit"] is True
    assert second["cleanup_on_exit"] is True