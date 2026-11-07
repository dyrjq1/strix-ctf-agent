# -*- coding: utf-8 -*-
"""Per-call LLM telemetry (C8): one structured record per completed call.

The point of the record is diagnosis, not accounting: given a hit-rate drop,
``turn`` + ``prefix_hash`` + ``item_count`` + ``capped_items`` say which call
changed shape.  All fixtures are synthetic.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import context as ctf_context  # noqa: E402
from ctf_strix import llm_telemetry  # noqa: E402
from ctf_strix import usage_meter  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv(usage_meter._CAP_ENV, raising=False)
    monkeypatch.delenv("CTF_USAGE_PATH", raising=False)
    monkeypatch.delenv(llm_telemetry.ENV_PATH, raising=False)
    usage_meter.reset_for_tests()
    try:
        yield
    finally:
        usage_meter.reset_for_tests()


def _usage(input_tokens=1_000, output_tokens=200, cached=0, cache_write=0):
    return types.SimpleNamespace(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
        input_tokens_details=types.SimpleNamespace(
            cached_tokens=cached, cache_write_tokens=cache_write
        ),
    )


def _response(usage=None):
    return types.SimpleNamespace(usage=usage)


def _drive(response, *, system="system", items=None, cap_items=None, calls=1, agent=None):
    items = items if items is not None else [{"role": "user", "content": "hello"}]

    async def go():
        from strix.core import hooks as strix_hooks

        hook = strix_hooks.ReportUsageHooks(model="test-model")
        ctx = types.SimpleNamespace(context={"agent_id": "root"})
        for _ in range(calls):
            await strix_hooks.ReportUsageHooks.on_llm_start(hook, ctx, agent, system, items)
            if cap_items is not None:
                ctf_context.HistoryCapper(
                    cap_chars=10, head=5, tail=5, arg_cap=0
                ).apply(cap_items)
            await strix_hooks.ReportUsageHooks.on_llm_end(hook, ctx, agent, response)

    asyncio.run(go())


def _lines(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_records_turn_tokens_and_cache(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    _drive(_response(_usage(cached=750)), calls=2)

    rows = _lines(trace)
    assert [row["turn"] for row in rows] == [1, 2]
    first = rows[0]
    assert first["seq"] == 1
    assert first["input"] == 1_000
    assert first["cache_read"] == 750
    assert first["hit_rate"] == 0.75
    assert first["item_count"] == 1
    assert first["capped_items"] == 0
    assert first["agent"] == "root"
    assert len(first["prefix_hash"]) == 16
    for key in (
        "ts", "seq", "agent", "turn", "input", "output", "cache_read",
        "cache_write", "hit_rate", "model", "prefix_hash", "item_count",
        "capped_items", "first_capped_index", "capped_hash",
    ):
        assert key in first


def test_missing_usage_does_not_crash(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    _drive(_response(None))

    row = _lines(trace)[0]
    assert row["input"] == 0
    assert row["cache_read"] == 0
    assert row["hit_rate"] == 0.0


def test_usage_without_cache_details_does_not_crash(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    bare = types.SimpleNamespace(input_tokens=100, output_tokens=10, total_tokens=110)
    _drive(_response(bare))

    row = _lines(trace)[0]
    assert row["cache_read"] == 0
    assert row["hit_rate"] == 0.0


def test_prefix_hash_is_stable_then_changes(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    _drive(_response(_usage()), system="alpha", calls=2)
    _drive(_response(_usage()), system="beta", calls=1)

    hashes = [row["prefix_hash"] for row in _lines(trace)]
    assert hashes[0] == hashes[1]
    assert hashes[0] != hashes[2]


def test_capped_items_and_item_count_come_from_capper(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    items = [
        {"type": "function_call_output", "call_id": "c1", "output": "x" * 100},
        {"type": "function_call_output", "call_id": "c2", "output": "short"},
    ]
    _drive(_response(_usage()), cap_items=items)

    row = _lines(trace)[0]
    assert row["item_count"] == 2
    assert row["capped_items"] == 1


def test_recent_mirrors_written_records(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    _drive(_response(_usage()), calls=3)

    assert len(llm_telemetry.recent()) == 3
    assert [row["turn"] for row in llm_telemetry.recent()] == [1, 2, 3]



def test_real_sdk_seam_records_one_row(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    from agents import Agent, RunConfig, Runner
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage

    class FakeModel(Model):
        async def get_response(self, *args, **kwargs):
            return ModelResponse(
                output=[],
                usage=Usage(
                    requests=1,
                    input_tokens=500,
                    output_tokens=20,
                    total_tokens=520,
                    input_tokens_details={"cached_tokens": 400, "cache_write_tokens": 0},
                ),
                response_id="resp-test",
            )

        def stream_response(self, *args, **kwargs):
            raise NotImplementedError("Runner.run uses get_response")

    from strix.core import hooks as strix_hooks

    asyncio.run(
        Runner.run(
            Agent(name="test", instructions="noop", model="test-model"),
            input="hi",
            run_config=RunConfig(model=FakeModel(), tracing_disabled=True),
            hooks=strix_hooks.ReportUsageHooks(model="test-model"),
            context={"agent_id": "root"},
        )
    )

    rows = _lines(trace)
    assert len(rows) == 1
    assert rows[0]["input"] == 500
    assert rows[0]["cache_read"] == 400
    assert rows[0]["hit_rate"] == 0.8
    assert rows[0]["turn"] == 1
    assert rows[0]["item_count"] >= 1


def test_cache_write_and_model_are_recorded(tmp_path, monkeypatch):
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()

    agent = types.SimpleNamespace(model="deepseek-chat")
    _drive(_response(_usage(cached=0, cache_write=12_000)), agent=agent)

    row = _lines(trace)[0]
    assert row["cache_read"] == 0
    assert row["cache_write"] == 12_000
    assert row["hit_rate"] == 0.0
    assert row["model"] == "deepseek-chat"


def test_real_seam_with_capper_records_first_capped_item(tmp_path, monkeypatch):
    """Real Runner seam + installed capper: mid-history cap must be visible."""
    trace = tmp_path / "llm_calls.jsonl"
    monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
    usage_meter.install()
    monkeypatch.setattr(
        ctf_context,
        "_CAPPER",
        ctf_context.HistoryCapper(cap_chars=10, head=5, tail=5, arg_cap=0),
    )

    from agents import Agent, RunConfig, Runner
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage

    class FakeModel(Model):
        async def get_response(self, *args, **kwargs):
            return ModelResponse(
                output=[],
                usage=Usage(
                    requests=1,
                    input_tokens=900,
                    output_tokens=10,
                    total_tokens=910,
                    input_tokens_details={"cached_tokens": 0, "cache_write_tokens": 800},
                ),
                response_id="resp-cap",
            )

        def stream_response(self, *args, **kwargs):
            raise NotImplementedError("Runner.run uses get_response")

    class CappingModel(Model):
        """Runs the production ``_CappingProxy`` inside a real ``Model`` seam."""

        def __init__(self, inner):
            self._inner = inner

        async def get_response(self, *args, **kwargs):
            return await self._inner.get_response(*args, **kwargs)

        def stream_response(self, *args, **kwargs):
            return self._inner.stream_response(*args, **kwargs)

    from strix.core import hooks as strix_hooks

    items = [
        {"type": "function_call_output", "call_id": "c1", "output": "x" * 400},
        {"type": "function_call_output", "call_id": "c2", "output": "short"},
    ]
    asyncio.run(
        Runner.run(
            Agent(name="test", instructions="noop", model="test-model"),
            input=items,
            run_config=RunConfig(
                model=CappingModel(ctf_context._CappingProxy(FakeModel())),
                tracing_disabled=True,
            ),
            hooks=strix_hooks.ReportUsageHooks(model="test-model"),
            context={"agent_id": "root"},
        )
    )

    row = _lines(trace)[0]
    assert row["capped_items"] == 1
    assert row["first_capped_index"] == 0
    assert row["capped_hash"] != ""
    assert row["item_count"] == 2


def test_install_reset_twice_restores_vendor_hook():
    from strix.core import hooks as strix_hooks

    vendor_end = strix_hooks.ReportUsageHooks.on_llm_end
    vendor_start = strix_hooks.ReportUsageHooks.on_llm_start
    for _ in range(2):
        usage_meter.install()
        usage_meter.reset_for_tests()
    assert strix_hooks.ReportUsageHooks.on_llm_end is vendor_end
    assert strix_hooks.ReportUsageHooks.on_llm_start is vendor_start
