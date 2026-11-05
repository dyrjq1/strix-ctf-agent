"""LLM fault routing: long transient backoff, fast credential failure.

Regression context: on 2026-11-04 the platform gateway returned 503 for
5+ minutes.  The SDK retried 2/4/8/16/32s (62s total), strix replayed the
turn five more times, and four runs died with the outage.  A separate
incident lost the BYOK key; that looked like a stream of 503s, so a longer
retry ladder without status routing would have burned the whole wall clock
on a credential that could never recover.

These tests pin the three-way split and the wall-clock clamp.  They drive the
real ``agents.retry.RetryPolicyContext`` and the real SDK retry loop so a
contract change shows up here rather than in production.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from ctf_strix import error_policy


def _http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://gateway.test/v1/chat/completions")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError("gateway error", request=request, response=response)


def _auth_error(status: int):
    from openai import AuthenticationError, PermissionDeniedError

    request = httpx.Request("POST", "http://gateway.test/v1/chat/completions")
    response = httpx.Response(status, request=request)
    cls = AuthenticationError if status == 401 else PermissionDeniedError
    return cls("credential rejected", response=response, body=None)


def _context(
    exc: BaseException,
    *,
    attempt: int = 1,
    max_retries: int = error_policy.MAX_RETRIES,
    status: int | None = None,
    network: bool = False,
):
    from agents.retry import ModelRetryNormalizedError, RetryPolicyContext

    return RetryPolicyContext(
        error=exc,
        attempt=attempt,
        max_retries=max_retries,
        stream=True,
        normalized=ModelRetryNormalizedError(
            status_code=status,
            is_network_error=network,
            is_timeout=False,
            is_abort=False,
        ),
    )


def _decide(context):
    decision = error_policy.retry_policy(context)
    if asyncio.iscoroutine(decision):
        decision = asyncio.run(decision)
    return decision


def test_503_retries_on_a_minute_scale_ladder(monkeypatch):
    """a. A >62s outage is survivable: retries continue past attempt 5."""
    monkeypatch.setattr(error_policy, "remaining_wall", lambda: None)
    delays = []
    for attempt in range(1, 9):
        decision = _decide(_context(_http_error(503), attempt=attempt, status=503))
        assert decision.retry is True
        delays.append(decision.delay)

    # The old ladder (2/4/8/16/32) totals 62s and stops.
    assert sum(delays) > 62
    assert any(delay >= 32 for delay in delays)
    assert delays == sorted(delays)


def test_remote_protocol_error_is_transient():
    """a. A dropped connection is retried on the same minute-scale ladder."""
    exc = httpx.RemoteProtocolError("peer closed connection")
    decision = _decide(_context(exc, attempt=1, network=True))
    assert decision.retry is True
    assert decision.delay == pytest.approx(error_policy.BASE_DELAY_SECONDS)

    delays = [
        _decide(_context(exc, attempt=attempt, network=True)).delay
        for attempt in range(1, 9)
    ]
    assert sum(delays) > 62, "a transport drop must outlive the old 62s ladder"


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors_fail_fast(status):
    """b. 401/403 must not retry, however many attempts remain."""
    decision = _decide(_context(_auth_error(status), attempt=1, status=status))
    assert decision.retry is False
    assert decision.reason == "credential_failure"


def test_auth_error_annotation_is_structured():
    """b. The result file gets a machine-readable credential annotation."""
    detail = error_policy.credential_failure(_auth_error(401))
    assert detail is not None
    assert detail["reason"] == "llm_credentials_rejected"
    assert detail["status_code"] == 401
    assert detail["retryable"] is False


def test_backoff_is_clamped_to_remaining_wallclock(monkeypatch):
    """c. A retry sleep never outlives the remaining wall clock."""
    monkeypatch.setattr(error_policy, "_clock", lambda: 100.0)
    error_policy.set_wall_deadline(130.0)
    try:
        decision = _decide(_context(_http_error(503), attempt=5, status=503))
        # attempt 5 would normally sleep 60s; only 30s remain (10 usable).
        assert decision.retry is True
        assert decision.delay <= 10.0
    finally:
        error_policy.clear_wall_deadline()


def test_no_retry_once_only_the_shutdown_reserve_is_left(monkeypatch):
    """c. With the wall clock spent, stop instead of sleeping to zero."""
    monkeypatch.setattr(error_policy, "_clock", lambda: 100.0)
    error_policy.set_wall_deadline(110.0)
    try:
        decision = _decide(_context(_http_error(503), attempt=1, status=503))
        assert decision.retry is False
        assert decision.reason == "wallclock_reserve"
    finally:
        error_policy.clear_wall_deadline()


@pytest.mark.parametrize("status", [400, 404])
def test_non_auth_4xx_is_neither_retried_nor_called_credential_failure(status):
    """d. A bad request is neither an outage nor a dead key."""
    exc = _http_error(status)
    decision = _decide(_context(exc, attempt=1, status=status))
    assert decision.retry is False
    assert decision.reason != "credential_failure"
    assert error_policy.credential_failure(exc) is None
    assert error_policy.classify_error(exc) == "client_error"


def test_sdk_network_flag_alone_is_transient():
    """a. Websocket-style drops have no status and may miss the class scan."""
    exc = RuntimeError("socket closed unusually")

    from agents.retry import ModelRetryNormalizedError, RetryPolicyContext

    context = RetryPolicyContext(
        error=exc,
        attempt=1,
        max_retries=error_policy.MAX_RETRIES,
        stream=True,
        normalized=ModelRetryNormalizedError(
            status_code=None,
            is_network_error=True,
            is_timeout=False,
            is_abort=False,
        ),
    )
    decision = _decide(context)
    assert decision.retry is True


def test_rate_limit_still_retries():
    decision = _decide(_context(_http_error(429), attempt=1, status=429))
    assert decision.retry is True


def test_cumulative_backoff_never_exceeds_available_wallclock(monkeypatch):
    """c. The sum of every sleep stays inside the wall budget, not just one."""
    now = [100.0]
    budget = 300.0
    deadline = now[0] + budget
    monkeypatch.setattr(error_policy, "_clock", lambda: now[0])
    error_policy.set_wall_deadline(deadline)
    total = 0.0
    try:
        for attempt in range(1, error_policy.MAX_RETRIES + 1):
            decision = _decide(_context(_http_error(503), attempt=attempt, status=503))
            if not decision.retry:
                break
            total += decision.delay
            now[0] += decision.delay
            assert now[0] < deadline

        assert total <= budget - error_policy.WALL_RESERVE_SECONDS
        assert now[0] <= deadline - error_policy.WALL_RESERVE_SECONDS
    finally:
        error_policy.clear_wall_deadline()


def test_vendor_turn_replay_does_not_retry_auth_errors():
    """b. The outer turn replay must not undo the SDK's fail-fast decision."""
    from strix.core import execution

    assert execution._is_transient_model_error(_auth_error(401)) is False
    assert execution._is_transient_model_error(_auth_error(403)) is False


def test_install_replaces_both_strix_bindings():
    """The policy must reach the binding make_model_settings really reads."""
    import strix.config.models as models
    import strix.core.execution as execution
    import strix.core.inputs as inputs

    original_models = models.DEFAULT_MODEL_RETRY
    original_inputs = inputs.DEFAULT_MODEL_RETRY
    original_transient = execution._is_transient_model_error
    was_installed = error_policy._installed
    was_guarded = error_policy._turn_guard_installed
    try:
        assert error_policy.install() is True
        assert models.DEFAULT_MODEL_RETRY is inputs.DEFAULT_MODEL_RETRY
        assert inputs.DEFAULT_MODEL_RETRY.policy is error_policy.retry_policy
        assert inputs.DEFAULT_MODEL_RETRY.max_retries > 5
        assert getattr(execution._is_transient_model_error, "_ctf_wall_aware", False)
    finally:
        # install() is deliberately process-wide for a real run; tests must
        # not leave strix patched for every later test in this interpreter.
        models.DEFAULT_MODEL_RETRY = original_models
        inputs.DEFAULT_MODEL_RETRY = original_inputs
        execution._is_transient_model_error = original_transient
        error_policy._installed = was_installed
        error_policy._turn_guard_installed = was_guarded


def test_turn_replay_guard_stops_only_near_the_wall_clock(monkeypatch):
    """c. The vendored turn replay must not sleep past the shutdown reserve."""
    from openai import InternalServerError
    from strix.core import execution

    request = httpx.Request("POST", "http://gateway.test/v1/chat/completions")
    response = httpx.Response(503, request=request)
    transient = InternalServerError("gateway overloaded", response=response, body=None)

    original = execution._is_transient_model_error
    was_guarded = error_policy._turn_guard_installed
    now = [100.0]
    monkeypatch.setattr(error_policy, "_clock", lambda: now[0])
    try:
        error_policy._turn_guard_installed = False
        error_policy.clear_wall_deadline()
        assert error_policy.install_turn_replay_guard() is True

        # Unbounded: the guard is a pass-through.
        assert execution._is_transient_model_error(transient) is True

        # Plenty of wall clock left: still a pass-through.
        error_policy.set_wall_deadline(now[0] + 600.0)
        assert execution._is_transient_model_error(transient) is True

        # Less than the largest replay sleep plus the reserve: refuse replay.
        error_policy.set_wall_deadline(now[0] + error_policy.WALL_RESERVE_SECONDS + 5.0)
        assert execution._is_transient_model_error(transient) is False
        # Non-transient errors are unchanged either way.
        assert execution._is_transient_model_error(_auth_error(401)) is False
    finally:
        error_policy.clear_wall_deadline()
        execution._is_transient_model_error = original
        error_policy._turn_guard_installed = was_guarded


def test_sdk_loop_survives_a_simulated_five_minute_outage(monkeypatch):
    """a. Drive the real SDK retry loop: success after 300 simulated seconds."""
    from agents.items import ModelResponse
    from agents.usage import Usage
    import agents.run_internal.model_retry as model_retry

    now = [0.0]
    monkeypatch.setattr(error_policy, "_clock", lambda: now[0])

    async def fake_sleep(delay: float) -> None:
        now[0] += delay

    monkeypatch.setattr(model_retry, "_sleep_for_retry", fake_sleep)
    error_policy.clear_wall_deadline()

    calls = [0]

    async def get_response():
        calls[0] += 1
        if now[0] < 300:
            raise _http_error(503)
        return ModelResponse(output=[], usage=Usage(), response_id="resp-1")

    async def rewind() -> None:
        return None

    async def run():
        return await model_retry.get_response_with_retry(
            get_response=get_response,
            rewind=rewind,
            retry_settings=error_policy.build_retry_settings(),
            get_retry_advice=lambda _request: None,
            previous_response_id=None,
            conversation_id=None,
        )

    asyncio.run(run())

    assert now[0] >= 300
    assert calls[0] > 5, "the old 62s ladder would have given up"


def _prepare_main(tmp_path: Path, monkeypatch) -> None:
    task = {
        "run_mode": "instance",
        "challenge": {"id": "X", "name": "x", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [
            {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
        ],
        "result": {"path": str(tmp_path / "result.json")},
    }
    (tmp_path / "task.json").write_text(json.dumps(task), encoding="utf-8")
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)


def test_main_marks_rejected_credentials_in_result_json(tmp_path, monkeypatch):
    """b. A credential failure from _run_agent lands in result.json."""
    from ctf_strix import agent

    _prepare_main(tmp_path, monkeypatch)

    def _rejected(*_args, **_kwargs):
        raise _auth_error(401)

    monkeypatch.setattr(agent, "_run_agent", _rejected)
    try:
        assert agent.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "credential_failure"
        assert payload["llm_errors"][0]["status_code"] == 401
        assert payload["llm_errors"][0]["retryable"] is False
    finally:
        import os

        os.environ.pop("CTFY_SOFT_DEADLINE", None)


def test_main_keeps_credential_failure_when_no_attempt_ran(tmp_path, monkeypatch):
    """b. The normal _run_agent path must not be overwritten by "no_attempt_ran"."""
    from ctf_strix import agent

    _prepare_main(tmp_path, monkeypatch)
    detail = error_policy.credential_failure(_auth_error(403))

    def _rejected(*_args, **_kwargs):
        # _run_agent returns diagnostics; main() is what writes result.json.
        return 0, {"llm_errors": [detail], "no_attempt_ran": True}

    monkeypatch.setattr(agent, "_run_agent", _rejected)
    try:
        assert agent.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "credential_failure"
        assert payload["llm_errors"][0]["status_code"] == 403
        assert "llm_credentials_rejected" in payload["writeup"]
    finally:
        import os

        os.environ.pop("CTFY_SOFT_DEADLINE", None)


def test_main_leaves_non_auth_4xx_as_error(tmp_path, monkeypatch):
    """d. A 400 must not be reported as a credential failure."""
    from ctf_strix import agent

    _prepare_main(tmp_path, monkeypatch)

    def _bad_request(*_args, **_kwargs):
        raise _http_error(400)

    monkeypatch.setattr(agent, "_run_agent", _bad_request)
    try:
        assert agent.main() == 0
        payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
        assert payload["stop_reason"] == "error"
        assert "llm_errors" not in payload
    finally:
        import os

        os.environ.pop("CTFY_SOFT_DEADLINE", None)
