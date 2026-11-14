"""Classify LLM failures and supply the SDK's retry policy.

The retry decision belongs here, not in a transport wrapper, because both
strix routing paths (the SDK-native OpenAI client and LiteLLM) execute
``agents.retry.ModelRetrySettings.policy`` around every model request.  The
policy is injected by replacing the module-level ``DEFAULT_MODEL_RETRY`` that
``strix.core.inputs.make_model_settings`` copies onto each request.  No
vendor file changes are needed.

The policy separates three cases:

* ``401``/``403``: credentials are rejected.  Do not retry, and let the
  entrypoint mark the result as ``credential_failure``.
* ``5xx``/transport failures: back off for minutes, but never past the
  process wall-clock deadline (minus a small shutdown reserve).
* other ``4xx`` (``400``/``404``/...): a bad request, not an outage or a
  credential problem.  Fail the request without inventing retries or
  claiming the key is dead.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Iterator
from typing import Any, Final


#: A rejected key cannot recover inside one run, so it is a distinct class.
AUTH_STATUSES = frozenset({401, 403})

#: Provider error-body codes that mean "this request is malformed", not "the
#: provider is flaky".  DashScope-style backends answer a missing ``max_tokens``
#: with ``InternalError.Algo.InvalidParameter`` and OpenAI-style backends use
#: ``invalid_parameter_error``/``invalid_request_error``.  When such an error
#: arrives as a mid-stream SSE event the SDK raises an ``APIError`` with **no**
#: ``status_code``, so the statusless-provider-error rule below would replay the
#: identical request forever -- the 2026-11-14 gateway smoke burned 837 s on 18
#: replays of one deterministic 400.  These markers say replaying cannot help.
_PERMANENT_REQUEST_MARKERS: Final[frozenset[str]] = frozenset(
    {
        "invalidparameter",
        "invalid_parameter",
        "invalid_request_error",
    }
)


def _is_permanent_request_error(exc: BaseException) -> bool:
    """Statusless provider error whose body marks the request itself as invalid.

    Only applies to statusless errors (``status_code`` missing): errors that
    carry a status already route through the 4xx/5xx branches above, and only
    to provider API errors, so a tool-level exception whose text happens to
    contain a marker is not reclassified.
    """
    if status_code_of(exc) is not None:
        return False
    for candidate in _iter_chain(exc):
        try:
            import openai

            if not isinstance(candidate, openai.APIError):
                continue
        except Exception:  # noqa: BLE001 - optional dependency
            continue
        lowered = str(candidate).lower()
        if any(marker in lowered for marker in _PERMANENT_REQUEST_MARKERS):
            return True
    return False

#: Statuses that mean "the provider is temporarily unavailable" or "back off".
TRANSIENT_STATUSES = frozenset(
    {
        408,
        409,
        425,
        429,
        500,
        502,
        503,
        504,
        520,
        521,
        522,
        523,
        524,
        529,
    }
)

#: Long enough to cross the observed 5+ minute gateway outage, while staying
#: finite.  The wall-clock clamp is the real upper bound.
MAX_RETRIES = 20
BASE_DELAY_SECONDS = 4.0
MAX_DELAY_SECONDS = 60.0

#: Leave this much wall clock for writing ``result.json`` and tearing down.
WALL_RESERVE_SECONDS = 20.0

#: Transport failures in a row, and how long that streak may last, before the
#: policy stops retrying.  Sized from the 2026-11-14 outage: one failed request
#: against a black-holed endpoint took 40-120 s, so two failures plus the
#: 45 s window open the breaker after roughly 1.5-2 minutes -- instead of the
#: 22 minutes two retry ladders spent grinding a dead host.
NETWORK_BREAKER_MIN_FAILURES = 2
NETWORK_BREAKER_SECONDS = 45.0

#: Fallback for the full turn-replay ladder (2+4+8+16+32).  The real value is
#: read from the vendored module so a ladder change cannot silently drift.
TURN_REPLAY_TOTAL_FALLBACK_SECONDS = 62.0

_AUTH_CLASS_NAMES = frozenset(
    {"AuthenticationError", "PermissionDeniedError", "PermissionDenied"}
)
_NETWORK_CLASS_NAMES = frozenset(
    {
        "APIConnectionError",
        "APITimeoutError",
        "ConnectError",
        "ReadError",
        "WriteError",
        "RemoteProtocolError",
        "TimeoutException",
        "ProxyError",
        "NetworkError",
    }
)

#: Transport failures that mean *nothing answered*.  Timeouts are deliberately
#: absent: a slow provider is what the retry ladders are for, and a 300 s
#: ``LLM_TIMEOUT`` twice in a row must not read as "the host is gone".
_CONNECT_CLASS_NAMES = frozenset(
    {
        "APIConnectionError",
        "ConnectError",
        "ReadError",
        "WriteError",
        "RemoteProtocolError",
        "ProxyError",
        "NetworkError",
    }
)
_TIMEOUT_CLASS_NAMES = frozenset(
    {"APITimeoutError", "TimeoutException", "ConnectTimeout", "ReadTimeout", "WriteTimeout"}
)

_installed = False
_turn_guard_installed = False
_deadline: float | None = None

#: Indirection so tests can drive the clock without sleeping.
_clock = time.monotonic

#: Transport-failure breaker state (see :func:`note_network_failure`).
_net_streak_started: float | None = None
_net_streak_count = 0
#: Set when the retry policy actually gave up on an unreachable endpoint.
#: ``main()`` consumes it to label that run; nothing else may read it, because
#: "the breaker once opened" is not evidence about *this* exception.
_unreachable_pending = False


def note_model_ok() -> None:
    """Clear the transport-failure streak after a request the provider served.

    Called from :mod:`ctf_strix.llm_telemetry` on every completed response, so
    a single dropped connection followed by healthy traffic never accumulates
    toward the breaker.
    """
    global _net_streak_started, _net_streak_count  # noqa: PLW0603 - process state
    _net_streak_started = None
    _net_streak_count = 0


def note_network_failure(now: float | None = None) -> bool:
    """Record one transport failure and report whether the breaker is open.

    A streak opens the breaker once it has lasted
    :data:`NETWORK_BREAKER_SECONDS` **and** counts at least
    :data:`NETWORK_BREAKER_MIN_FAILURES` requests.  The window matters as much
    as the count: successive requests against a dead host are expensive, while
    a burst of fast failures minutes apart is a normal flaky provider.

    Args:
        now: Injected clock for tests; defaults to the policy clock.

    Returns:
        ``True`` when the run should stop retrying the endpoint.
    """
    global _net_streak_started, _net_streak_count  # noqa: PLW0603 - process state
    moment = _clock() if now is None else float(now)
    if _net_streak_started is None:
        _net_streak_started = moment
    _net_streak_count += 1
    return breaker_open(moment)


def breaker_open(now: float | None = None) -> bool:
    """Whether the transport-failure streak has tripped the breaker."""
    if _net_streak_started is None:
        return False
    if _net_streak_count < NETWORK_BREAKER_MIN_FAILURES:
        return False
    moment = _clock() if now is None else float(now)
    return (moment - _net_streak_started) >= NETWORK_BREAKER_SECONDS


def note_unreachable() -> None:
    """Record that the retry policy abandoned the endpoint (consume-once)."""
    global _unreachable_pending  # noqa: PLW0603 - process state
    _unreachable_pending = True


def take_unreachable() -> bool:
    """Consume the "gave up on an unreachable endpoint" evidence."""
    global _unreachable_pending  # noqa: PLW0603 - process state
    seen, _unreachable_pending = _unreachable_pending, False
    return seen


def reset_breaker() -> None:
    """Forget breaker state; ``main()`` calls this so runs cannot inherit it."""
    note_model_ok()
    take_unreachable()


def set_wall_deadline(deadline_monotonic: float | None) -> None:
    """Set the absolute ``monotonic()`` deadline for this run.

    ``None`` means no known wall-clock bound; retries are then bounded only by
    :data:`MAX_RETRIES`.
    """
    global _deadline  # noqa: PLW0603 - process-wide run state
    _deadline = deadline_monotonic


def clear_wall_deadline() -> None:
    """Forget the run deadline (used between ``main()`` invocations/tests)."""
    set_wall_deadline(None)


def remaining_wall() -> float | None:
    """Seconds left before the wall-clock deadline, or ``None`` if unbounded."""
    if _deadline is None:
        return None
    return max(_deadline - _clock(), 0.0)


def backoff_delay(attempt: int) -> float:
    """Exponential delay for retry number ``attempt`` (1-based)."""
    exponent = max(attempt - 1, 0)
    if exponent > 20:  # avoid an overflow; the wall clamp stops long before this
        return MAX_DELAY_SECONDS
    return min(BASE_DELAY_SECONDS * (2.0**exponent), MAX_DELAY_SECONDS)


def _iter_chain(exc: BaseException | None) -> Iterator[BaseException]:
    """Yield ``exc`` and its causes/context, de-duplicating cycles."""
    seen: set[int] = set()
    stack: list[BaseException] = [exc] if exc is not None else []
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        for attr in ("__cause__", "__context__", "original_exception", "inner_exception"):
            nested = getattr(current, attr, None)
            if isinstance(nested, BaseException):
                stack.append(nested)


def _int_status(value: object) -> int | None:
    """Coerce a retry-normalized status code without accepting booleans."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def status_code_of(exc: BaseException | None) -> int | None:
    """Best-effort HTTP status from an OpenAI/LiteLLM/httpx exception chain."""
    for candidate in _iter_chain(exc):
        value = _int_status(getattr(candidate, "status_code", None))
        if value is not None:
            return value
        response = getattr(candidate, "response", None)
        value = _int_status(getattr(response, "status_code", None))
        if value is not None:
            return value
        value = _int_status(getattr(candidate, "status", None))
        if value is not None:
            return value
    return None


def is_network_error(exc: BaseException | None) -> bool:
    """Whether ``exc`` is a transport failure rather than an HTTP reply."""
    for candidate in _iter_chain(exc):
        if isinstance(candidate, TimeoutError | ConnectionError):
            return True
        try:
            import httpx

            if isinstance(candidate, httpx.TransportError):
                return True
        except Exception:  # noqa: BLE001 - optional dependency
            pass
        try:
            import openai

            if isinstance(candidate, openai.APIConnectionError | openai.APITimeoutError):
                return True
        except Exception:  # noqa: BLE001 - optional dependency
            pass
        if type(candidate).__name__ in _NETWORK_CLASS_NAMES:
            return True
    return False


def is_connect_error(exc: BaseException | None) -> bool:
    """Whether ``exc`` says nothing answered (a timeout does not count).

    The retry ladders and the breaker want different questions answered:
    "should I wait?" (any transport failure) versus "is this host gone?"
    (only refused/reset/unresolvable connections).
    """
    for candidate in _iter_chain(exc):
        name = type(candidate).__name__
        if isinstance(candidate, TimeoutError) or name in _TIMEOUT_CLASS_NAMES:
            continue
        if isinstance(candidate, ConnectionError):
            return True
        try:
            import httpx

            if isinstance(candidate, httpx.TimeoutException):
                continue
            if isinstance(candidate, httpx.TransportError):
                return True
        except Exception:  # noqa: BLE001 - optional dependency
            pass
        try:
            import openai

            # ``APITimeoutError`` subclasses ``APIConnectionError``: ask first.
            if isinstance(candidate, openai.APITimeoutError):
                continue
            if isinstance(candidate, openai.APIConnectionError):
                return True
        except Exception:  # noqa: BLE001 - optional dependency
            pass
        if name in _CONNECT_CLASS_NAMES:
            return True
    return False


def _is_statusless_provider_error(exc: BaseException) -> bool:
    """Provider errors with no status are the SDK's existing transient class."""
    for candidate in _iter_chain(exc):
        try:
            import openai

            if isinstance(candidate, openai.APIError):
                return True
        except Exception:  # noqa: BLE001 - optional dependency
            pass
        module = type(candidate).__module__
        name = type(candidate).__name__
        if module.startswith("litellm") and "Error" in name:
            return True
    return False


def _is_auth_class(exc: BaseException) -> bool:
    return any(type(candidate).__name__ in _AUTH_CLASS_NAMES for candidate in _iter_chain(exc))


def classify_error(
    exc: BaseException,
    *,
    status_code: int | None = None,
    is_network: bool | None = None,
    is_timeout: bool | None = None,
) -> str:
    """Return ``credential_failure``, ``client_error``, ``transient`` or ``fatal``.

    ``status_code``/``is_network``/``is_timeout`` let callers reuse the SDK's
    already-normalized error facts; omitted values are derived from the
    exception chain.
    """
    status = status_code if status_code is not None else status_code_of(exc)
    if status in AUTH_STATUSES or (status is None and _is_auth_class(exc)):
        return "credential_failure"

    network = is_network if is_network is not None else is_network_error(exc)
    timeout = is_timeout if is_timeout is not None else any(
        isinstance(candidate, TimeoutError) for candidate in _iter_chain(exc)
    )
    if status is not None and 400 <= status < 500:
        return "transient" if status in TRANSIENT_STATUSES else "client_error"
    if status is not None and status >= 500:
        return "transient"
    if network or timeout:
        return "transient"
    if status is None and _is_permanent_request_error(exc):
        return "client_error"
    if status is None and _is_statusless_provider_error(exc):
        return "transient"
    return "fatal"


def credential_failure(exc: BaseException) -> dict[str, Any] | None:
    """Structured ``result.json`` annotation for a rejected credential.

    Returns ``None`` for every non-auth failure, including ``400``/``404``.
    """
    status = status_code_of(exc)
    if status not in AUTH_STATUSES and not (status is None and _is_auth_class(exc)):
        return None
    message = str(exc).strip() or type(exc).__name__
    return {
        "reason": "llm_credentials_rejected",
        "status_code": status,
        "error_type": type(exc).__name__,
        "message": message[:500],
        "retryable": False,
    }


def retry_policy(context: Any) -> Any:
    """SDK retry policy: long transient backoff, immediate credential stop."""
    from agents.retry import RetryDecision

    normalized = context.normalized
    status = (
        normalized.status_code
        if normalized.status_code is not None
        else status_code_of(context.error)
    )
    # The SDK's normalized flags catch transports our class-name scan cannot
    # see (for example a websockets ConnectionClosed); the exception chain
    # catches adapters that leave those flags empty.  Use both.
    kind = classify_error(
        context.error,
        status_code=status,
        is_network=normalized.is_network_error or None,
        is_timeout=normalized.is_timeout or None,
    )
    if normalized.is_abort:
        return RetryDecision(retry=False, reason="aborted")
    if kind in {"credential_failure", "client_error", "fatal"}:
        return RetryDecision(retry=False, reason=kind)

    # A transport failure that keeps repeating is an unreachable endpoint, not
    # a slow provider: further attempts only spend the wall clock.  This check
    # sits before the retry counter so the breaker wins over a large budget.
    # Only *connect-class* failures count: ``LLM_TIMEOUT`` is 300 s, and two of
    # those against a merely busy provider must not read as "the host is gone".
    if kind == "transient" and is_connect_error(context.error) and note_network_failure():
        note_unreachable()
        return RetryDecision(retry=False, reason="endpoint_unreachable")

    if context.attempt > context.max_retries:
        return RetryDecision(retry=False, reason="max_retries")

    delay = backoff_delay(context.attempt)
    retry_after = normalized.retry_after
    if retry_after is not None and retry_after > 0:
        delay = max(delay, retry_after)

    remaining = remaining_wall()
    if remaining is not None:
        usable = remaining - WALL_RESERVE_SECONDS
        if usable <= 0:
            return RetryDecision(retry=False, reason="wallclock_reserve")
        # Every retry consumes the remaining budget, so the sum of all delays
        # can never exceed the wall clock that was available on entry.
        delay = min(delay, usable)

    return RetryDecision(retry=True, delay=delay, reason=kind)


def build_retry_settings() -> Any:
    """Build the ``ModelRetrySettings`` strix applies to model requests."""
    from agents.retry import ModelRetryBackoffSettings, ModelRetrySettings

    return ModelRetrySettings(
        max_retries=MAX_RETRIES,
        backoff=ModelRetryBackoffSettings(
            initial_delay=BASE_DELAY_SECONDS,
            max_delay=MAX_DELAY_SECONDS,
            multiplier=2.0,
            jitter=False,
        ),
        policy=retry_policy,
    )


def _turn_replay_total_delay(execution_module: Any) -> float:
    """Total sleep in the vendored turn-replay ladder (currently 2+4+8+16+32)."""
    try:
        retries = int(getattr(execution_module, "_MAX_TRANSIENT_MODEL_RETRIES", 5))
        base = float(getattr(execution_module, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 2.0))
        cap = float(getattr(execution_module, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 90.0))
    except (TypeError, ValueError):
        return TURN_REPLAY_TOTAL_FALLBACK_SECONDS
    if retries <= 0 or base <= 0 or cap <= 0:
        return TURN_REPLAY_TOTAL_FALLBACK_SECONDS
    delays = (min(base * (2.0 ** (attempt - 1)), cap) for attempt in range(1, retries + 1))
    return sum(delays)


def install_turn_replay_guard() -> bool:
    """Make strix's turn-level replay wall-aware, without editing vendor code.

    ``strix.core.execution._is_transient_model_error`` drives a second retry
    ladder (2/4/8/16/32s) after the SDK policy gives up.  That ladder is not
    clamped, so near the deadline it could sleep past the reserve we keep for
    writing ``result.json``.  Wrap it: keep its classification exactly as-is,
    but refuse a replay unless the whole ladder plus the reserve still fits in
    the remaining wall clock.

    The guard only narrows behaviour when a wall deadline is set and nearly
    spent; with an unbounded run it is a pure pass-through.

    Returns:
        ``True`` when the shim was installed (or already present), ``False``
        when the vendored module does not expose the expected hook.
    """
    global _turn_guard_installed  # noqa: PLW0603 - process-wide run state
    if _turn_guard_installed:
        return True
    try:
        from strix.core import execution
    except Exception:  # noqa: BLE001 - a missing runtime keeps stock behaviour
        return False

    original = getattr(execution, "_is_transient_model_error", None)
    if not callable(original):
        return False
    if getattr(original, "_ctf_wall_aware", False):
        _turn_guard_installed = True
        return True

    # Refuse a replay unless the full vendored ladder plus the shutdown
    # reserve still fits; the sum (not one sleep) is what must be bounded.
    threshold = WALL_RESERVE_SECONDS + _turn_replay_total_delay(execution)

    def wall_aware(exc: BaseException) -> bool:
        # An open breaker means the endpoint is unreachable, not flaky: the
        # 2/4/8/16/32 s replay ladder would only repeat the same failure.
        if breaker_open():
            return False
        # A malformed request (e.g. the gateway's missing-``max_tokens`` 400
        # raised as a statusless mid-stream APIError) is deterministic: replay
        # burns the wall clock without ever changing the answer.
        if _is_permanent_request_error(exc):
            return False
        remaining = remaining_wall()
        if remaining is not None and remaining <= threshold:
            return False
        return bool(original(exc))

    wall_aware._ctf_wall_aware = True  # type: ignore[attr-defined]
    wall_aware.__wrapped__ = original  # type: ignore[attr-defined]
    execution._is_transient_model_error = wall_aware  # type: ignore[attr-defined]
    _turn_guard_installed = True
    return True


def install() -> bool:
    """Patch strix's module-level retry defaults (idempotent).

    ``strix.core.inputs`` imports ``DEFAULT_MODEL_RETRY`` by value at module
    import time, so patching only ``strix.config.models`` would not reach
    ``make_model_settings``.  Patch both bindings.

    Returns:
        ``True`` when both bindings were replaced, ``False`` when strix is not
        importable (the caller then keeps strix's stock retry behaviour).
    """
    global _installed  # noqa: PLW0603 - process-wide installation flag
    if _installed:
        # The retry bindings are already ours, but a module reload in an
        # embedded caller could have restored the vendored replay hook.
        install_turn_replay_guard()
        _install_success_hook()
        return True
    try:
        settings = build_retry_settings()
        import strix.config.models as models
        import strix.core.inputs as inputs
    except Exception as exc:  # noqa: BLE001 - a missing runtime must not break the run
        print(
            f"[ctfy] LLM error policy not installed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return False

    models.DEFAULT_MODEL_RETRY = settings
    inputs.DEFAULT_MODEL_RETRY = settings
    _installed = True
    install_turn_replay_guard()
    _install_success_hook()
    return True


def _install_success_hook() -> bool:
    """Clear the transport streak from the SDK hook, not from telemetry.

    The streak's "+" lives on the retry path, which is always installed; its
    "-" must not depend on an optional sink.  ``llm_telemetry`` also clears it,
    but that module is wrapped by ``usage_meter`` and its failure is only a
    warning -- a run with telemetry off would count failures forever.
    """
    try:
        from strix.core import hooks as strix_hooks
    except Exception:  # noqa: BLE001 - a missing runtime is not our problem
        return False
    original = getattr(strix_hooks.ReportUsageHooks, "on_llm_end", None)
    if not callable(original) or getattr(original, "_ctf_streak_cleared", False):
        return callable(original)

    async def on_llm_end(self: Any, context: Any, agent: Any, response: Any, *args: Any, **kwargs: Any) -> Any:
        note_model_ok()
        return await original(self, context, agent, response, *args, **kwargs)

    on_llm_end._ctf_streak_cleared = True  # type: ignore[attr-defined]
    strix_hooks.ReportUsageHooks.on_llm_end = on_llm_end  # type: ignore[method-assign]
    return True
