"""Startup reachability probe for the model endpoint.

Why this module exists (2026-11-14, TPCTF Agent Track).  Three web lanes
were relaunched at 07:12Z against an endpoint the box could no longer
reach.  Every model request failed with ``APIConnectionError``; the SDK
ladder and the vendored turn replay then spent 20 minutes per run on
backoff, and the wall-clock watchdog killed a process that had produced no
transcript and -- because the harness armed the watchdog with
``result_path=None`` -- no ``result.json`` either.  Three runs, roughly 66
minutes, zero model calls.

This module supplies the first two of three cheap defences:

* :func:`describe` renders one attribution line, so the log says which
  model and host a run actually talked to.  The API key never appears.
* :func:`probe` performs one tiny completion before the run starts, so a
  dead endpoint costs seconds instead of the whole budget.

The mid-run equivalent -- an endpoint that dies after a good start -- is
the consecutive-failure breaker in :mod:`ctf_strix.error_policy`
(:func:`~ctf_strix.error_policy.note_model_ok` clears it; the retry
policy opens it).

The probe is deliberately conservative: it never blocks a run for reasons
that are not provably fatal.  A missing ``httpx``, an unconfigured
endpoint, an explicit opt-out, or a non-OpenAI provider (whose wire
dialect this probe cannot speak) all return ``ok=True``.  ``429`` counts
as reachable -- the endpoint answered, and the run's own retry policy
owns rate limiting from there.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from ctf_strix.platform_env import KEY_ENV_NAMES

#: Set to ``0``/``false`` to disable the probe, ``1``/``true`` to force it on
#: where it would otherwise be off.  Unset means "probe whenever an endpoint is
#: configured".  The suite does not rely on ``PYTEST_CURRENT_TEST``: pytest
#: exports that variable into every subprocess, so a smoke test that really
#: starts an agent -- or the image build's own pytest step -- would silently
#: run without the guard.  ``tests/conftest.py`` sets this variable instead.
ENV_DISABLE = "CTF_LLM_PREFLIGHT"

#: Process exit code when the probe refuses the run.  Distinct from the
#: agent's own 0 (ran) so an outer harness can tell "never started" from
#: "started and solved nothing" without parsing prose.  Must stay in sync
#: with ``batch_eval._stop_reason_of``, which folds it into the
#: ``llm_unreachable`` stop reason.
EXIT_CODE = 3

#: Seconds for one probe request.  Long enough for a slow provider TLS
#: handshake, short enough that a black-holed endpoint costs a rounding
#: error against a 900-1800 s budget.
DEFAULT_TIMEOUT = 12.0

#: Attempts per probe.  Two covers a single dropped SYN without turning a
#: dead host into a 30 s startup penalty.
DEFAULT_ATTEMPTS = 2

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}

#: Statuses that prove the endpoint is reachable and worth running against.
_REACHABLE_STATUSES = {429}

#: Providers whose wire dialect :func:`probe` knows how to speak.  Anything
#: else is passed through unprobed -- see the gate in :func:`probe`.
_PROBED_PROVIDERS = {"openai"}


@dataclass(frozen=True)
class Endpoint:
    """What the run will talk to, with the credential left out."""

    model: str
    model_id: str
    provider: str
    base: str
    host: str
    key_present: bool


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one reachability probe.

    ``kind`` is what the caller acts on when ``ok`` is false -- "the host is
    not there" and "the key is dead" need different responses, and only the
    first one is worth re-dispatching to a different endpoint.
    """

    ok: bool
    reason: str
    kind: str = "ok"
    detail: str = ""
    status: int | None = None
    elapsed_ms: int = 0
    endpoint: Endpoint | None = None

    def as_dict(self) -> dict[str, Any]:
        """JSON-safe summary for ``result.json`` diagnostics (no secret)."""
        payload: dict[str, Any] = {
            "ok": self.ok,
            "reason": self.reason,
            "kind": self.kind,
            "elapsed_ms": self.elapsed_ms,
        }
        if self.status is not None:
            payload["status"] = self.status
        if self.detail:
            payload["detail"] = self.detail[:300]
        if self.endpoint is not None:
            payload["model"] = self.endpoint.model
            payload["host"] = self.endpoint.host
        return payload

    def summary(self) -> str:
        """One human-readable line for the run log."""
        where = "unconfigured"
        if self.endpoint is not None:
            where = f"{self.endpoint.model} @ {self.endpoint.host}"
        text = f"llm endpoint unreachable ({where}): {self.reason}"
        if self.detail:
            text = f"{text} - {self.detail[:160]}"
        return text


class LlmUnreachable(RuntimeError):
    """The preflight proved the endpoint cannot serve this run.

    ``kind`` mirrors :attr:`ProbeResult.kind` so the caller can tell "the host
    is not there" (worth re-dispatching elsewhere) from "the credential is
    dead" and "the path is wrong" (re-dispatching changes nothing).
    """

    def __init__(self, message: str, kind: str = "unreachable") -> None:
        super().__init__(message)
        self.kind = kind


def enabled(env: Mapping[str, str] | None = None) -> bool:
    """Whether :func:`probe` should run at all.

    Args:
        env: Environment mapping; defaults to ``os.environ``.

    Returns:
        ``False`` for an explicit opt-out or an unconfigured endpoint.
    """
    env = os.environ if env is None else env
    flag = (env.get(ENV_DISABLE) or "").strip().lower()
    if flag in _FALSY:
        return False
    return describe(env) is not None


def _first_env(env: Mapping[str, str], names: tuple[str, ...]) -> str:
    """First non-empty value among ``names`` (empty string counts as unset)."""
    for name in names:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return ""


def describe(env: Mapping[str, str] | None = None) -> Endpoint | None:
    """Describe the configured endpoint, or ``None`` when none is set.

    Reads the same variables strix does after
    :func:`ctf_strix.platform_env.normalise` bridged the platform's names.
    The key names come from :data:`ctf_strix.platform_env.KEY_ENV_NAMES` so
    "no key" can never disagree with "key bridged": an anthropic-flavoured
    run carrying only ``ANTHROPIC_AUTH_TOKEN`` used to be refused as
    ``no_key`` although the bridge accepts it (2026-11-14 Codex review N4).
    """
    env = os.environ if env is None else env
    base = (env.get("LLM_API_BASE") or env.get("OPENAI_API_BASE") or "").strip()
    model = (env.get("STRIX_LLM") or "").strip()
    key = _first_env(env, KEY_ENV_NAMES)
    if not base or not model:
        return None
    provider, sep, tail = model.partition("/")
    model_id = tail if sep and tail else model
    if not sep:
        provider = "openai"
    host = urlsplit(base).hostname or base
    return Endpoint(
        model=model,
        model_id=model_id,
        provider=provider,
        base=base,
        host=host,
        key_present=bool(key),
    )


def _chat_url(base: str) -> str:
    """``.../v1`` -> ``.../v1/chat/completions`` (already-suffixed stays put)."""
    trimmed = base.rstrip("/")
    if trimmed.endswith("/chat/completions"):
        return trimmed
    return f"{trimmed}/chat/completions"


def _dns_failure(exc: BaseException) -> bool:
    """Whether the exception chain contains a name-resolution failure."""
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, socket.gaierror):
            return True
        text = str(current).lower()
        if "name or service not known" in text or "nodename nor servname" in text:
            return True
        for attr in ("__cause__", "__context__", "original_exception"):
            nested = getattr(current, attr, None)
            if isinstance(nested, BaseException):
                stack.append(nested)
    return False


def _classify_exception(exc: BaseException) -> tuple[str, int | None]:
    """Map a transport exception to ``(reason, status_code)``."""
    from ctf_strix import error_policy

    status = error_policy.status_code_of(exc)
    if status is not None:
        return f"http_{status}", status
    if _dns_failure(exc):
        return "dns", None
    if isinstance(exc, TimeoutError) or type(exc).__name__ in {"APITimeoutError", "Timeout", "ReadTimeout", "ConnectTimeout"}:
        return "timeout", None
    if error_policy.is_network_error(exc):
        return "connect", None
    return "error", None


#: Anything shaped like a credential in a provider's error body.  Vendor
#: keys use ``sk-``; the competition gateway's per-session credentials use
#: ``pk_`` (v1.0 参赛接口文档), and both shapes get echoed back on auth
#: failures -- the regex is the backstop when the exact key is not known
#: to the caller.
_SECRET_RE = re.compile(r"(?:sk-|pk_)[A-Za-z0-9_\-]{8,}")


def _redact(text: str, key: str = "") -> str:
    """Strip credentials out of a provider error body before it is logged.

    Providers echo the key back on an auth failure (``Incorrect API key
    provided: sk-...``), and ``detail`` lands in ``result.json``.
    """
    cleaned = _SECRET_RE.sub("***", text or "")
    if key and key in cleaned:
        cleaned = cleaned.replace(key, "***")
    return cleaned


def _verdict_for_status(status: int) -> tuple[bool, str, str]:
    """Map an HTTP status from the probe to ``(ok, reason, kind)``.

    The question is "can this endpoint serve a run", not "is this reply
    ideal": a 5xx means it answered and is overloaded, which the run's own
    retry ladders handle (a rolling gateway deploy lasts about a minute).
    Only a dead credential or a wrong path is worth refusing the run over.
    """
    if 200 <= status < 300:
        return True, "ok", "ok"
    if status in _REACHABLE_STATUSES:
        return True, f"http_{status}", "ok"
    if status in (401, 403):
        return False, f"http_{status}", "credential"
    if status in (404, 405):
        return False, f"http_{status}", "misconfigured"
    if 500 <= status < 600:
        return True, f"http_{status}", "overloaded"
    return True, f"http_{status}", "answered"


def _looks_like_completion(body: str) -> bool:
    """Whether a 2xx body is JSON carrying an OpenAI-shaped payload."""
    try:
        payload = json.loads(body or "")
    except (TypeError, ValueError):
        return False
    if not isinstance(payload, dict):
        return False
    return "choices" in payload or "id" in payload or "object" in payload


def _post(endpoint: Endpoint, key: str, timeout: float) -> tuple[int, str]:
    """One minimal completion; returns ``(status, body_snippet)``."""
    import httpx

    payload = {
        "model": endpoint.model_id,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "temperature": 0,
        "stream": False,
    }
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.post(_chat_url(endpoint.base), json=payload, headers=headers)
        body = ""
        try:
            body = (response.text or "").strip()
        except Exception:  # noqa: BLE001 - body is diagnostic only
            body = ""
        return int(response.status_code), body


def guard(env: Mapping[str, str] | None = None) -> ProbeResult:
    """Probe when :func:`enabled`, otherwise return a pass-through verdict.

    Callers use this instead of :func:`probe` so a unit test never opens a
    socket and an explicit opt-out stays cheap.
    """
    if not enabled(env):
        return ProbeResult(ok=True, reason="disabled")
    return probe(env=env)


def probe(
    endpoint: Endpoint | None = None,
    *,
    timeout: float | None = None,
    attempts: int | None = None,
    env: Mapping[str, str] | None = None,
) -> ProbeResult:
    """Ask the configured endpoint for one token.

    Args:
        endpoint: Endpoint to probe; derived from ``env`` when omitted.
        timeout: Per-attempt timeout in seconds.
        attempts: Number of attempts before giving up.
        env: Environment mapping used for the endpoint and the key.

    Returns:
        A :class:`ProbeResult`.  ``ok=False`` only when the endpoint
        provably cannot serve the run.
    """
    env = os.environ if env is None else env
    ep = endpoint if endpoint is not None else describe(env)
    if ep is None:
        return ProbeResult(ok=True, reason="not_configured")
    if not ep.key_present:
        # A missing key is the platform's normal "no model configured" state
        # (CTFY-0001 allows an empty LLM_API_KEY), not an unreachable host.
        return ProbeResult(ok=False, reason="no_key", kind="credential", endpoint=ep)
    # Only the OpenAI chat-completions dialect is probed.  An anthropic/ gemini/
    # model answers 404 or 405 on ``/chat/completions`` while being perfectly
    # healthy, so probing it would refuse a run that would have worked.  A
    # false "unreachable" is far worse than a missed detection.
    if ep.provider not in _PROBED_PROVIDERS:
        return ProbeResult(ok=True, reason="provider_unprobed", endpoint=ep)

    try:
        import httpx  # noqa: F401 - presence check only
    except Exception:  # noqa: BLE001 - optional at import time
        return ProbeResult(ok=True, reason="no_httpx", endpoint=ep)

    key = _first_env(env, KEY_ENV_NAMES)
    budget = float(DEFAULT_TIMEOUT if timeout is None else timeout)
    tries = max(int(DEFAULT_ATTEMPTS if attempts is None else attempts), 1)

    started = time.monotonic()
    reason = "error"
    kind = "unreachable"
    detail = ""
    status: int | None = None
    for attempt in range(1, tries + 1):
        try:
            status, body = _post(ep, key, budget)
        except BaseException as exc:  # noqa: BLE001 - every failure becomes a verdict
            reason, status = _classify_exception(exc)
            detail = _redact(str(exc).strip() or type(exc).__name__, key)
            # A timeout says "slow", not "gone": a provider queueing under
            # load can take 15-20 s to the first byte while a real run with a
            # 300 s timeout would have been fine.  Only a refusal or a
            # resolution failure refuses the run.
            if reason == "timeout":
                return ProbeResult(
                    ok=True,
                    reason="timeout_unproven",
                    kind="timeout_unproven",
                    detail=detail,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    endpoint=ep,
                )
            kind = "unreachable" if reason in {"connect", "dns"} else "misconfigured"
            # Retry only a *cheap* blow-over.  ``timeout=12`` does not cover
            # name resolution: with a dead resolver one DNS attempt blocks
            # ~40 s (measured 2026-11-14 on the contest box, both providers),
            # so a second one buys the same answer for another 40 s.
            cheap = (time.monotonic() - started) < budget
            if attempt < tries and cheap and reason in {"connect", "timeout", "dns"}:
                time.sleep(1.0)
                continue
            break
        ok, reason, kind = _verdict_for_status(status)
        detail = _redact(body, key)
        if ok and 200 <= status < 300 and not _looks_like_completion(detail):
            # An ISP portal or a hijacking proxy answers 200 with HTML.  The
            # endpoint is up but the run will fail differently -- pass it
            # through and leave a trace instead of guessing.
            reason = "http_2xx_nonjson"
        if ok:
            return ProbeResult(
                ok=True,
                reason=reason,
                kind=kind,
                detail=detail,
                status=status,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                endpoint=ep,
            )
        break

    return ProbeResult(
        ok=False,
        reason=reason,
        kind=kind,
        detail=detail,
        status=status,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        endpoint=ep,
    )