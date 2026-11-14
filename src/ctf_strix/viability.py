"""Viability probe: three mechanism-class ladders in one call, three verdicts.

Why this module exists
----------------------
The measured failure is not a budget problem.  On 2026-11-14 the failed runs
sat at p50 37 model turns against a 40-turn budget, with a median of 551s
against a 60-70s success time: the agent kept generating *new names for one
mechanism* and never found out that the mechanism itself was dead.  Telling a
model "remember to try all spellings" has decayed at least three times in this
repo (007 enumeration, 009 method sweep, 095 variants); the fix that survived
was to make the whole family one call.

``path_variants`` answers "does this one path answer under another spelling".
``viability_probe`` answers the question one level up: *is this whole class of
attack worth another turn?*  It runs three fixed ladders over the traffic the
run has already collected and returns one line each:

* ``reflection_canary``  -- does any input surface echo a unique nonce back,
  and does it echo it in a way that can break out of its context?
* ``auth_variant_split`` -- does a 401/403 path answer differently under the
  spelling variants a string-matching gate would miss?
* ``reference_enum``     -- does an identifier the target handed us have
  neighbours that answer?

Every verdict is decidable from the responses this call itself recorded:
``dead`` means "all N probes came back identical", never "I did not find it".
The model therefore does not have to reason between two calls -- one call, one
table, and ``dead`` is a fact it can act on.

Scope discipline
----------------
The budget is part of the capability, not a knob: at most 40 requests and 90s
per call, internal ``(method, url, body)`` de-duplication, and no cross-call
cache (a measured run showed the ledger's coverage was too thin for a cache to
pay).  Output is a fixed-width table capped at 1600 chars; response bodies are
never returned, only the evidence that decides the verdict.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3

from ctf_strix import traffic
from ctf_strix.http_probe import session_cookies
from ctf_strix.variants import _variant_paths

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#: Hard scope caps.  These are the ladder upper bounds added up, not tunables:
#: 20 surfaces + 14 variants + 10 reference probes = 44, so the 40-request cap
#: is the one that actually binds on a rich page.  A probe must stay cheaper
#: than the 60-70s a successful solve takes.
_MAX_REQUESTS: Final = 40
_MAX_WALL: Final = 90.0
_MAX_OUT: Final = 1600
#: Per-request timeout.  A slow variant belongs to ``http_probe`` with its own
#: longer budget; here a slow endpoint must not eat the whole ladder.
_REQ_TIMEOUT: Final = 8.0
#: Bodies are read only to compare lengths and look for one nonce; 32 KB is
#: several times the largest page a CTFytarget serves and keeps memory flat.
_BODY_KEEP: Final = 32 * 1024

#: Per-ladder request ceilings.  Sum is below ``_MAX_REQUESTS`` on purpose so a
#: later ladder always gets a few requests even when the earlier ones run full.
_L1_SURFACES: Final = 20
_L2_PATHS: Final = 2
_L2_KINDS: Final = ("upper", "title", "pct", "dot", "semi", "slash", "query")
_L3_IDS: Final = 2
_L3_SPAN: Final = 2
#: A baseline shorter than this is not a page; comparing neighbours to a
#: 1-byte body turns every response into a false `hit`.
_MIN_BASE_LEN: Final = 8

_LADDER_ORDER: Final = ("reflection_canary", "auth_variant_split", "reference_enum")

#: Characters that make a reflected value dangerous *if they survive intact*.
#: The alphanumeric nonce proves the surface is an echo; these prove the echo
#: is not escaped into a safe context.
_PROBE_TAIL: Final = "'\"<>"
#: How each of those characters looks once the sink encoded it.  Any of these
#: next to the nonce is ``transformed`` -- the spec's "echoed but escaped".
_ENC_MARKS: Final = (
    "&#39;", "&#x27;", "&quot;", "&lt;", "&gt;", "&#60;", "&#62;",
    "%27", "%22", "%3C", "%3E", "%3c", "%3e",
    "\\u0027", "\\u003c", "\\x27", "\\x3c",
)

_INPUT_NAME = re.compile(r"\bname\s*=\s*[\"']([^\"']{1,40})[\"']", re.IGNORECASE)
_FORM_ACTION = re.compile(r"\baction\s*=\s*[\"']([^\"']{0,200})[\"']", re.IGNORECASE)
_FORM_METHOD = re.compile(r"\bmethod\s*=\s*[\"']?(get|post)", re.IGNORECASE)
_LOGIN_MARK = re.compile(r"login|sign[\s_-]?in|password|passwd", re.IGNORECASE)
_TAIL_HEX = re.compile(r"([0-9a-fA-F]{2,})$")
_ERROR_MARK = re.compile(
    r"\b(not found|404|no such|does not exist|invalid id|unknown id|"
    r"forbidden|unauthorized|access denied)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Verdict:
    """One ladder's outcome, already shaped for the fixed-width table."""

    name: str
    state: str
    evidence: str


@dataclass
class _Budget:
    """Request counter, wall clock, and within-call de-duplication."""

    started: float = field(default_factory=time.monotonic)
    requests: int = 0
    seen: dict[tuple[str, str, str], tuple[int | None, str, str]] = field(default_factory=dict)

    def exhausted(self) -> bool:
        return self.requests >= _MAX_REQUESTS or self.remaining() <= 0.5

    def remaining(self) -> float:
        return _MAX_WALL - (time.monotonic() - self.started)

    def claim(self) -> bool:
        if self.exhausted():
            return False
        self.requests += 1
        return True


@dataclass(frozen=True)
class _Surface:
    """One input the target will accept a value through."""

    kind: str  # "query" | "form" | "json"
    method: str
    url: str
    field_name: str


def _nonce() -> str:
    """Return a fresh 6-char lowercase-hex token, unique per call.

    Hex rather than base32 keeps the token inside the identifier alphabet, so
    a reflected nonce cannot be confused with markup or punctuation.  6 chars
    is 24 bits: two calls in one run colliding is 1 in 16 million, and the
    token is short enough to survive a field that truncates at 32 chars.
    """
    return secrets.token_hex(3)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _send(
    budget: _Budget,
    method: str,
    url: str,
    *,
    data: dict[str, str] | None = None,
    payload: dict[str, str] | None = None,
) -> tuple[int | None, str, str]:
    """Send one request inside the budget, recording it in the traffic ledger.

    Returns ``(status, body, phase)``.  ``status`` is ``None`` when the request
    never completed; ``phase`` then names the failure ("budget" when the call's
    own caps refused it, otherwise the exception class).  De-duplication is by
    ``(method, url, body)`` *within this call only*: the task order measured
    cross-call caching as not paying for itself.
    """
    body_key = ""
    if data is not None:
        body_key = urlencode(sorted(data.items()))
    elif payload is not None:
        body_key = json.dumps(payload, sort_keys=True)
    key = (method.upper(), url, body_key)
    if key in budget.seen:
        return budget.seen[key]
    if not budget.claim():
        return (None, "", "budget")

    request_id = traffic.ledger().next_id()
    started = time.time()
    timeout = max(1.0, min(_REQ_TIMEOUT, budget.remaining()))
    cookies = session_cookies("auto", url)
    headers = {"Connection": "close"}
    try:
        response = requests.request(
            method.upper(),
            url,
            data=data,
            json=payload,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            cookies=cookies or None,
        )
        body = (response.text or "")[:_BODY_KEEP]
        status: int | None = response.status_code
        phase = ""
        result = (status, body, phase)
        traffic.record(
            request_id=request_id,
            method=method,
            url=url,
            req_headers=dict(headers),
            req_body=body_key,
            status=status,
            resp_headers=dict(response.headers),
            resp_body=body,
            size=len(body),
            elapsed=time.time() - started,
        )
    except Exception as exc:  # noqa: BLE001 - one dead endpoint must not abort
        phase = type(exc).__name__
        result = (None, "", phase)
        traffic.record(
            request_id=request_id,
            method=method,
            url=url,
            req_headers=dict(headers),
            req_body=body_key,
            phase=phase,
            elapsed=time.time() - started,
            note=f"{phase}: {exc}"[:300],
        )
    budget.seen[key] = result
    return result


def _classify(body: str, nonce: str, payload: str) -> str:
    """Classify one response's treatment of the injected payload.

    Returns ``absent`` / ``verbatim`` / ``transformed`` / ``partial``.
    ``partial`` is "the nonce survived but nothing about the context did"; it
    is deliberately *not* a hit, because a value echoed into a JSON string is
    not exploitable and calling it one would be guessing.
    """
    if nonce not in body:
        return "absent"
    if payload in body:
        return "verbatim"
    at = body.find(nonce)
    window = body[at : at + len(payload) + 16]
    if any(mark in window for mark in _ENC_MARKS):
        return "transformed"
    return "partial"


def _form_surfaces(item: traffic.Exchange) -> list[_Surface]:
    """Extract ``<input name=...>`` surfaces from one recorded response body."""
    body = item.resp_body or ""
    if "<input" not in body.lower():
        return []
    out: list[_Surface] = []
    action = item.url
    method = "GET"
    # Walk the document so each <input> is attributed to the <form> it is in.
    tokens = re.finditer(
        r"<form\b[^>]*>|<input\b[^>]*>", body, re.IGNORECASE
    )
    for match in tokens:
        chunk = match.group(0)
        if chunk.lower().startswith("<form"):
            found_action = _FORM_ACTION.search(chunk)
            found_method = _FORM_METHOD.search(chunk)
            action = found_action.group(1) if found_action else item.url
            method = (found_method.group(1).upper() if found_method else "GET")
            continue
        name_match = _INPUT_NAME.search(chunk)
        if not name_match:
            continue
        name = name_match.group(1).strip()
        if not name or name.lower() in ("submit", "button", "csrf", "_token"):
            continue
        target = action
        if not target.lower().startswith(("http://", "https://")):
            base = _origin(item.url)
            target = base + (target if target.startswith("/") else "/" + target)
        out.append(_Surface("form", method, target, name))
    return out


def _surfaces(items: list[traffic.Exchange]) -> list[_Surface]:
    """Collect input surfaces from recorded traffic, newest first, deduplicated."""
    out: list[_Surface] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(surface: _Surface) -> None:
        key = (surface.kind, surface.method, surface.url, surface.field_name)
        if key in seen:
            return
        seen.add(key)
        out.append(surface)

    for item in reversed(items):
        parts = urlsplit(item.url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        for name, _value in query:
            if name:
                add(_Surface("query", "GET", item.url, name))
        body = (item.req_body or "").strip()
        if body.startswith("{"):
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                for name in parsed:
                    if isinstance(name, str) and name:
                        add(_Surface("json", "POST", item.url, name))
        for surface in _form_surfaces(item):
            add(surface)
    return out


def _with_param(url: str, name: str, value: str) -> str:
    """Set one query parameter, keeping the others."""
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def _ladder_reflection(budget: _Budget, items: list[traffic.Exchange]) -> Verdict:
    surfaces = _surfaces(items)[:_L1_SURFACES]
    if not surfaces:
        return Verdict("reflection_canary", "unknown", "no input surface in recorded traffic")

    nonce = _nonce()
    payload = nonce + _PROBE_TAIL
    tried = 0
    hits: list[str] = []
    partial = 0
    errors = 0
    for surface in surfaces:
        if budget.exhausted():
            break
        if surface.kind == "query":
            url, data = _with_param(surface.url, surface.field_name, payload), None
            method, json_body = "GET", None
        elif surface.kind == "form" and surface.method.upper() == "GET":
            # A GET form carries its fields in the query string.  Sending them
            # as a request body makes a reflecting page look dead.
            url, data = _with_param(surface.url, surface.field_name, payload), None
            method, json_body = "GET", None
        elif surface.kind == "json":
            url, data, method, json_body = surface.url, None, "POST", {surface.field_name: payload}
        else:
            url, data, method, json_body = surface.url, {surface.field_name: payload}, surface.method, None
        status, body, phase = _send(budget, method, url, data=data, payload=json_body)
        tried += 1
        if status is None:
            errors += 1
            continue
        if status >= 500:
            errors += 1
            continue
        verdict = _classify(body, nonce, payload)
        if verdict == "verbatim":
            hits.append(f"verbatim in {surface.field_name}")
        elif verdict == "transformed":
            hits.append(f"HTML/URL-encoded in {surface.field_name}")
        elif verdict == "partial":
            partial += 1
        if hits:
            break

    if hits:
        return Verdict(
            "reflection_canary", "hit",
            f"nonce {hits[0]} ({len(hits)}/{tried} surfaces)",
        )
    if tried == 0:
        return Verdict("reflection_canary", "skipped", "budget spent before the first surface")
    if errors == tried:
        return Verdict("reflection_canary", "unknown", f"all {tried} probes errored")
    if partial:
        return Verdict(
            "reflection_canary", "unknown",
            f"nonce echoed but context escaped/stripped ({partial}/{tried} surfaces)",
        )
    return Verdict(
        "reflection_canary", "dead",
        f"all {tried} surfaces dropped the nonce, no error signature",
    )


def _auth_samples(items: list[traffic.Exchange]) -> list[traffic.Exchange]:
    """Pick recorded paths a string-matching gate might treat inconsistently.

    Two shapes qualify: an explicit 401/403, and a 200 that looks like a login
    page (a gate may redirect there instead of refusing).  Anything else has no
    access-control claim to test.
    """
    out: list[traffic.Exchange] = []
    seen: set[str] = set()
    for item in reversed(items):
        path = urlsplit(item.url).path or "/"
        if path in seen:
            continue
        status = item.status or 0
        login_page = 200 <= status < 300 and bool(_LOGIN_MARK.search(item.resp_body or ""))
        if status in (401, 403) or login_page:
            seen.add(path)
            out.append(item)
    return out


def _baseline_len(item: traffic.Exchange) -> int:
    return int(item.size or 0) or len(item.resp_body or "")


def _ladder_auth(
    budget: _Budget, items: list[traffic.Exchange], fresh: bool = False
) -> Verdict:
    samples = _auth_samples(items)[:_L2_PATHS]
    if not samples:
        return Verdict(
            "auth_variant_split", "unknown",
            "no 401/403 or login page in recorded traffic",
        )

    tried = 0
    variants_hit: list[str] = []
    baseline_status = 0
    baseline_len = 0
    all_same = True
    for item in samples:
        if budget.exhausted():
            break
        path = urlsplit(item.url).path or "/"
        baseline_status = int(item.status or 0)
        baseline_len = _baseline_len(item)
        if fresh:
            # The target may have changed since the exchange was recorded;
            # re-read the baseline so ``dead`` is decided against today's page.
            live_status, live_body, _phase = _send(budget, "GET", item.url)
            if live_status is not None:
                baseline_status = live_status
                baseline_len = len(live_body)
        base_url = _origin(item.url)
        for kind, variant in _variant_paths(path, _L2_KINDS):
            if budget.exhausted():
                break
            url = base_url + variant
            status, body, _phase = _send(budget, "GET", url)
            tried += 1
            if status is None:
                all_same = False
                continue
            length = len(body)
            status_changed = status != baseline_status
            length_off = abs(length - baseline_len) > max(2, int(baseline_len * 0.02))
            if status_changed or length_off:
                all_same = False
            if 200 <= status < 300 and status != baseline_status:
                grew = baseline_len == 0 or abs(length - baseline_len) > baseline_len * 0.10
                if grew:
                    variants_hit.append(f"{kind}->{status} len={length} (base {baseline_status} len={baseline_len})")
            elif 200 <= status < 300 and length_off:
                variants_hit.append(f"{kind}->{status} len={length} vs base {baseline_len}")

    if variants_hit:
        return Verdict("auth_variant_split", "hit", variants_hit[0])
    if tried == 0:
        return Verdict("auth_variant_split", "skipped", "budget spent before the first variant")
    if all_same:
        return Verdict(
            "auth_variant_split", "dead",
            f"all {tried} variants matched baseline {baseline_status} len={baseline_len} (+-2%)",
        )
    return Verdict(
        "auth_variant_split", "unknown",
        f"{tried} variants moved but none landed 2xx with a >10% body change",
    )


def _neighbours(token: str, span: int = _L3_SPAN) -> list[str]:
    """Return ``token`` with its trailing hex run moved by +-1 and +-2.

    A reference ladder must stay a *neighbourhood*, not a burst: four probes
    per identifier is enough to see whether ids are sequential, and the cap is
    what keeps this call out of the "scanning the site" category.
    """
    match = _TAIL_HEX.search(token)
    if not match:
        return []
    tail = match.group(1)
    width = len(tail)
    base = int(tail, 16)
    out: list[str] = []
    for delta in (-span, -1, 1, span):
        value = base + delta
        if value < 0:
            continue
        out.append(token[: match.start()] + format(value, f"0{width}x"))
    return out


def _token_url(item: traffic.Exchange, token: str) -> str:
    origin = _origin(item.url)
    if token.startswith("/"):
        return origin + token
    path = urlsplit(item.url).path or "/"
    return origin + path.rstrip("/") + "/" + token


def _ladder_reference(budget: _Budget, items: list[traffic.Exchange]) -> Verdict:
    pending = traffic.pending_targets(limit=_L3_IDS)
    if not pending:
        return Verdict("reference_enum", "unknown", "no identifier observed in any response")

    tried = 0
    dead_ids = 0
    for token in pending:
        if budget.exhausted():
            break
        source = next(
            (item for item in reversed(items) if token in (item.resp_body or "")),
            None,
        )
        if source is None:
            continue
        base_url = _token_url(source, token)
        base_status, base_body, _ = _send(budget, "GET", base_url)
        tried += 1
        if base_status is None or not (200 <= base_status < 300):
            continue
        base_len = len(base_body)
        if base_len < _MIN_BASE_LEN:
            continue
        neighbours = _neighbours(token)
        if not neighbours:
            continue
        bodies: list[str] = []
        found: list[str] = []
        for neighbour in neighbours:
            if budget.exhausted():
                break
            url = _token_url(source, neighbour)
            status, body, _ = _send(budget, "GET", url)
            tried += 1
            if status is None:
                continue
            bodies.append(body)
            if 200 <= status < 300:
                off = abs(len(body) - base_len) > max(2, int(base_len * 0.02))
                if off and not _ERROR_MARK.search(body[:1000]):
                    found.append(f"{neighbour} -> {status} len={len(body)} vs base {base_len}")
        if found:
            return Verdict("reference_enum", "hit", found[0])
        if bodies and len(set(bodies)) == 1 and _ERROR_MARK.search(bodies[0][:1000]):
            dead_ids += 1

    if tried == 0:
        return Verdict("reference_enum", "skipped", "budget spent before the first identifier")
    if dead_ids:
        return Verdict(
            "reference_enum", "dead",
            f"all neighbours of {dead_ids} identifier(s) returned the same error page",
        )
    return Verdict(
        "reference_enum", "unknown",
        f"{tried} probes, no sequential neighbour answered",
    )


_LADDERS = {
    "reflection_canary": _ladder_reflection,
    "auth_variant_split": _ladder_auth,
    "reference_enum": _ladder_reference,
}


def _render(budget: _Budget, verdicts: list[Verdict], unknown_classes: list[str]) -> str:
    """Render the fixed-width table, hard-capped at ``_MAX_OUT`` characters."""
    elapsed = time.monotonic() - budget.started
    lines = [f"viability ({budget.requests} reqs, {elapsed:.1f}s)"]
    for verdict in verdicts:
        lines.append(f"{verdict.name:<20}{verdict.state:<9}{verdict.evidence}")
    for name in unknown_classes:
        lines.append(f"{name:<20}{'skipped':<9}unknown class")
    text = "\n".join(lines)
    if len(text) > _MAX_OUT:
        text = text[: _MAX_OUT - 1] + "~"
    return text


# ---------------------------------------------------------------- tool entry


def viability_probe(
    url: str = "", classes: str = "all", fresh: bool = False
) -> str:
    """Batch-probe three mechanism classes and return hit/dead/unknown verdicts.

    Call this when two or more candidate directions remain and none has
    evidence yet.  Each ladder is a fixed, small sweep whose verdict is decided
    by the responses it records in the same call: ``dead`` means every probe
    came back identical, not "I did not find anything".

    Use it as an accelerator, not a prerequisite: a run that already has
    evidence should follow the evidence instead.  The ladders read the run's
    traffic ledger, which is often empty because most agent HTTP goes through
    ``exec_command`` and curl; pass ``url`` to bootstrap it with one recorded
    GET before the ladders run.

    Args:
        url: page to fetch and record first when it is not already in the
            ledger (or when ``fresh`` is set).  This request counts against
            the 40-request budget.
        classes: comma-separated ladder names from ``reflection_canary``,
            ``auth_variant_split``, ``reference_enum``; ``all`` (default) runs
            all three in that order.
        fresh: re-fetch ``url`` even when the ledger already has it, and
            re-read the auth baseline instead of trusting the recorded
            status/length (use when the target just changed).

    Returns:
        A fixed-width table, at most 1600 characters, naming the request count
        and elapsed time.  Response bodies are never included.
    """
    wanted = [c.strip().lower() for c in re.split(r"[\s,]+", classes or "") if c.strip()]
    if not wanted or "all" in wanted:
        wanted = list(_LADDER_ORDER)
    unknown_classes = [c for c in wanted if c not in _LADDERS]
    ordered = [c for c in _LADDER_ORDER if c in wanted]

    budget = _Budget()
    target = (url or "").strip()
    if target and (fresh or target not in {item.url for item in traffic.ledger().items()}):
        # One recorded GET: the exchange it produces is the ladders' input.
        _send(budget, "GET", target)

    items = traffic.ledger().items()
    if not items:
        verdicts = [
            Verdict(name, "unknown", "no recorded traffic (pass url= to bootstrap)")
            for name in ordered
        ]
        return _render(budget, verdicts, unknown_classes)

    verdicts: list[Verdict] = []
    stopped = False
    for name in ordered:
        if stopped:
            verdicts.append(Verdict(name, "skipped", "budget spent by an earlier ladder"))
            continue
        if budget.exhausted():
            verdicts.append(Verdict(name, "skipped", f"budget: {budget.requests}/{_MAX_REQUESTS} requests"))
            stopped = True
            continue
        if name == "auth_variant_split":
            verdicts.append(_LADDERS[name](budget, items, fresh=fresh))
        else:
            verdicts.append(_LADDERS[name](budget, items))
        if budget.exhausted():
            stopped = True
    return _render(budget, verdicts, unknown_classes)


TOOLS: Final = (viability_probe,)


def _as_async(func):
    """Run the blocking ladder work off the agent event loop.

    ``function_tool(timeout=...)`` raises at registration for a sync handler.
    ``functools.wraps`` keeps ``classes``/``fresh`` visible to the SDK, which
    derives the JSON schema from the signature.
    """
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner


def register(register_fn=None) -> list[str]:
    """Register ``viability_probe`` on every scan agent built afterwards."""
    from agents import function_tool

    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()
    wrapped = [function_tool(timeout=120)(_as_async(fn)) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]