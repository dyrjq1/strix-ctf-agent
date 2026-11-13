"""Path-variant matrix: turn "forgot to try another spelling" into one call.

Why this module exists
----------------------
On one run the DeepSeek arm spent 29 tool calls and the full 600s wall
clock without solving. The transcript shows it locked onto a single
hypothesis ("nginx/Express differ in percent-decoding") and kept generating
new payloads for that one hypothesis. It never once tried all-uppercase --
and `/INTERNAL/banner` was the answer. The GLM arm solved it in 8 calls.

That is not a knowledge gap. `upper`, `pct`, `dot`, `semi`, `slash` and
`query` are six *independent* mechanisms: any middlebox (WAF, reverse proxy,
framework router) that normalises one but not another produces a difference.
Models either forget a class or judge it "not worth trying".

Anything that means "remember to do X" belongs in one call -- this repo has
already seen prompt-level instructions decay three times (007 enumeration,
009 method sweep, 095 variants).

Division of labour with `method_sweep`
--------------------------------------
- `method_sweep`: one path  x many HTTP methods.
- `path_variants`: one resource x many spellings (GET only by default).

Together they cover the path x method x spelling cube. See docs/18 for the
Chinese write-up and the rule-check that this stays inside competition scope
(target is the one assigned vhost; sequential, small concurrency).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Final
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from ctf_strix import traffic
from ctf_strix.http_probe import session_cookies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#: Single-request timeout. Variant probing must be quick; slow endpoints
#: belong to `http_probe` where the caller can pick a longer budget.
_TIMEOUT: Final = 8.0

#: Each kind maps to a distinct middlebox normalisation behaviour.
_VARIANT_KINDS: Final = (
    "upper", "lower", "title", "pct", "pct2", "dot", "semi", "slash", "query",
)


def _encode_pct(text: str) -> str:
    """Percent-encode one path segment, keeping alphanumerics and -_.~ intact."""
    out: list[str] = []
    for ch in text:
        if ch.isalnum() or ch in "-_.~":
            out.append(ch)
        else:
            out.append("".join("%%%02X" % b for b in ch.encode()))
    return "".join(out)


def _segments(path: str) -> list[str]:
    return [seg for seg in path.split("/") if seg]


def _variant_paths(path: str, kinds: tuple[str, ...]) -> list[tuple[str, str]]:
    """Generate (kind, variant path) pairs for one resource path.

    Case variants only touch the letters of each segment, so they still point at
    the same hierarchy. Dot/semicolon/duplicate-slash variants change how the
    separators are escaped -- that is where "proxy collapses vs backend does
    not" diverges.
    """
    segs = _segments(path)
    if not segs:
        return []
    lead = "/" if path.startswith("/") else ""
    out: list[tuple[str, str]] = []
    for kind in kinds:
        if kind == "upper":
            body = "/".join(s.upper() for s in segs)
        elif kind == "lower":
            body = "/".join(s.lower() for s in segs)
        elif kind == "title":
            body = "/".join(s[:1].upper() + s[1:] for s in segs)
        elif kind == "pct":
            body = "/".join(_encode_pct(s) for s in segs)
        elif kind == "pct2":
            body = "/".join(_encode_pct(_encode_pct(s)) for s in segs)
        elif kind == "dot":
            body = "/".join("./" + s for s in segs)
        elif kind == "semi":
            body = "/".join(s + ";" for s in segs)
        elif kind == "slash":
            body = "//".join(segs)
        elif kind == "query":
            body = "/".join(segs)
        else:
            continue
        cand = lead + body
        if kind == "query":
            cand = cand.rstrip("/") + "/?x=1"
        if cand == path:
            continue
        out.append((kind, cand))
    return out


def _run_path_variants(
    urls: str,
    base_url: str = "",
    kinds: str = "",
    methods: str = "GET",
    concurrency: int = 6,
    baseline: bool = True,
    headers_json: str = "",
    session: str = "auto",
) -> str:
    """Probe one resource through several spelling variants.

    Use this when a path exists but a gate in front of it may normalise
    differently from the backend. Each call sweeps independent mechanisms
    (case, percent-encoding once/twice, dot segments, semicolon params,
    duplicate slashes, trailing query) so a single hypothesis cannot eat the
    whole budget.

    Args:
        urls: newline- or comma-separated paths. Relative paths are joined to
            `base_url`.
        base_url: e.g. `https://host`. Required for relative paths.
        kinds: comma-separated subset of upper/lower/title/pct/pct2/dot/semi/
            slash/query. Empty means all.
        methods: comma-separated; only GET/HEAD/OPTIONS/POST are accepted.
            Default GET -- variant probing must not mutate target state.
        concurrency: worker count, default 6. The target is a challenge box,
            not a load-test subject.
        baseline: also probe the original spelling. Without it a 200 on a
            variant cannot be told apart from a catch-all route.
        headers_json: extra request headers, JSON string (same format as
            ``http_probe``), e.g. ``{"Authorization": "Bearer x"}``.
        session: same semantics as ``http_probe``. Default ``auto``: cookies the
            login session holds for each target host are attached to every
            request, so an authenticated path stays visible while spelling
            variants are probed. ``off`` stays anonymous. Set-Cookie responses
            are never written back (the sweep stays read-only).

    Returns:
        One line per differing result (status, method, kind, path, size, body
        snippet), grouped by kind, plus a verdict line that says whether the
        difference is a real bypass, an auth gate, or nothing.
    """
    base = (base_url or "").strip()
    raw = [u.strip() for u in re.split(r"[\s,]+", urls or "") if u.strip()]
    if not raw:
        return "[path_variants] urls empty; pass newline-separated paths"

    try:
        extra_headers = json.loads(headers_json) if headers_json.strip() else {}
    except json.JSONDecodeError as exc:
        return "[path_variants] headers_json is not valid JSON: %s" % exc
    if not isinstance(extra_headers, dict):
        return "[path_variants] headers_json must be a JSON object."

    wanted = tuple(k.strip() for k in re.split(r"[\s,]+", kinds or "") if k.strip())
    if not wanted:
        wanted = _VARIANT_KINDS
    unknown = [k for k in wanted if k not in _VARIANT_KINDS]
    if unknown:
        return "[path_variants] unknown kinds %s; choose from %s" % (
            unknown, ", ".join(_VARIANT_KINDS))

    mlist = [m.strip().upper() for m in re.split(r"[\s,]+", methods or "") if m.strip()]
    mlist = [m for m in mlist if m in {"GET", "HEAD", "OPTIONS", "POST"}][:4] or ["GET"]

    # `methods` was advertised as "GET/HEAD/OPTIONS/POST, up to four" but only
    # `mlist[0]` was ever sent, while the summary line reported `len(mlist)`
    # (report WEB-7): the tool printed a request count it had not made.  Jobs
    # now carry the method and every listed method is actually sent.
    jobs: list[tuple[str, str, str, str]] = []
    for u in raw:
        if u.startswith(("http://", "https://")):
            path = urlparse(u).path or "/"
            absolute = u
        else:
            path = u if u.startswith("/") else "/" + u
            if not base:
                return "[path_variants] relative path %s needs base_url" % u
            absolute = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        for method in mlist:
            if baseline:
                jobs.append(("as-is", path, absolute, method))
            for kind, variant in _variant_paths(path, wanted):
                full = (urljoin(base.rstrip("/") + "/", variant.lstrip("/"))
                        if base else variant)
                jobs.append((kind, variant, full, method))

    planned = len(jobs)
    if len(jobs) > 120:
        jobs = jobs[:120]

    # WEB-1: inherit http_probe's login state. A requests.Session is not
    # thread-safe, so the pool never shares the Session object -- it attaches a
    # read-only cookie snapshot per target host instead, and never writes back.
    carried = {url: session_cookies(session, url) for url in {job[2] for job in jobs}}

    def probe(job: tuple[str, str, str, str]) -> dict | None:
        kind, path, url, method = job
        headers = {"Connection": "close"}
        headers.update(extra_headers)
        snap = carried.get(url) or {}
        sent_headers = dict(headers)
        if snap:
            sent_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in snap.items())
        # Same rule as http_probe / method_sweep: the id is reserved *before*
        # sending and a failed attempt is recorded too -- "this spelling was
        # refused" is itself the observation that ends the retry loop.
        request_id = traffic.ledger().next_id()
        started = time.time()
        try:
            r = requests.request(
                method, url, timeout=_TIMEOUT, verify=False,
                allow_redirects=False, headers=headers, cookies=snap or None,
            )
        except Exception as exc:  # noqa: BLE001
            traffic.record(
                request_id=request_id, method=method, url=url, req_headers=sent_headers,
                phase=type(exc).__name__, elapsed=time.time() - started,
                note=f"{type(exc).__name__}: {exc}"[:300],
            )
            return {"kind": kind, "path": path, "method": method,
                    "status": 0, "note": type(exc).__name__, "id": request_id}
        text = r.text or ""
        traffic.record(
            request_id=request_id, method=method, url=url, req_headers=sent_headers,
            status=r.status_code, resp_headers=dict(r.headers), resp_body=text,
            size=len(r.content or b""), elapsed=time.time() - started,
        )
        body = text.replace("\n", " ")[:180]
        return {"kind": kind, "path": path, "method": method,
                "status": r.status_code, "size": len(r.content or b""),
                "body": body, "id": request_id}

    with ThreadPoolExecutor(max_workers=max(1, min(10, int(concurrency)))) as pool:
        results = [r for r in pool.map(probe, jobs) if r]

    # Baseline is per (path, method) now that more than one method is sent: a
    # GET baseline must not explain away a POST 403, which is exactly the
    # signal "the write handler exists and is gated".
    base_status: dict[tuple[str, str], int] = {}
    for r in results:
        if r["kind"] == "as-is":
            base_status[(str(r["path"]), str(r["method"]))] = int(r["status"])

    def baseline_for(r: dict) -> int | None:
        key = (str(r["path"]), str(r["method"]))
        if key in base_status:
            return base_status[key]
        # baseline=False, or the baseline row was culled by the 120 cap: fall
        # back to any baseline of the same method rather than to none.
        for (_, m), st in base_status.items():
            if m == str(r["method"]):
                return st
        return None

    def notable(r: dict) -> bool:
        status = int(r["status"])
        if status == 0:
            return True
        if status in (404, 410):
            return False
        if r["kind"] != "as-is":
            base = baseline_for(r)
            if base is not None and base == status and base >= 400:
                return False
        return True

    kept = [r for r in results if notable(r)]
    kept.sort(key=lambda r: (0 if 200 <= int(r["status"]) < 300 else 1,
                             -int(r.get("size", 0))))

    groups: dict[str, list[dict]] = {}
    for r in kept:
        groups.setdefault(str(r["kind"]), []).append(r)

    # Report what was actually sent: the methods present in `jobs` after the
    # 120 cap, and the exact request count.  The old line multiplied by
    # `len(mlist)` while sending `mlist[0]` only (report WEB-7).
    sent_methods = "/".join(sorted({job[3] for job in jobs})) or "none"
    capped = " (capped from %d planned)" % planned if planned > len(jobs) else ""
    lines = [
        "[path_variants] %d paths x %d kinds x %s = %d requests%s | differing %d"
        % (len(raw), len(wanted), sent_methods, len(jobs), capped, len(kept))
    ]
    if any(carried.values()):
        n_auth = sum(1 for v in carried.values() if v)
        lines.append(
            "auth: %d/%d target hosts carry session cookies "
            "(http_probe login state applies; the sweep never writes back)"
            % (n_auth, len(carried))
        )
    for kind, rows in groups.items():
        for r in rows[:6]:
            status = int(r["status"])
            if status == 0:
                lines.append("ERR %-6s [%s] %s | %s | id=%s"
                             % (r["method"], kind, r["path"], r.get("note", ""),
                                r.get("id", "")))
                continue
            body = str(r.get("body") or "")
            lines.append("%d %-6s [%s] %s | %dB | id=%s%s"
                         % (status, r["method"], kind, r["path"],
                            r.get("size", 0), r.get("id", ""),
                            (" | " + body) if body else ""))

    hits = [r for r in kept if 200 <= int(r["status"]) < 300]
    if hits:
        kinds_hit = sorted({str(r["kind"]) for r in hits})
        lines.append("hit: %d 2xx via %s. Check whether as-is is also 2xx "
                     "(then it is a catch-all route, not a variant bypass)."
                     % (len(hits), kinds_hit))
    elif kept:
        lines.append("no-2xx: variants returned 4xx/5xx only. A 401/403 on one "
                     "variant means it bypassed the front gate; retry that variant "
                     "with auth. 5xx means the request reached a different handler.")
    else:
        lines.append("no-signal: every variant matched the baseline. This path is "
                     "insensitive to spelling; switch mechanism (parameters, method, "
                     "Content-Type) instead of adding more variant kinds.")
    lines.append(
        "ledger: every row above is a recorded exchange -- reread a body with "
        "traffic_view(id), or survey the whole sweep with "
        "traffic_list(url_contains=...), instead of sending the request again."
    )
    return "\n".join(lines)


async def path_variants(
    urls: str,
    base_url: str = "",
    kinds: str = "",
    methods: str = "GET",
    concurrency: int = 6,
    baseline: bool = True,
    headers_json: str = "",
    session: str = "auto",
) -> str:
    """Probe one resource through several spelling variants.

    Async wrapper: `agents.function_tool(timeout=...)` only accepts async
    handlers, and a sync one fails registration with a ValueError that the
    capability installer records as ``variants: []`` -- silent in the tool
    surface, loud only in the run log. The blocking HTTP work runs in a worker
    thread so the agent event loop stays responsive.

    Args:
        urls: newline- or comma-separated paths; relative paths join `base_url`.
        base_url: e.g. `https://host`. Required for relative paths.
        kinds: subset of upper/lower/title/pct/pct2/dot/semi/slash/query;
            empty means all.
        methods: only GET/HEAD/OPTIONS/POST are accepted; default GET.
        concurrency: worker count, default 6.
        baseline: also probe the original spelling for comparison.
        headers_json: extra request headers as a JSON string, like http_probe.
        session: "auto" (default) attaches the login session's cookies for each
            target host; "off" stays anonymous. Never written back.

    Returns:
        One line per differing result plus a verdict line.
    """
    return await asyncio.to_thread(
        _run_path_variants, urls, base_url, kinds, methods, concurrency, baseline,
        headers_json, session
    )


TOOLS = (path_variants,)


def register(register_fn=None) -> list[str]:
    """Register `path_variants` on every scan agent built afterwards."""
    from agents import function_tool

    if register_fn is None:
        from strix.agents import factory
        register_fn = factory.register_agent_tools
        existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
    else:
        existing = set()
    wrapped = [function_tool(timeout=180)(fn) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]
