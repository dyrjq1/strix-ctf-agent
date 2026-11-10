# -*- coding: utf-8 -*-
"""Web primitives pack B-1: jwt_forge, authdiff, jsrecon, http_burst.

Four pure-stdlib tools ported from ctfy_project and adapted to the
strix-agent tool conventions (traffic ledger, http_probe-style registration,
catalogue-driven prompt).  jwt_forge is purely local; the other three go
through the same traffic recording as http_probe.

Design constraints:
- Pure stdlib for the tool logic; network requests reuse the project's
  ``requests`` dependency (already in vendor), same as ``http_probe``.
- Every request is recorded in the traffic ledger with a source tag so
  ``traffic_list`` / ``traffic_view`` can read it back.
- Descriptions must not mention specific challenge numbers, IPs, flags, or
  failure paths.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import re
import ssl
import threading
import time
from typing import Any, Final
from urllib.parse import urljoin, urlparse

from ctf_strix import traffic

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

_TOOL_TEXT_MAX: Final = 6000


def _clip(text: str, limit: int = _TOOL_TEXT_MAX) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 40] + "\n...[truncated, original length {} chars]".format(len(text))


def _fail(msg: str) -> None:
    """Abort a call with an actionable message.

    Bad *input* is validated before any I/O.  A returned string would be read
    as a server response by the model, so these call sites raise instead.
    """
    raise RuntimeError(msg)


def _require_url(url: Any, tool: str) -> str:
    if not isinstance(url, str) or not url.strip():
        _fail(f"{tool} requires a url, e.g. https://host/path")
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        _fail(f"{tool} needs an absolute http(s) url, got {cleaned[:80]!r}")
    return cleaned


def _headers_from_json(headers_json: str, limit: int) -> dict[str, str]:
    try:
        parsed = json.loads(headers_json) if headers_json.strip() else {}
    except json.JSONDecodeError as exc:
        _fail(f"headers_json is not valid JSON: {exc}")
    if not isinstance(parsed, dict):
        _fail("headers_json must be a JSON object")
    if len(parsed) > limit:
        _fail(f"at most {limit} extra headers, got {len(parsed)}")
    out: dict[str, str] = {}
    for key, value in parsed.items():
        name, val = str(key), str(value)
        if not name or "\r" in name + val or "\n" in name + val:
            _fail(f"illegal header (empty name or CR/LF): {name!r}")
        out[name] = val
    return out


def _safe_fetch(
    url: str,
    method: str = "GET",
    body: str = "",
    extra_headers: dict[str, str] | None = None,
    timeout_s: float = 20.0,
    source: str = "webprim",
) -> tuple[int, str, str]:
    """Fetch one URL, record in traffic ledger, return (status, content_type, text)."""
    method = (method or "GET").strip().upper()
    url = (url or "").strip()
    request_id = traffic.ledger().next_id()
    started = time.time()
    headers = dict(extra_headers or {})
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            data=body.encode("utf-8") if body else None,
            timeout=timeout_s,
            allow_redirects=False,
            verify=False,
        )
    except Exception as exc:
        elapsed = time.time() - started
        traffic.record(
            request_id=request_id,
            method=method,
            url=url,
            req_headers=headers,
            req_body=body if isinstance(body, str) else "",
            phase="FETCH_ERROR",
            elapsed=elapsed,
            note=f"{source}: {type(exc).__name__}: {exc}"[:300],
        )
        raise

    elapsed = time.time() - started
    raw = resp.content or b""
    text = raw.decode(resp.encoding or "utf-8", errors="replace")
    ctype = resp.headers.get("content-type", "?")
    traffic.record(
        request_id=request_id,
        method=method,
        url=url,
        req_headers=headers,
        req_body=body if isinstance(body, str) else "",
        status=resp.status_code,
        resp_headers=dict(resp.headers),
        resp_body=text,
        size=len(raw),
        elapsed=elapsed,
    )
    return resp.status_code, ctype, text


# ---------------------------------------------------------------------------
# 1. jwt_forge
# ---------------------------------------------------------------------------

def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


_HASHES: Final = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

_RSA_N = int(
    "936d6a39cdf53e4e7eac133c9c32ff97068f7e852561fe7d17443eb838fb2af315655aff535488b391e03e618fe76ac2ec938f37328d3d5905fcbd29c5c5437758c424a71db01f36b602d6764fed9d32c502453fbafe956093013fc0a1c0ce47d01e62c06f68e2c3a68a634e3687e59d10a122862af3a7b71ba0f2dcbe8b4eac93277ea0211a5b278aa5db323d44833c89ee5fa029e6fd094d0b5b426ac791bb650ccb71298f9a7634b2523d1b90738d7c0ae78af20d27dceb76bfe7fa982afb7c8cd08305c240ad8372f0262da18bd36a2e6df9bcbf6c3b01ef2f81eee07eb854046d83852d77d4c52600130dd565a7de82d60a77942b9cd2cf68227dd6d5c3",
    16,
)
_RSA_D = int(
    "71a602226773ebc125034f9d04a887c18bcc2873499b1e4c9e17fce594ff825f7b99f3a92a3adb5ada546ca25705c596583b7446cfd0737f620f305fb856d62875a456c10130d90f1b065aff3fa463ef5451e8c2354bb629898987f4de7cbc483dd67eb7ebea860cdf20856730c0583059366e5fd1529d729978dc5f710000f7fabb9297ef6efd405ff4a4c9b40a9244e34018056565ab39a2c02fe1b91bc75b8cc2d282f5ae891cad9b1236607287c4dc0f7a31b5f89fcc2ef8365a4c5698123346d71c2661109a4d7629651779ccda60ef5c6b8bde58e31c97644176d2cc6cee892d1fe6d1fc1d79e5ede2b18f74c1ffa455fb6ea0df9c3173c088369ee4d9",
    16,
)
_RSA_E = 65537
_SHA256_DI = bytes.fromhex("3031300d060960864801650304020105000420")


def _int_b64u(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


_RSA_PUBLIC_JWK: Final = {
    "kty": "RSA", "use": "sig", "alg": "RS256",
    "kid": "ctfy-test-key", "n": _int_b64u(_RSA_N), "e": _int_b64u(_RSA_E),
}


def _rsa_sha256_sign(signing_input: bytes) -> bytes:
    k = (_RSA_N.bit_length() + 7) // 8
    digest = hashlib.sha256(signing_input).digest()
    t = _SHA256_DI + digest
    ps_len = k - len(t) - 3
    if ps_len < 8:
        _fail("RSA key too short, cannot sign")
    em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    return pow(int.from_bytes(em, "big"), _RSA_D, _RSA_N).to_bytes(k, "big")


def jwt_forge(
    alg: str = "HS256",
    secret: str = "",
    token: str = "",
    claims_json: str = "",
    header_json: str = "",
    remove: list[str] | None = None,
) -> str:
    """Forge / resign a JWT (pure local computation).

    - alg=none: no signature, signature segment empty.
    - alg=HS256/384/512: HMAC with secret. For RS256->HS256 confusion,
      pick HS256 and pass the public key PEM as secret.
    - alg=RS256: sign with built-in test key pair and embed public key
      in jwk header (for services that trust a self-issued key).
    - When token is given, its header/claims become the base for rewriting.
    - secret is never echoed back, only its length.
    """
    alg = str(alg or "HS256")
    alg_key = alg.upper()
    try:
        header_extra = json.loads(header_json) if header_json.strip() else {}
    except json.JSONDecodeError as exc:
        _fail(f"header_json is not valid JSON: {exc}")
    try:
        claims_extra = json.loads(claims_json) if claims_json.strip() else {}
    except json.JSONDecodeError as exc:
        _fail(f"claims_json is not valid JSON: {exc}")
    if not isinstance(header_extra, dict):
        _fail("header_json must be a JSON object")
    if not isinstance(claims_extra, dict):
        _fail("claims_json must be a JSON object")
    if remove is not None and not isinstance(remove, list):
        _fail('remove must be a list, e.g. ["exp", "nbf"]')
    remove_keys = [str(k) for k in (remove or []) if isinstance(k, str)]

    header_out: dict = {"typ": "JWT"}
    claims_out: dict = {}
    if token:
        parts = token.strip().split(".")
        if len(parts) < 2:
            _fail("token does not look like a JWT: fewer than 2 dot-separated segments")
        try:
            header_out = json.loads(_b64u_decode(parts[0]))
            claims_out = json.loads(_b64u_decode(parts[1]))
        except Exception as exc:
            _fail(f"token first two segments are not valid base64url JSON: {exc}")

    changed: list[str] = []
    for key, value in header_extra.items():
        if value is None:
            continue
        header_out[str(key)] = value
    for key, value in claims_extra.items():
        if value is None:
            continue
        k = str(key)
        if claims_out.get(k) != value:
            changed.append(k)
        claims_out[k] = value
    removed: list[str] = []
    for key in remove_keys:
        if key in claims_out:
            claims_out.pop(key)
            removed.append(key)

    valid_algs = {"NONE", "HS256", "HS384", "HS512", "RS256"}
    if alg_key not in valid_algs:
        _fail(f"unsupported alg: {alg}; available: none / HS256 / HS384 / HS512 / RS256")

    if alg_key == "NONE":
        header_out["alg"] = "none"
    elif alg_key in ("HS256", "HS384", "HS512"):
        header_out["alg"] = alg_key
    elif alg_key == "RS256":
        header_out["alg"] = "RS256"
        header_out["jwk"] = dict(_RSA_PUBLIC_JWK)

    header_raw = json.dumps(header_out, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    claims_raw = json.dumps(claims_out, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signing_input = _b64u(header_raw).encode("ascii") + b"." + _b64u(claims_raw).encode("ascii")

    if alg_key == "NONE":
        sig = b""
    elif alg_key.startswith("HS"):
        if not secret:
            _fail("HS* requires secret; for RS256->HS256 confusion pass the public key PEM as secret")
        sig = hmac.new(secret.encode("utf-8"), signing_input, _HASHES[alg_key]).digest()
    else:
        sig = _rsa_sha256_sign(signing_input)

    token_out = signing_input.decode("ascii") + "." + _b64u(sig)
    result: dict[str, Any] = {
        "token": token_out,
        "alg": "none" if alg_key == "NONE" else alg_key,
        "header": header_out,
        "claims": claims_out,
        "changed": changed,
        "removed": removed,
    }
    if alg_key.startswith("HS"):
        result["secret_len"] = len(secret)
    return _clip(json.dumps(result, ensure_ascii=False))


# ---------------------------------------------------------------------------
# 2. authdiff
# ---------------------------------------------------------------------------

AUTHDIFF_MAX_HEADERS: Final = 6
AUTHDIFF_MAX_ROWS: Final = 14
AUTHDIFF_BUDGET: Final = 45.0

AUTHDIFF_BYPASS_HEADERS: Final = (
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Admin", "true"),
)

AUTHDIFF_VARIANTS: Final = ("anon", "bypass", "path")
_METHODS: Final = ("GET", "POST", "PUT", "PATCH", "DELETE")


def authdiff(
    url: str = "",
    method: str = "GET",
    body: str = "",
    headers_json: str = "",
    variants: str = "anon,bypass",
) -> str:
    """Privilege / auth comparison probe.

    Sends the same request under several identity variants and compares
    status, length, and body hash across them.

    Variant sets (comma-separated, from anon,bypass,path):
    - anon: strip cookies (anonymous view).
    - bypass: add proxy-forwarding / admin-trust headers.
    - path: append path-traversal variants to test filter-vs-route mismatches.

    Every request is recorded in the traffic ledger (source=authdiff).
    """
    url = _require_url(url, "authdiff")
    method = (method or "GET").strip().upper()
    if method not in _METHODS:
        _fail(f"method must be one of {', '.join(_METHODS)}, got {method!r}")

    want = set(v.strip().lower() for v in (variants or "anon,bypass").split(",") if v.strip())
    unknown = want - set(AUTHDIFF_VARIANTS)
    if unknown:
        _fail(f"unknown variant(s): {', '.join(sorted(unknown))}; available: {', '.join(AUTHDIFF_VARIANTS)}")

    extra_headers = _headers_from_json(headers_json, AUTHDIFF_MAX_HEADERS)
    cookie_present = any(
        name.lower() == "cookie" and value.strip()
        for name, value in extra_headers.items()
    )

    rows: list[dict] = []
    budget_deadline = time.time() + AUTHDIFF_BUDGET

    try:
        st, ct, txt = _safe_fetch(url, method, body, extra_headers, source="authdiff")
        rows.append({"variant": "baseline", "status": st, "len": len(txt),
                      "hash": hashlib.sha256(txt.encode()).hexdigest()[:12]})
    except Exception as exc:
        rows.append({"variant": "baseline", "error": f"{type(exc).__name__}: {exc}"})

    if time.time() > budget_deadline:
        return _clip(json.dumps({"tool": "authdiff", "rows": rows, "stopped_early": True}, ensure_ascii=False))

    if "anon" in want:
        anon_headers = dict(extra_headers)
        anon_headers["Cookie"] = ""
        try:
            st, ct, txt = _safe_fetch(url, method, body, anon_headers, source="authdiff")
            rows.append({"variant": "anon", "status": st, "len": len(txt),
                          "hash": hashlib.sha256(txt.encode()).hexdigest()[:12]})
        except Exception as exc:
            rows.append({"variant": "anon", "error": f"{type(exc).__name__}: {exc}"})

    if time.time() > budget_deadline:
        return _clip(json.dumps({"tool": "authdiff", "rows": rows, "stopped_early": True}, ensure_ascii=False))

    if "bypass" in want:
        for hdr_name, hdr_val in AUTHDIFF_BYPASS_HEADERS:
            if time.time() > budget_deadline:
                break
            bh = dict(extra_headers)
            bh[hdr_name] = hdr_val
            try:
                st, ct, txt = _safe_fetch(url, method, body, bh, source="authdiff")
                rows.append({"variant": f"bypass:{hdr_name}", "status": st, "len": len(txt),
                              "hash": hashlib.sha256(txt.encode()).hexdigest()[:12]})
            except Exception as exc:
                rows.append({"variant": f"bypass:{hdr_name}", "error": f"{type(exc).__name__}: {exc}"})

    if time.time() > budget_deadline:
        return _clip(json.dumps({"tool": "authdiff", "rows": rows, "stopped_early": True}, ensure_ascii=False))

    if "path" in want:
        parsed = urlparse(url)
        path = parsed.path or "/"
        suffixes = [
            "/../", "/..;/", "/%2e%2e/", "/.;/",
            "/../" + path.lstrip("/"), "/..;/" + path.lstrip("/"),
            "/%2e%2e/" + path.lstrip("/"),
        ]
        for suffix in suffixes:
            if time.time() > budget_deadline:
                break
            variant_url = parsed._replace(path=path.rstrip("/") + suffix).geturl()
            try:
                st, ct, txt = _safe_fetch(variant_url, method, body, extra_headers, source="authdiff")
                rows.append({"variant": f"path:{suffix}", "status": st, "len": len(txt),
                              "hash": hashlib.sha256(txt.encode()).hexdigest()[:12]})
            except Exception as exc:
                rows.append({"variant": f"path:{suffix}", "error": f"{type(exc).__name__}: {exc}"})

    rows = rows[:AUTHDIFF_MAX_ROWS]

    baseline_hash = ""
    anon_hash = ""
    for r in rows:
        if r.get("variant") == "baseline":
            baseline_hash = r.get("hash", "")
        if r.get("variant") == "anon":
            anon_hash = r.get("hash", "")

    conclusions: list[str] = []
    if anon_hash and baseline_hash:
        if anon_hash == baseline_hash:
            if cookie_present:
                conclusions.append("anonymous response identical to authenticated: access control may be missing")
            else:
                conclusions.append(
                    "no Cookie header supplied, so anon equals baseline by construction; "
                    "capture a session first, then rerun for a meaningful privilege check"
                )
        else:
            conclusions.append("anonymous response differs from authenticated")
    bypass_diffs = [r for r in rows if r.get("variant", "").startswith("bypass:") and "error" not in r]
    if bypass_diffs:
        for r in bypass_diffs:
            if r.get("hash") != baseline_hash and baseline_hash:
                conclusions.append(f"{r['variant']} changed the response (status {r['status']})")

    payload: dict[str, Any] = {
        "tool": "authdiff",
        "cookie_supplied": cookie_present,
        "rows": rows,
    }
    if conclusions:
        payload["conclusions"] = conclusions
    payload["note"] = "use traffic_view to diff any two responses byte-by-byte"

    return _clip(json.dumps(payload, ensure_ascii=False))


# ---------------------------------------------------------------------------
# 3. jsrecon
# ---------------------------------------------------------------------------

JSRECON_MAX_BUNDLES: Final = 6
JSRECON_MAX_BUNDLE_CHARS: Final = 512 * 1024
JSRECON_MAX_JSON_CHARS: Final = 6 * 1024 * 1024
JSRECON_MAX_PER_KIND: Final = 12
JSRECON_BUDGET: Final = 60.0
JSRECON_NOISE_EXT: Final = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".txt",
)

_SCRIPT_SRC_RE = re.compile(r"""(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""")
_INLINE_SCRIPT_RE = re.compile(r"(?is)<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>")
_SOURCEMAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s*\"']{3,200})")
_FETCH_CALL_RE = re.compile(
    r"""(?i)\b(fetch|axios(?:\.(?:get|post|put|delete|patch))?|\$\.(?:get|post|ajax))\s*\(\s*["'`]([^"'`]{2,200})["'`]"""
)
_STR_LIT_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./{}:$~%]{2,80})["'`]""")
_PARAMS_OBJ_RE = re.compile(r"(?is)\b(?:params|body|data|payload|query)\s*:\s*\{([^{}]{0,400})\}")
_PARAM_KEY_RE = re.compile(r"""["']?([A-Za-z_$][\w$]{1,30})["']?\s*:""")
_SEARCHPARAM_RE = re.compile(r"""(?i)searchParams\.(?:set|append)\(\s*["'`]([^"'`]{1,40})["'`]""")
_ROUTE_PATH_RE = re.compile(r"""(?i)\bpath\s*:\s*["'`](/[^"'`]{1,80})["'`]""")
_SECRET_RE = re.compile(
    r"""(?i)\b(api[_-]?key|secret|token|password|passwd|bearer|access[_-]?key)\b\s*[:=]\s*["'`]([^"'`\s]{6,120})["'`]"""
)
_COMMENT_HINT_RE = re.compile(
    r"(?i)(?://|/\*)\s*([^\n]{0,160}?\b(?:TODO|FIXME|HACK|debug|internal|admin|flag)\b[^\n]{0,120})"
)


_PRIORITY_WORDS = ("admin", "internal", "flag", "upload", "user", "auth", "login", "token", "api")

def _rank(items: list[str]) -> list[str]:
    def score(item: str) -> int:
        low = item.lower()
        return -sum(1 for word in _PRIORITY_WORDS if word in low)
    return sorted(dict.fromkeys(items), key=score)


def _is_noise_path(path: str) -> bool:
    low = path.lower().split("?")[0]
    if low in ("/", ""):
        return True
    return low.endswith(JSRECON_NOISE_EXT)


def jsrecon(url: str = "") -> str:
    """JS static reconnaissance.

    Fetches the page and its frontend bundles / inline scripts, then
    extracts API paths, parameter names, frontend routes, hard-coded
    secrets, sourceMap URLs, and suspicious comments.

    All fetches are recorded in the traffic ledger (source=jsrecon).
    """
    target = _require_url(url, "jsrecon")

    started = time.perf_counter()
    try:
        status, ctype, html = _safe_fetch(target, source="jsrecon")
    except Exception as exc:
        return _clip(json.dumps({"tool": "jsrecon", "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))

    scripts = _SCRIPT_SRC_RE.findall(html or "")
    inline = _INLINE_SCRIPT_RE.findall(html or "")

    bundles: list[dict] = []
    js_chunks: list[str] = []
    budget = JSRECON_MAX_JSON_CHARS
    stopped_early = False
    for src in scripts[:JSRECON_MAX_BUNDLES]:
        if time.perf_counter() - started > JSRECON_BUDGET:
            stopped_early = True
            break
        abs_url = urljoin(target, src)
        try:
            bstatus, bctype, text = _safe_fetch(abs_url, source="jsrecon")
        except Exception as exc:
            bundles.append({"url": abs_url, "error": f"{type(exc).__name__}: {exc}"})
            continue
        text = text or ""
        truncated = len(text) > JSRECON_MAX_BUNDLE_CHARS
        kept = text[:JSRECON_MAX_BUNDLE_CHARS]
        if budget > 0:
            kept = kept[:budget]
            budget -= len(kept)
            js_chunks.append(kept)
        bundles.append({"url": abs_url, "status": bstatus, "len": len(text), "truncated": truncated})

    for chunk in inline:
        if budget <= 0:
            break
        kept = (chunk or "")[:budget]
        budget -= len(kept)
        js_chunks.append(kept)

    js = "\n".join(js_chunks)
    api_paths = [p for p in _STR_LIT_PATH_RE.findall(js) if not _is_noise_path(p)]
    calls = [f"{fn}({arg})" for fn, arg in _FETCH_CALL_RE.findall(js)][:JSRECON_MAX_PER_KIND * 2]
    params: list[str] = []
    for block in _PARAMS_OBJ_RE.findall(js):
        params.extend(_PARAM_KEY_RE.findall(block))
    params.extend(_SEARCHPARAM_RE.findall(js))
    routes = _ROUTE_PATH_RE.findall(js)
    secrets = [f"{k}={v[:60]}" for k, v in _SECRET_RE.findall(js)]
    maps = _SOURCEMAP_RE.findall(js)
    comments = [c.strip() for c in _COMMENT_HINT_RE.findall(js)]

    payload: dict[str, Any] = {
        "tool": "jsrecon",
        "page": {"status": status, "bytes": len(html or ""),
                 "type": (ctype or "").split(";")[0].strip()[:40],
                 "scripts": len(scripts), "inline": len(inline)},
        "bundles": bundles,
        "api": _rank(api_paths)[:JSRECON_MAX_PER_KIND],
        "api_total": len(set(api_paths)),
        "calls": calls[:JSRECON_MAX_PER_KIND],
        "params": _rank(params)[:JSRECON_MAX_PER_KIND],
        "routes": _rank(routes)[:JSRECON_MAX_PER_KIND],
        "secrets": secrets[:JSRECON_MAX_PER_KIND],
        "sourcemaps": maps[:4],
        "comments": comments[:6],
    }
    if not api_paths and not calls:
        payload["note"] = (
            "no API paths extracted: may be a pure static site or bundle is "
            "obfuscated/encrypted; try route_map crawl first, or probe "
            "suspicious paths directly with http_probe"
        )
    elif payload.get("sourcemaps"):
        payload["note"] = "sourceMap found; pull the .map to reconstruct source, then read line by line"
    else:
        payload["note"] = (
            "probe ranked API paths with http_probe one by one; parameter "
            "names can be used as a custom fuzz wordlist"
        )

    if stopped_early:
        payload["stopped_early"] = True
        payload["note"] = f"budget exceeded ({JSRECON_BUDGET:.0f}s); " + payload.get("note", "")

    text = json.dumps(payload, ensure_ascii=False)
    for key in ("comments", "sourcemaps", "routes", "params", "calls", "api", "bundles"):
        while len(text) > _TOOL_TEXT_MAX and payload.get(key):
            payload[key] = payload[key][:-1]
            text = json.dumps(payload, ensure_ascii=False)
    return _clip(text)


# ---------------------------------------------------------------------------
# 4. http_burst
# ---------------------------------------------------------------------------

MAX_BURST: Final = 24
BURST_TIMEOUT: Final = 15.0
BURST_TOTAL_TIMEOUT: Final = 60.0
BURST_READ_BYTES: Final = 2048
BURST_STORE_BYTES: Final = 64 * 1024
MAX_BURST_GROUPS: Final = 12


def http_burst(
    url: str = "",
    method: str = "POST",
    body: str = "",
    headers_json: str = "",
    count: int = 8,
    values: list[str] | None = None,
    nonce: str = "",
) -> str:
    """Concurrent / batch HTTP requests (pure stdlib threading).

    - values empty: race mode -- same request count times concurrently.
    - values non-empty: batch mode -- one request per value, {v} replaced
      verbatim in url and body.

    Workers connect first, then release together on a Barrier. If any
    worker fails to connect, the barrier is aborted and the whole round
    is discarded.

    All requests are recorded in the traffic ledger (source=http_burst).
    Max 24 requests per call.
    """
    url = _require_url(url, "http_burst")
    netloc = urlparse(url).netloc
    method = (method or "POST").upper()
    if method == "HEAD":
        _fail("http_burst does not support HEAD (no response body, grouping meaningless)")
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        _fail(f"unsupported method: {method}")

    if values is not None and not isinstance(values, list):
        _fail("values must be a list, e.g. [\"alice\", \"bob\"]")
    vals = [str(v) for v in (values or [])]
    if vals:
        if len(vals) > MAX_BURST:
            _fail(f"values max {MAX_BURST}, got {len(vals)}")
        targets = []
        for v in vals:
            u = _require_url(url.replace("{v}", v), "http_burst")
            b = body.replace("{v}", v)
            targets.append((u, b))
        mode = "batch"
    else:
        try:
            n = max(2, min(int(count or MAX_BURST), MAX_BURST))
        except (TypeError, ValueError):
            _fail(f"count must be an integer 2..{MAX_BURST}, got {count!r}")
        targets = [(url, body)] * n
        mode = "race"

    hdrs = _headers_from_json(headers_json, 24)
    if not any(k.lower() == "accept-encoding" for k in hdrs):
        hdrs["Accept-Encoding"] = "identity"
    if not any(k.lower() == "user-agent" for k in hdrs):
        hdrs["User-Agent"] = "ctf-strix/1.2"

    # Snapshot once before the round.  Workers each build their own header
    # dict, so a shared cookie jar would lose keys written concurrently
    # (last-writer-wins).  Cookies set during the round are merged afterwards
    # and returned once, for the next call to pass back explicitly.
    cookie_snapshot = ""
    for name, value in hdrs.items():
        if name.lower() == "cookie":
            cookie_snapshot = value
            break

    results: list[dict | None] = [None] * len(targets)
    barrier = threading.Barrier(len(targets))

    def worker(i: int, u: str, b: str) -> None:
        conn = None
        try:
            parsed = urlparse(u)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    parsed.hostname, parsed.port or 443,
                    timeout=BURST_TIMEOUT, context=ctx,
                )
            else:
                conn = http.client.HTTPConnection(
                    parsed.hostname, parsed.port or 80,
                    timeout=BURST_TIMEOUT,
                )
            conn.connect()
        except Exception as exc:
            results[i] = {"i": i, "error": f"connect failed: {type(exc).__name__}: {exc}"}
            try:
                barrier.abort()
            except Exception:
                pass
            return
        try:
            barrier.wait(timeout=BURST_TIMEOUT)
        except threading.BrokenBarrierError:
            results[i] = {"i": i, "error": "round aborted: a peer failed to connect (retry or lower count)"}
            conn.close()
            return
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        req_hdrs = dict(hdrs)
        if cookie_snapshot and parsed.netloc == netloc:
            req_hdrs["Cookie"] = cookie_snapshot
        t0 = time.perf_counter()
        try:
            body_bytes = b.encode("utf-8") if b else None
            conn.request(method, path, body=body_bytes, headers=req_hdrs)
            resp = conn.getresponse()
            raw = resp.read(BURST_STORE_BYTES)
            results[i] = {
                "i": i,
                "status": resp.status,
                "ms": round((time.perf_counter() - t0) * 1000, 1),
                "body": raw.decode("utf-8", "replace"),
                "set_cookie": resp.headers.get_all("Set-Cookie") or [],
                "mime": resp.getheader("Content-Type") or "",
            }
        except Exception as exc:
            results[i] = {"i": i, "error": f"{type(exc).__name__}: {exc}"}
        finally:
            conn.close()

    threads = [
        (i, threading.Thread(target=worker, args=(i, u, b), daemon=True))
        for i, (u, b) in enumerate(targets)
    ]
    for _i, t in threads:
        t.start()
    deadline = time.time() + BURST_TOTAL_TIMEOUT
    for _i, t in threads:
        t.join(max(0.1, deadline - time.time()))
    for idx in range(len(results)):
        if results[idx] is None:
            results[idx] = {"i": idx, "error": "did not return within deadline"}

    jar: dict[str, str] = {}
    for pair in cookie_snapshot.split(";") if cookie_snapshot else []:
        if "=" in pair:
            key, value = pair.strip().split("=", 1)
            jar[key] = value
    for r in results:
        for raw_cookie in (r or {}).get("set_cookie") or []:
            pair = raw_cookie.split(";", 1)[0]
            if "=" in pair:
                key, value = pair.strip().split("=", 1)
                jar[key] = value
    rec_hdrs = dict(hdrs)
    if cookie_snapshot:
        rec_hdrs["Cookie"] = cookie_snapshot

    for idx, (u, b) in enumerate(targets):
        r = results[idx] or {}
        if "error" in r:
            traffic.record(
                request_id=traffic.ledger().next_id(),
                method=method, url=u,
                req_headers=rec_hdrs, req_body=b,
                phase="BURST_ERROR",
                elapsed=0,
                note=f"http_burst: {r['error']}"[:300],
            )
        else:
            sc = r.get("set_cookie") or []
            body_text = r.get("body") or ""
            traffic.record(
                request_id=traffic.ledger().next_id(),
                method=method, url=u,
                req_headers=rec_hdrs, req_body=b,
                status=r.get("status"),
                resp_headers={"Set-Cookie": "; ".join(sc)} if sc else {},
                resp_body=body_text,
                size=len(body_text),
                elapsed=r.get("ms", 0) / 1000.0,
            )

    ok = failed = 0
    status_counter: dict[int, int] = {}
    times: list[float] = []
    groups: dict[str, dict] = {}
    for r in results:
        r = r or {}
        if "error" in r:
            failed += 1
            continue
        ok += 1
        status_counter[r["status"]] = status_counter.get(r["status"], 0) + 1
        times.append(r["ms"])
        g = groups.setdefault(r["body"][:BURST_READ_BYTES], {
            "count": 0, "i": [], "status": r["status"], "head": r["body"][:120],
        })
        g["count"] += 1
        g["i"].append(r["i"])

    groups_sorted = sorted(groups.values(), key=lambda g: -g["count"])
    shown = groups_sorted[:MAX_BURST_GROUPS]
    if len(groups_sorted) > MAX_BURST_GROUPS:
        tail = groups_sorted[MAX_BURST_GROUPS:]
        collapsed_status: dict = {}
        collapsed_i: list[int] = []
        for g in tail:
            collapsed_status[g["status"]] = collapsed_status.get(g["status"], 0) + g["count"]
            collapsed_i.extend(g["i"])
        shown.append({
            "count": sum(g["count"] for g in tail),
            "status": collapsed_status,
            "i": collapsed_i,
            "head": "",
            "collapsed": len(tail),
        })

    summary: dict[str, Any] = {
        "mode": mode,
        "requested": len(targets),
        "ok": ok,
        "failed": failed,
        "status": status_counter,
        "distinct_bodies": len(groups),
        "groups": shown,
    }
    if times:
        summary["ms"] = {"min": min(times), "max": max(times), "spread": round(max(times) - min(times), 1)}
    if jar:
        summary["cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())[:1000]
    if mode == "batch":
        for g in shown:
            g["v"] = [vals[j] for j in g["i"]]
    if failed:
        summary["errors"] = [r for r in results if r and "error" in r]
    return _clip(json.dumps(summary, ensure_ascii=False))


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

TOOLS: Final = (jwt_forge, authdiff, jsrecon, http_burst)


def _as_async(func):
    """Run a blocking helper off the event loop, keeping its signature."""
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner


def register(register_fn=None) -> list[str]:
    """Register the four web-primitive tools with the strix agent.

    Args:
        register_fn: injection point; defaults to
            ``factory.register_agent_tools``.

    Returns:
        Newly registered names (empty when already present).
    """
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=90)(_as_async(fn)) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]
