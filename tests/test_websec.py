"""websec: authdiff / jsrecon / traffic_diff -- copied logic must behave.

The authdiff and jsrecon logic is reused (with the other team's consent,
2026-11-17) from ctfy_project's ``tools_websec.py``; the transport layer was
rewritten to this repo's conventions.  These tests pin the contract that
matters for the merge:

* authdiff: one call sends baseline + anonymous + bypass-header variants, and
  the verdict names the mechanism that actually leaked;
* jsrecon: bundle and inline JS are read once and the API surface comes back
  ranked;
* traffic_diff: two ledger rows compare without any new request;
* registration and the probe-tool surface agree with the new names.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import traffic  # noqa: E402
from ctf_strix.websec import (  # noqa: E402
    _path_variants,
    authdiff,
    jsrecon,
)


@pytest.fixture(autouse=True)
def fresh_ledger(monkeypatch):
    """In-memory ledger per test; nothing lands in the repository root."""
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    return ledger


@pytest.fixture(autouse=True)
def clean_sessions():
    """http_probe sessions are process state; a login in one test must not
    make the next test's "anonymous" variant carry a cookie."""
    from ctf_strix import http_probe

    http_probe.reset_sessions()
    yield
    http_probe.reset_sessions()


def _call(fn, *args, **kwargs):
    """Tools are async (function_tool requires it); await them plainly."""
    return asyncio.run(fn(*args, **kwargs))


# ------------------------------------------------------------------ server

class _AuthHandler(BaseHTTPRequestHandler):
    """/login sets a cookie; /data gates on it and trusts X-Admin; /open does
    not check anything -- the three verdicts authdiff can name."""

    def log_message(self, *args):
        pass

    def _send(self, status: int, body: str, headers: dict | None = None):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/login":
            self._send(200, '{"ok":true}', {"Set-Cookie": "sid=abc123"})
        elif self.path == "/data":
            if self.headers.get("X-Admin") == "true":
                self._send(200, '{"admin":true,"users":["a","b"]}')
            elif self.headers.get("Cookie"):
                self._send(200, '{"data":"secret"}')
            else:
                self._send(403, '{"error":"login required"}')
        elif self.path == "/token":
            # Token-gated endpoint: a Bearer header works, a cookie does not.
            if self.headers.get("Authorization"):
                self._send(200, '{"via":"token"}')
            else:
                self._send(403, '{"error":"token required"}')
        elif self.path == "/glitch":
            # A bypass header that *changes* the answer but to an error page:
            # "changed but non-2xx" must not be sold as a bypass hit.
            if self.headers.get("X-Admin") == "true":
                self._send(500, '{"error":"boom"}')
            else:
                self._send(200, '{"ok":true}')
        elif self.path == "/open":
            self._send(200, '{"public":"info"}')
        else:
            self._send(404, '{"error":"not found"}')


@pytest.fixture(scope="module")
def auth_base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def _login(base: str):
    """Seed http_probe's session jar (the autouse fixture clears cookies
    between tests, so every test logs in again for its own baseline)."""
    from ctf_strix.http_probe import http_probe as probe

    return _call(probe, method="GET", url=f"{base}/login")


# ---------------------------------------------------------------- authdiff

def test_authdiff_names_the_bypass_header_that_leaked(auth_base):
    """bypass:X-Admin must appear in the verdicts -- that is the actionable
    part of the tool, not the row list."""
    _login(auth_base)
    out = _call(authdiff, url=f"{auth_base}/data", variants="anon,bypass")
    data = json.loads(out)
    joined = "；".join(data["verdicts"])
    assert "鉴权生效" in joined, data["verdicts"]
    assert "bypass:X-Admin" in joined, data["verdicts"]
    # The row that changed is marked not-same against the authed baseline.
    by_label = {row["label"]: row for row in data["rows"]}
    assert by_label["anon"]["same"] is False
    assert by_label["bypass:X-Admin"]["same"] is False


def test_authdiff_flags_an_unauthenticated_endpoint(auth_base):
    """Same body with and without the session cookie -> 疑似未鉴权."""
    _login(auth_base)
    out = _call(authdiff, url=f"{auth_base}/open", variants="anon")
    data = json.loads(out)
    joined = "；".join(data["verdicts"])
    assert "疑似未鉴权" in joined, data["verdicts"]
    assert data["rows"][0]["label"] == "authed"


def test_authdiff_baseline_refused_is_not_anonymous_readable(auth_base):
    """S2：基线 403 时 anon 与基线相同只说明两者都被拒——不得报「匿名可读
    /不需要登录」这种反向结论，必须先修基线。"""
    out = _call(authdiff, url=f"{auth_base}/data", variants="anon",
                session="off")
    data = json.loads(out)
    joined = "；".join(data["verdicts"])
    assert "基线不可读" in joined, data["verdicts"]
    assert "不需要登录" not in joined, data["verdicts"]
    assert "匿名可读" not in joined, data["verdicts"]


def test_authdiff_baseline_404_is_not_anonymous_readable(auth_base):
    """基线 404（路径不存在）同样没有对照意义（variants.py 的 404 先例）。"""
    _login(auth_base)
    out = _call(authdiff, url=f"{auth_base}/nope", variants="anon")
    data = json.loads(out)
    assert "基线不可读" in "；".join(data["verdicts"]), data["verdicts"]


def test_authdiff_public_endpoint_without_login_says_so(auth_base):
    """基线 2xx 且 jar 无 cookie：anon 相同才允许「不需要登录」的结论。"""
    out = _call(authdiff, url=f"{auth_base}/open", variants="anon",
                session="off")
    data = json.loads(out)
    joined = "；".join(data["verdicts"])
    assert "不需要登录" in joined, data["verdicts"]


def test_authdiff_anon_strips_model_supplied_credentials(auth_base):
    """S1：headers_json 里带 Authorization 时，anon 变体必须剥掉它——
    否则"匿名"请求其实带凭据，会得出「匿名可读」的反向结论。"""
    out = _call(authdiff, url=f"{auth_base}/token", variants="anon",
                session="off",
                headers_json='{"Authorization": "Bearer tok-123"}')
    data = json.loads(out)
    by_label = {row["label"]: row for row in data["rows"]}
    assert by_label["authed"]["status"] == 200, by_label
    assert by_label["anon"]["status"] == 403, by_label
    joined = "；".join(data["verdicts"])
    assert "鉴权生效" in joined, data["verdicts"]
    assert "匿名可读" not in joined, data["verdicts"]


def test_authdiff_changed_but_non_2xx_is_not_a_bypass_hit(auth_base):
    """bypass 头把 200 打成 500：是「改变但非 2xx」，不是疑似绕过——
    不能引导模型拿一个错误页去复验。"""
    out = _call(authdiff, url=f"{auth_base}/glitch", variants="bypass",
                session="off")
    data = json.loads(out)
    joined = "；".join(data["verdicts"])
    assert "非 2xx" in joined, data["verdicts"]
    assert "疑似生效" not in joined, data["verdicts"]


def test_authdiff_rejects_destructive_methods(auth_base):
    """写方法不参与对照（重放放大 6~13 次的破坏性请求）。"""
    assert "method 非法" in _call(authdiff, url=f"{auth_base}/data",
                                  method="DELETE")


def test_authdiff_output_stays_valid_json_when_capped(auth_base, monkeypatch):
    """输出超限时按行裁列表而不是硬切字符串——模型拿到一段坏 JSON 比少几行
    行更糟（authdiff 原先没有 jsrecon 那套裁剪兜底）。"""
    from ctf_strix import websec as _websec

    _login(auth_base)
    monkeypatch.setattr(_websec, "TOOL_TEXT_MAX", 900)
    out = _call(authdiff, url=f"{auth_base}/data", variants="anon,bypass,path")
    assert len(out) <= 960, len(out)
    data = json.loads(out)
    assert data["rows"] and data["verdicts"], data


def test_authdiff_rows_carry_the_ledger_id(auth_base):
    """S3：每行回传台账 id，traffic_diff 才能对着具体两条记录比（rows
    的 url 全相同时，traffic_list 分不清哪条是哪个变体）。"""
    _login(auth_base)
    out = _call(authdiff, url=f"{auth_base}/data", variants="anon")
    data = json.loads(out)
    ids = [row["id"] for row in data["rows"] if "error" not in row]
    assert ids and all(isinstance(i, str) and i for i in ids)
    assert data["baseline"]["id"] == ids[0]
    # The ids are real ledger rows: diffing two of them works end to end.
    assert "diff" in traffic.traffic_diff(ids[0], ids[1]) or "identical" in \
        traffic.traffic_diff(ids[0], ids[1])


def test_authdiff_path_variants_generate_rewrites():
    """The copied path-rewrite set must actually rewrite the path."""
    out = _path_variants("https://h.test/api/users")
    labels = [label for label, _url in out]
    assert "upper" in labels
    assert "semicolon" in labels
    for label, url in out:
        assert url != "https://h.test/api/users", label


def test_authdiff_rejects_bad_input_before_any_request():
    assert "需要 url" in _call(authdiff, url="")
    assert "未知变体" in _call(authdiff, url="https://x.test/", variants="bogus")
    assert "method 非法" in _call(authdiff, url="https://x.test/", method="BREW")
    assert "不是合法 JSON" in _call(authdiff, url="https://x.test/",
                                     headers_json="{bad")


def test_authdiff_records_every_variant_in_the_ledger(auth_base, fresh_ledger):
    """A refused or anonymous variant is an observation; losing it is how the
    same dead end gets retried."""
    _login(auth_base)
    _call(authdiff, url=f"{auth_base}/data", variants="anon,bypass")
    rows = fresh_ledger.items()
    # The login itself is a recorded exchange (that is the ledger working,
    # not noise); authdiff then adds authed + anon + 4 bypass headers = 6.
    data_rows = [r for r in rows if r.url.endswith("/data")]
    assert len(data_rows) == 6, [r.url for r in rows]
    assert any(r.url.endswith("/login") for r in rows)
    assert any(r.status == 403 for r in data_rows), "the anonymous 403 must land"


# ----------------------------------------------------------------- jsrecon

_PAGE = (
    b"<html><head><script src='/app.js'></script></head><body>"
    b"<script>fetch('/api/admin/stats');const apiKey='sk_1234567890abc';"
    b"</script></body></html>"
)
_APP_JS = (
    b"const r = {path: '/admin', component: Home};"
    b"u.searchParams.set('token', t);"
    b"fetch('/api/internal/export');"
    b"// TODO: remove debug flag endpoint before prod"
)


class _JsHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            raw, ctype = _PAGE, "text/html"
        elif self.path == "/app.js":
            raw, ctype = _APP_JS, "application/javascript"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture(scope="module")
def js_base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _JsHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_jsrecon_extracts_and_ranks_the_api_surface(js_base):
    out = _call(jsrecon, url=f"{js_base}/")
    data = json.loads(out)
    # String-literal API paths from both the bundle and the inline script.
    assert "/api/admin/stats" in data["api"], data["api"]
    assert "/api/internal/export" in data["api"], data["api"]
    # admin/internal rank ahead of plain paths: the first entries are the
    # interesting ones for a CTF.
    first = data["api"][0]
    assert "admin" in first or "internal" in first, data["api"]
    # Hardcoded key-like strings come back masked to a prefix.
    assert data["secrets"], data
    assert data["secrets"][0].startswith("apiKey=")
    # Front-end route and query parameter names.
    assert "/admin" in data["routes"], data["routes"]
    assert "token" in data["params"], data["params"]
    assert data["page"]["scripts"] == 1
    assert data["page"]["inline"] == 1


def test_jsrecon_records_page_and_bundle_fetches(js_base, fresh_ledger):
    _call(jsrecon, url=f"{js_base}/")
    urls = {r.url for r in fresh_ledger.items()}
    assert any(u.endswith("/") for u in urls), urls
    assert any(u.endswith("/app.js") for u in urls), urls


def test_jsrecon_rejects_missing_url():
    assert "需要 url" in _call(jsrecon, url="")


_CROSS_PAGE = (
    b"<html><head>"
    b"<script src='http://169.254.169.254/latest/meta.js'></script>"
    b"<script src='/app.js'></script>"
    b"<script src='/app.js'></script>"
    b"</head></html>"
)


class _JsCrossHandler(BaseHTTPRequestHandler):
    """Page content naming a third-party absolute URL and a duplicate local
    script: page content is untrusted input, neither should be fetched twice
    nor fetched at all."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            raw = _CROSS_PAGE
        elif self.path == "/app.js":
            raw = b"fetch('/api/local/thing');"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path == "/" else
                         "application/javascript")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture(scope="module")
def js_cross_base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _JsCrossHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_jsrecon_skips_cross_origin_and_duplicate_scripts(js_cross_base,
                                                          fresh_ledger):
    out = _call(jsrecon, url=f"{js_cross_base}/")
    data = json.loads(out)
    assert data["skipped_cross_origin"] == 1, data
    urls = [b["url"] for b in data["bundles"]]
    assert urls == [f"{js_cross_base}/app.js"], urls
    # The metadata endpoint was never even attempted.
    assert all("169.254" not in r.url for r in fresh_ledger.items()), \
        [r.url for r in fresh_ledger.items()]


class _JsRedirectHandler(BaseHTTPRequestHandler):
    """/old 302 -> /app/ ; /app/ references app.js, which must resolve against
    the *final* page URL (/app/app.js), not the original target."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/old":
            self.send_response(302)
            self.send_header("Location", "/app/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/app/":
            raw = b"<html><script src='app.js'></script></html>"
            ctype = "text/html"
        elif self.path == "/app/app.js":
            raw = b"fetch('/api/after/redirect');"
            ctype = "application/javascript"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture(scope="module")
def js_redirect_base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _JsRedirectHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_jsrecon_resolves_relative_src_after_redirect(js_redirect_base):
    """302 之后相对 src 按最终页面 URL 解析：/old 页的 app.js 是
    /app/app.js，不是根下的 /app.js。"""
    out = _call(jsrecon, url=f"{js_redirect_base}/old")
    data = json.loads(out)
    urls = [b["url"] for b in data["bundles"]]
    assert urls == [f"{js_redirect_base}/app/app.js"], urls
    assert "/api/after/redirect" in data["api"], data["api"]


def test_jsrecon_unreachable_page_returns_a_readable_error():
    """首屏连接失败给 [jsrecon] 可读报错，不是裸异常甩给 SDK。"""
    out = _call(jsrecon, url="http://127.0.0.1:9/")
    assert out.startswith("[jsrecon]"), out
    assert "不可达" in out, out


# ------------------------------------------------------------ traffic_diff

def test_traffic_diff_shows_the_changed_lines(fresh_ledger):
    traffic.record(request_id="r1", method="GET", url="https://x.test/a",
                   resp_body="alpha\nbeta\ngamma\n", status=200)
    traffic.record(request_id="r2", method="GET", url="https://x.test/a",
                   resp_body="alpha\nBETA\ngamma\n", status=200)
    out = traffic.traffic_diff("r1", "r2")
    assert "+1 -1" in out, out
    assert "-beta" in out and "+BETA" in out, out
    assert "[traffic] diff r1(200) vs r2(200)" in out


def test_traffic_diff_identical_bodies_say_so(fresh_ledger):
    traffic.record(request_id="r1", method="GET", url="https://x.test/a",
                   resp_body="same\n", status=200)
    traffic.record(request_id="r2", method="GET", url="https://x.test/b",
                   resp_body="same\n", status=200)
    out = traffic.traffic_diff("r1", "r2")
    assert "line-identical" in out, out


def test_traffic_diff_unknown_id_names_what_exists(fresh_ledger):
    traffic.record(request_id="r1", method="GET", url="https://x.test/a",
                   resp_body="x\n", status=200)
    out = traffic.traffic_diff("r1", "r99")
    assert "no record 'r99'" in out
    assert "r1" in out


def test_traffic_diff_same_id_twice_is_rejected(fresh_ledger):
    traffic.record(request_id="r1", method="GET", url="https://x.test/a",
                   resp_body="x\n", status=200)
    assert "same exchange" in traffic.traffic_diff("r1", "r1")


def test_traffic_diff_empty_bodies_is_reported_not_crashed(fresh_ledger):
    traffic.record(request_id="r1", method="GET", url="https://x.test/a",
                   status=304)
    traffic.record(request_id="r2", method="GET", url="https://x.test/b",
                   status=304)
    assert "empty" in traffic.traffic_diff("r1", "r2")


# ------------------------------------------------------ wiring and surface

def test_tools_are_async_and_register_by_name():
    """A sync handler silently fails registration (see test_variants)."""
    from agents import function_tool

    from ctf_strix import websec

    for fn in (authdiff, jsrecon):
        assert inspect.iscoroutinefunction(fn)
        tool = function_tool(timeout=120)(fn)
        assert tool.name in ("authdiff", "jsrecon")

    seen: list[str] = []

    def register_fn(*tools):
        seen.extend(t.name for t in tools)

    assert websec.register(register_fn=register_fn) == ["authdiff", "jsrecon"]
    assert seen == ["authdiff", "jsrecon"]


def test_traffic_diff_registers_with_the_other_traffic_tools():
    from ctf_strix import traffic

    seen: list[str] = []

    def register_fn(*tools):
        seen.extend(t.name for t in tools)

    assert traffic.register(register_fn=register_fn) == [
        "traffic_list", "traffic_view", "traffic_diff"]
    assert seen == ["traffic_list", "traffic_view", "traffic_diff"]


def test_new_names_join_the_probe_surface():
    """authdiff and jsrecon reach the target; the guards must see them.  A
    read-only diff over stored rows does not, and counting it would be noise."""
    from ctf_strix import probe_surface

    assert probe_surface.is_probe_tool("authdiff")
    assert probe_surface.is_probe_tool("jsrecon")
    assert not probe_surface.is_probe_tool("traffic_diff")


def test_catalogue_offers_the_new_tools_to_web_only():
    from ctf_strix import catalogue

    web_names = catalogue.registered_names("web")
    assert {"authdiff", "jsrecon", "traffic_diff"} <= web_names
    for kind in ("file", "tcp"):
        kind_names = catalogue.registered_names(kind)
        for name in ("authdiff", "jsrecon", "traffic_diff"):
            assert name not in kind_names, f"{kind} would pay for {name}"


def test_summaries_stay_one_line():
    from ctf_strix import catalogue

    for name in ("authdiff", "jsrecon", "traffic_diff"):
        line = catalogue.describe(name)
        assert line and len(line) <= 180, line
