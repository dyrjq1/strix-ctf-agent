"""评审 WEB-1 后半段：扫描工具必须能带着登录态和自定义头发请求。

评审报告 WEB-1（P0）：``http_probe`` 已有会话，但 ``method_sweep`` /
``path_variants`` 是裸 ``requests.request``——登录之后一扫就退回匿名，
认证墙后的路径在扫描里结构性不可见；两工具也不接受 header，带 token
的接口扫不了。

契约：
1. http_probe 默认会话登录后，method_sweep 自动带 cookie（登录态延续）；
2. path_variants 同样延续；
3. ``session="off"`` 显式回到匿名（旧行为可复现）；
4. ``headers_json`` 逐请求附加（服务器回显即证明）；
5. 坏的 headers_json 在本地报错，不产生网络请求；
6. 台账记录的是真正发出的头（含 Cookie）。
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import traffic  # noqa: E402
from ctf_strix.discovery import method_sweep  # noqa: E402
from ctf_strix.http_probe import http_probe, reset_sessions  # noqa: E402
from ctf_strix.variants import path_variants  # noqa: E402

#: 数据行 ``r12 401 GET http://…``——行首 id 是台账指针。
_ROW_RE = re.compile(r"^r\d+\s+(\d{3}|ERR)\s")


class _Handler(BaseHTTPRequestHandler):
    """登录发 cookie；/panel 只认 cookie；/echo 回显收到的头。"""

    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        cookie = self.headers.get("Cookie") or ""
        token = self.headers.get("X-Token") or ""
        if path == "/panel":
            if "sid=" in cookie:
                self._send(200, json.dumps({"panel": "seen"}).encode())
            else:
                self._send(401, b'{"error":"login required"}')
        elif path == "/echo":
            self._send(200, json.dumps({"token": token, "cookie": cookie}).encode())
        else:
            self._send(404, b"{}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        path = urlsplit(self.path).path
        if path == "/login":
            self._send(
                302, b"", extra={"Location": "/panel", "Set-Cookie": "sid=u1; Path=/"}
            )
        elif path == "/panel":
            if "sid=" in (self.headers.get("Cookie") or ""):
                self._send(200, b'{"panel":"write"}')
            else:
                self._send(401, b'{"error":"login required"}')
        else:
            self._send(404, b"{}")

    do_OPTIONS = do_GET


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    """空会话表 + 内存台账：会话与台账都有状态，不隔离会互相串。"""
    reset_sessions()
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    yield
    reset_sessions()


@pytest.fixture(scope="module")
def base_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def rows_of(out: str) -> list[str]:
    return [line for line in out.splitlines() if _ROW_RE.match(line)]


def login(url: str) -> str:
    return asyncio.run(http_probe(method="POST", url=f"{url}/login"))


def sweep(base_url: str, **kwargs) -> str:
    defaults = dict(urls="/panel", base_url=base_url, methods="GET,POST")
    defaults.update(kwargs)
    return asyncio.run(method_sweep(**defaults))


def test_method_sweep_carries_login_cookie(base_url):
    """登录态必须延续进批量扫描，否则认证墙后的路径结构性不可见。"""
    login(base_url)
    out = sweep(base_url)
    rows = rows_of(out)
    assert rows, out
    assert any(_ROW_RE.match(r).group(1) == "200" for r in rows), out
    assert "auth:" in out, "输出要明说本批带上了登录态"


def test_method_sweep_without_login_sees_only_the_gate(base_url):
    out = sweep(base_url)
    rows = rows_of(out)
    assert rows
    assert all(_ROW_RE.match(r).group(1) == "401" for r in rows), out


def test_method_sweep_session_off_is_anonymous(base_url):
    """显式 off 时旧行为可复现：登录了也不带。"""
    login(base_url)
    out = sweep(base_url, session="off")
    rows = rows_of(out)
    assert rows
    assert all(_ROW_RE.match(r).group(1) == "401" for r in rows), out


def test_method_sweep_passes_extra_headers(base_url):
    out = sweep(base_url, urls="/echo", methods="GET",
                headers_json='{"X-Token": "tok-123"}')
    assert "tok-123" in out


def test_method_sweep_rejects_bad_headers_json(base_url):
    out = sweep(base_url, urls="/echo", methods="GET", headers_json="{oops")
    assert "headers_json" in out and "JSON" in out


def test_ledger_records_the_cookie_the_sweep_actually_sent(base_url):
    """台账记真正发出的头（含 Cookie），排查不用猜——与 http_probe 同款契约。"""
    login(base_url)
    out = sweep(base_url, methods="GET")
    rid = rows_of(out)[0].split()[0]
    record = traffic.ledger().get(rid)
    assert record is not None
    sent = {k.lower(): v for k, v in (record.req_headers or {}).items()}
    assert "cookie" in sent
    assert "sid=u1" in sent["cookie"]


def test_path_variants_carries_login_cookie(base_url):
    login(base_url)
    out = asyncio.run(
        path_variants(urls="/panel", base_url=base_url, kinds="upper", methods="GET")
    )
    assert "200 GET" in out and "[as-is]" in out, out
    assert "401 GET" not in out, out


def test_path_variants_passes_extra_headers(base_url):
    out = asyncio.run(
        path_variants(urls="/echo", base_url=base_url, kinds="upper", methods="GET",
                      headers_json='{"X-Token": "tok-123"}')
    )
    assert "tok-123" in out


def test_path_variants_rejects_bad_headers_json(base_url):
    out = asyncio.run(
        path_variants(urls="/echo", base_url=base_url, kinds="upper", methods="GET",
                      headers_json="{oops")
    )
    assert "headers_json" in out and "JSON" in out
