"""W6：http_probe 的会话——登录态必须活到下一次调用。

用户报告 §5 P0-2：``http_probe`` 原本是裸 ``requests.request``，注册/登录
返回的 ``Set-Cookie`` 当场蒸发，于是「登录 → 打 /admin」的所有多步题
（越权、盲注、CSRF token）在第一步之后全部退回匿名访客。

这一组用例把契约钉在 5 件事上：
1. 默认 ``session="auto"``：同 host 的下一次调用自动带 cookie；
2. ``session="off"``：一个字节都不留（旧行为仍可复现）；
3. 具名会话（``alice`` / ``bob``）：互不覆盖，双账号越权才做得成；
4. ``cookies=``：只作用于本次请求，不写回会话；
5. 会话按 scheme+host+port 分桶：换实例/换题不串味。

外加一条台账断言：``req_headers`` 里必须有真正发出去的 Cookie 头，
否则排查时又要靠猜。
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import traffic  # noqa: E402
from ctf_strix.http_probe import http_probe, reset_sessions  # noqa: E402

SESSION_COOKIE = "sid=abc123"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静音
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        path = urlsplit(self.path).path
        if path == "/admin":
            match = re.search(r"sid=([A-Za-z0-9]+)", cookie)
            if match:
                self._send(200, json.dumps({"admin": True, "sid": match.group(1)}).encode())
            else:
                self._send(401, b'{"error":"login required"}')
        elif path == "/ua":
            ua = self.headers.get("User-Agent") or ""
            self._send(200, json.dumps({"ua": ua}).encode())
        elif path == "/ok":
            self._send(200, b'{"hello":"world"}')
        else:
            self._send(404, b'{"message":"Page not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        parts = urlsplit(self.path)
        if parts.path == "/login":
            # /login?as=alice → sid=alice；不带 as 就是默认账号。
            who = (parse_qs(parts.query).get("as") or ["abc123"])[0]
            self._send(
                302,
                b"",
                extra={"Location": "/admin", "Set-Cookie": f"sid={who}; Path=/"},
            )
        else:
            self._send(404, b'{"message":"Page not found"}')


@pytest.fixture(autouse=True)
def _fresh_sessions():
    """每条用例从空会话表开始；会话有状态，不隔离就会互相串 cookie。"""
    reset_sessions()
    yield
    reset_sessions()


def _serve() -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def base_url():
    srv = _serve()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(scope="module")
def other_base_url():
    """同机不同端口的第二个靶机：用来证明会话按端口分桶。"""
    srv = _serve()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def call(**kwargs) -> str:
    return asyncio.run(http_probe(**kwargs))


def login(url: str, who: str = "", **kwargs) -> str:
    suffix = f"?as={who}" if who else ""
    return call(method="POST", url=f"{url}/login{suffix}", **kwargs)


def admin(url: str, **kwargs) -> str:
    return call(url=f"{url}/admin", **kwargs)


def test_login_cookie_carries_to_next_call(base_url):
    """本文件存在的理由：登录之后不许再是匿名访客。"""
    out = login(base_url)
    assert "[HTTP 302]" in out
    assert "jar: sid=abc123" in out, "登录响应应展示已进 jar 的 cookie"

    after = admin(base_url)
    assert "[HTTP 200]" in after
    assert '"admin": true' in after


def test_login_hint_points_at_location(base_url):
    """302+Set-Cookie 是最常见的登录形态，提示要说清下一步打哪里。"""
    out = login(base_url)
    assert "next:" in out
    assert "会话" in out
    assert "/admin" in out
    assert "别重发同一个请求" in out


def test_session_off_keeps_nothing(base_url):
    """旧行为仍可复现：off 时 Set-Cookie 当场丢弃，且提示要明说。"""
    out = login(base_url, session="off")
    assert "Set-Cookie 不会保留" in out
    assert "jar:" not in out

    after = admin(base_url, session="off")
    assert "[HTTP 401]" in after


def test_named_sessions_do_not_overwrite_each_other(base_url):
    """双账号越权：alice 的登录态不能被 bob 顶掉。

    靶机把登录身份写进 sid 并在 /admin 回显，所以"各自还在"是可断言的事实，
    不是"两边都 200"这种分不清谁是谁的弱证据。
    """
    login(base_url, who="alice", session="alice")
    login(base_url, who="bob", session="bob")

    alice = admin(base_url, session="alice")
    bob = admin(base_url, session="bob")
    assert '"sid": "alice"' in alice
    assert '"sid": "bob"' in bob


def test_auto_session_is_per_port(other_base_url, base_url):
    """不同端口的实例是不同的靶机，不能共享 cookie。"""
    login(base_url)
    assert "[HTTP 200]" in admin(base_url)
    assert "[HTTP 401]" in admin(other_base_url)

    login(other_base_url)
    assert "[HTTP 200]" in admin(other_base_url)
    assert "[HTTP 200]" in admin(base_url)


def test_cookies_argument_is_per_request_only(base_url):
    """临时注入一个 cookie 看效果，但不该污染后续请求。"""
    out = admin(base_url, cookies=SESSION_COOKIE)
    assert "[HTTP 200]" in out

    after = admin(base_url)
    assert "[HTTP 401]" in after, "cookies= 只作用于本次请求，不写回会话"


def test_cookies_argument_accepts_json(base_url):
    out = admin(base_url, cookies='{"sid": "abc123"}')
    assert "[HTTP 200]" in out


def test_bad_cookies_argument_is_reported_locally(base_url):
    """参数写错要在本地说清楚，不能变成一次无效的网络请求。"""
    out = call(url=f"{base_url}/admin", cookies="sid")
    assert "cookies 解析失败" in out
    assert "name=value" in out


def test_reset_sessions_drops_login(base_url):
    login(base_url)
    keys = reset_sessions()
    assert any(k.startswith("auto:") for k in keys)
    assert "[HTTP 401]" in admin(base_url)


def test_ledger_records_the_cookie_actually_sent(base_url):
    """台账记的是真正发出去的头（含 Cookie），排查不用猜。"""
    login(base_url)
    out = admin(base_url)
    rid = re.search(r"id=(r\d+)", out).group(1)
    record = traffic.ledger().get(rid)
    assert record is not None
    sent = {k.lower(): v for k, v in record.req_headers.items()}
    assert "cookie" in sent
    assert SESSION_COOKIE in sent["cookie"]


def test_session_sends_browser_user_agent(base_url):
    """``python-requests/x.y`` 常被 WAF/靶机直接拦；会话路径统一成浏览器 UA。"""
    out = call(url=f"{base_url}/ua")
    assert "Mozilla/5.0" in out and "Chrome/124" in out

    stateless = call(url=f"{base_url}/ua", session="off")
    assert "python-requests" in stateless