"""P1：http_probe 的观测质量。

核心断言只有一条：**"请求没到达"和"服务器拒绝了"必须可区分**。
009 的第一跑就是死在两者混成一个 000 上。
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.http_probe import http_probe  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静音，测试输出要干净
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Nuxt")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ok":
            self._send(200, b'{"hello":"world"}')
        elif self.path == "/redirect":
            self._send(302, b"", extra={"Location": "/ok"})
        elif self.path == "/big":
            self._send(200, b"x" * 5000, ctype="text/plain")
        elif self.path == "/flag":
            self._send(200, ("FLAG{deadbeef}" + "y" * 6000).encode(), ctype="text/plain")
        elif self.path == "/empty":
            self._send(200, b"")
        else:
            self._send(404, b'{"message":"Page not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if self.path == "/api/plugins/preview":
            self._send(400, b'{"error":"code_b64 required"}')
        else:
            self._send(200, body or b"{}")

    def do_PUT(self):
        self._send(405, b'{"error":"method not allowed"}', extra={"Allow": "GET, POST"})


@pytest.fixture(scope="module")
def base_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def call(**kwargs) -> str:
    return asyncio.run(http_probe(**kwargs))


def test_get_returns_status_body_and_server_header(base_url):
    out = call(url=f"{base_url}/ok")
    assert out.startswith("[HTTP 200] GET")
    assert '"hello":"world"' in out
    assert "x-powered-by=Nuxt" in out


def test_400_body_is_shown_as_schema_hint(base_url):
    """服务端的字段名报错是最高价值的信息，必须原样带出来 + 给出下一步。"""
    out = call(method="POST", url=f"{base_url}/api/plugins/preview",
               headers_json='{"Content-Type": "application/json"}', body="{}")
    assert "[HTTP 400]" in out
    assert "code_b64 required" in out
    assert "schema" in out


def test_405_reveals_allow_header(base_url):
    out = call(method="PUT", url=f"{base_url}/ok")
    assert "[HTTP 405]" in out
    assert "allow=GET, POST" in out


def test_redirect_is_not_followed_by_default(base_url):
    """3xx 指向哪里本身就是信息；自动跟随会把这个事实抹掉。"""
    out = call(url=f"{base_url}/redirect")
    assert "[HTTP 302]" in out
    assert "location=/ok" in out
    assert "hello" not in out


def test_large_body_is_truncated(base_url):
    out = call(url=f"{base_url}/big")
    assert "chars" in out and "body:" in out
    assert len(out) < 2500, "工具输出必须短，否则会挤掉前几轮的结论"


def test_flag_is_not_truncated(base_url):
    """旧总账缺陷 #6：flag 被日志截断等于整题白跑。"""
    out = call(url=f"{base_url}/flag")
    assert "FLAG{deadbeef}" in out
    assert len(out) > 4000, "含 flag 的响应应放宽到 4000 字符"


def test_empty_200_gets_actionable_hint(base_url):
    out = call(url=f"{base_url}/empty")
    assert "[HTTP 200]" in out
    assert "空 body" in out


def test_connection_refused_is_phase_connect_not_000():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    out = call(url=f"http://127.0.0.1:{port}/", timeout_s=3)
    assert out.startswith("[NO RESPONSE]")
    assert "phase=CONNECT" in out
    assert "000" not in out.splitlines()[0]


def test_invalid_url_is_classified():
    out = call(url="not-a-url")
    assert "phase=INVALID_URL" in out


def test_missing_url_is_reported_locally():
    out = call(url="")
    assert out.startswith("[http_probe] 缺少 url")


def test_dns_failure_is_classified():
    out = call(url="http://nonexistent-host-for-ctf.invalid/", timeout_s=8)
    assert "phase=DNS" in out or "phase=CONNECT" in out

def test_bad_headers_json_is_reported():
    """参数写错要在本地立刻说清楚，不能变成一次无效的网络请求。"""
    out = call(url="http://127.0.0.1:9/", headers_json="{not json}")
    assert "headers_json" in out and "JSON" in out
