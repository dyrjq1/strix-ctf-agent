"""P2：发现层（route_map / method_sweep）。

两条断言对应 009 的两个失误：
① 从 bundle 里**提**路径（而不是肉眼读全文）；
② 对已知路径**换方法**（而不是只发 GET）。
"""

from __future__ import annotations

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.discovery import method_sweep, route_map  # noqa: E402

APP_JS = r'''
import {x} from "/_nuxt/other.js";
const a = fetch("/api/plugins/stats");
const b = $fetch("/api/plugins/preview");
const c = "/assets/logo.png";
const d = "/_nuxt/chunk-abc.js";
export const routes = ["/api/plugins/featured", "/auth/login"];
'''

VENDOR_JS = r'''
export const q = () => fetch("/api/plugins/stats");
export const r = "/api/plugins/categories";
'''


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ctype="application/javascript", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            html = (
                '<html><head>'
                '<script type="module" src="/_nuxt/app.js"></script>'
                '<link rel="modulepreload" href="/_nuxt/vendor.js">'
                '<script src="https://cdn.example.com/analytics.js"></script>'
                '</head></html>'
            ).encode()
            self._send(200, html, ctype="text/html")
        elif self.path == "/_nuxt/app.js":
            self._send(200, APP_JS.encode())
        elif self.path == "/_nuxt/vendor.js":
            self._send(200, VENDOR_JS.encode())
        elif self.path == "/api/plugins/stats":
            self._send(200, b'{"plugins_listed":84}', ctype="application/json")
        else:
            self._send(404, b'{"message":"Page not found"}', ctype="application/json")

    def do_POST(self):
        if self.path == "/api/plugins/preview":
            self._send(400, b'{"error":"code_b64 required"}', ctype="application/json")
        elif self.path == "/api/plugins/stats":
            self._send(200, b"{}", ctype="application/json")
        else:
            self._send(404, b"{}", ctype="application/json")

    def do_PATCH(self):
        self._send(404, b"{}", ctype="application/json")

    def do_PUT(self):
        if self.path == "/api/locked":
            self._send(405, b"{}", ctype="application/json", extra={"Allow": "GET, POST"})
        else:
            self._send(404, b"{}", ctype="application/json")


@pytest.fixture(scope="module")
def base_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def run(coro) -> str:
    return asyncio.run(coro)


def test_route_map_extracts_api_paths_and_skips_assets(base_url):
    out = run(route_map(base_url))
    assert "[route_map]" in out
    assert "/api/plugins/stats" in out
    assert "/api/plugins/preview" in out
    assert "/auth/login" in out
    assert "_nuxt/chunk-abc" not in out, "构建产物不是路由"
    assert "logo.png" not in out
    assert "chunks 2/2" in out


def test_route_map_ranks_repeated_path_first(base_url):
    out = run(route_map(base_url))
    first = [l for l in out.splitlines() if l[:1].isdigit()][0]
    assert "/api/plugins/stats" in first
    assert "x2" in first


def test_route_map_rejects_url_without_scheme():
    assert run(route_map("127.0.0.1:8000")) .startswith("[route_map] base_url 必须带 scheme")


def test_method_sweep_finds_undocumented_post(base_url):
    out = run(method_sweep("/api/plugins/preview", base_url=base_url))
    assert "400 POST" in out
    assert "code_b64 required" in out
    assert "字段名" in out, "拿到校验错误要直接提示按字段名构造 body"


def test_method_sweep_omits_404_noise(base_url):
    out = run(method_sweep("/nope/does-not-exist", base_url=base_url))
    rows = [l for l in out.splitlines() if l[:3] in {"200", "302", "400", "401", "403",
                                                     "404", "405", "500", "501"} or l.startswith("ERR ")]
    assert rows == [], f"404 应当全部省略，却回报了：{rows}"
    assert "有信息量 0 条" in out


def test_method_sweep_keeps_405_only_with_allow(base_url):
    out = run(method_sweep("/api/locked", base_url=base_url, methods="PUT"))
    assert "405" in out
    assert "allow=GET, POST" in out


def test_method_sweep_requires_base_url_for_relative_path():
    out = run(method_sweep("/api/x"))
    assert "需要 base_url" in out


def test_method_sweep_rejects_illegal_method():
    out = run(method_sweep("/api/x", base_url="http://127.0.0.1:1", methods="TRACE"))
    assert "没有合法方法" in out


def test_method_sweep_accepts_multiline_input(base_url):
    out = run(method_sweep("/api/plugins/stats\n/api/plugins/preview", base_url=base_url))
    assert "2 路径" in out
    assert "/api/plugins/stats" in out and "/api/plugins/preview" in out

def test_route_map_rejects_bundle_rereading_at_the_top(base_url):
    """提示语放末尾没用：模型读完列表就动手了，不会回头读最后一行。"""
    out = run(route_map(base_url))
    head = out.splitlines()[:3]
    assert any("不要再下载或阅读 bundle" in line for line in head), head
