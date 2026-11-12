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


class _NoDrainHandler(BaseHTTPRequestHandler):
    """靶机常见形状：不读请求体，直接回 400 并关连接。

    客户端还没把 body 发完就收到 RST（Windows 10053），
    连已经到达的 400 响应也会一起丢掉。实测 body 型请求约 5% 概率撞上，
    无 body 请求 0/300 失败。探测层必须在最后降级为空 body 重试，
    否则"这个路径上有这个方法"这一行证据会被静默删掉。
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_POST(self):
        self.close_connection = True
        self._send(400, b'{"error":"code_b64 required"}')

    def do_GET(self):
        self._send(404, b"{}")

    def do_PUT(self):
        self._send(404, b"{}")

    def do_PATCH(self):
        self._send(404, b"{}")


@pytest.fixture()
def nodrain_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _NoDrainHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_method_sweep_survives_server_that_never_reads_body(nodrain_url):
    # 连跑 12 次：单次有约 5% 概率碰不到 RST，跑多次才能稳定验证。
    for _ in range(12):
        out = run(method_sweep("/api/plugins/preview", base_url=nodrain_url, methods="POST"))
        assert "400 POST" in out, out
        assert "code_b64 required" in out, out
        assert "ERR " not in out, out


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


def test_derived_candidates_use_page_vocabulary() -> None:
    """页面文案里的动词要能拼到已发现的 API 前缀上。

    009 的教训：route_map 只给 stats/featured/categories 三条时，模型会去读
    bundle 原文；给出 ``/api/plugins/preview`` 时它直接就打了那个入口。
    """
    from ctf_strix.discovery import _derived_candidates

    counts = {
        "/api/plugins/stats": 1,
        "/api/plugins/featured": 1,
        "/api/plugins/categories": 1,
    }
    blob = "Submit a plugin for review. Preview how it behaves before publishing."
    got = _derived_candidates(counts, blob)
    assert "/api/plugins/preview" in got
    assert "/api/plugins/submit" in got
    assert all(p not in counts for p in got), "已发现的路径不该混进候选"


def test_derived_candidates_empty_without_api_prefix() -> None:
    """没有 /api 前缀时不要凭空造候选。"""
    from ctf_strix.discovery import _derived_candidates

    assert _derived_candidates({"/login": 2, "/static/x": 1}, "preview submit") == []


def test_discovery_requests_land_in_the_traffic_ledger(base_url):
    """route_map / method_sweep 的请求也必须入账，否则重扫无法被看见。"""
    from ctf_strix import traffic

    before = len(traffic.ledger().items())
    run(route_map(base_url))
    run(method_sweep("/api/plugins/stats", base_url=base_url))
    after = len(traffic.ledger().items())

    assert after > before
    phases = {item.phase for item in traffic.ledger().items()}
    assert "DISCOVERY" in phases
    assert "SWEEP" in phases

