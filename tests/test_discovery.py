"""P2：发现层（route_map / method_sweep）。

两条断言对应 009 的两个失误：
① 从 bundle 里**提**路径（而不是肉眼读全文）；
② 对已知路径**换方法**（而不是只发 GET）。
"""

from __future__ import annotations

import asyncio
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import traffic  # noqa: E402
from ctf_strix.discovery import method_sweep, route_map  # noqa: E402

#: One rendered row of ``method_sweep``: ``r7    400 POST    http://…``.
#: The id comes first because the row is a pointer into the traffic ledger.
_ROW_RE = re.compile(r"^r\d+\s+(\d{3}|ERR)\s")


@pytest.fixture(autouse=True)
def fresh_ledger(monkeypatch):
    """Each test owns an in-memory ledger.

    ``method_sweep`` records every probe now, and the module-level ledger binds
    its file path at import time -- without this the suite would write
    ``.ctf_traffic.jsonl`` into the repository root.
    """
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    return ledger


def rows_of(out: str) -> list[str]:
    """The result rows, distinguishable from headers and advice lines."""
    return [line for line in out.splitlines() if _ROW_RE.match(line)]

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
    rows = rows_of(out)
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


# -- 一次批量探索只回摘要：完整响应留在台账里 ----------------------------


def test_every_shown_row_resolves_to_the_same_exchange(base_url, fresh_ledger):
    """行首 id 是取回完整响应的 key，不是装饰。"""
    out = run(method_sweep("/api/plugins/preview", base_url=base_url))
    rows = rows_of(out)
    assert rows, out

    for row in rows:
        rid, status = row.split()[:2]
        saved = fresh_ledger.get(rid)
        assert saved is not None, f"{rid} 只在结果里出现，台账却取不回：{row}"
        assert saved.url.endswith("/api/plugins/preview")
        assert str(saved.status) == status
        assert "code_b64" in saved.resp_body, "台账要存完整 body，不是 160 字预览"


def test_combinations_omitted_from_the_display_are_still_in_the_ledger(base_url, fresh_ledger):
    """404 不占行，但"这个组合试过了"必须能读回来，否则会被反复重发。"""
    out = run(method_sweep("/nope/does-not-exist", base_url=base_url))
    assert rows_of(out) == []

    saved = [item for item in fresh_ledger.items() if "/nope/does-not-exist" in item.url]
    assert len(saved) >= 2, "每个组合都要入台账，包括不占显示行的那些"
    # 404 与未实现的 HEAD（501 非 JSON）都被显示层丢掉，台账里都还在。
    assert {item.status for item in saved} <= {404, 501}
    assert 404 in {item.status for item in saved}


def test_a_refused_combination_is_recorded_with_its_phase(fresh_ledger):
    out = run(method_sweep("/api/x", base_url="http://127.0.0.1:1", methods="GET"))

    rows = rows_of(out)
    assert len(rows) == 1 and "ERR" in rows[0], out
    saved = fresh_ledger.get(rows[0].split()[0])
    assert saved is not None
    assert saved.status is None
    assert saved.phase, "传输失败的阶段要落盘，否则同一条死路会被重试"


def test_the_result_ends_with_a_read_back_pointer(base_url):
    """快速路径的契约：回摘要 + 指针，两样都不能少。"""
    for path in ("/api/plugins/preview", "/nope/does-not-exist"):
        out = run(method_sweep(path, base_url=base_url))
        tail = out.splitlines()[-1]
        assert "台账" in tail, out
        assert "traffic_view(" in tail, out
        assert 'traffic_list(url_contains=' in tail, out

