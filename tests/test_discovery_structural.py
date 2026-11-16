"""route_map 的「结构派生候选」：确定性、只取页面词汇、按台账去重。

三类候选（实例 / 子资源 / 参数）都必须能从输入里指出出处：
id 来自已观测的路径或页面，名词与参数名来自页面文字/表单/JS。
任何一条命中流量台账的 URL 都不许再出现。
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
from ctf_strix.discovery import _structural_candidates, route_map  # noqa: E402

COUNTS = {
    "/api/notes/${id}": 1,
    "/api/notes/42": 2,
    "/api/plugins/stats": 3,
}

BLOB = (
    '<a href="/api/notes/43">note</a>'
    ' note_d6e7380c'
    ' <form><input name="q"><input name="limit"></form>'
    ' fetch("/api/notes?sort=desc")'
    ' { "offset": 1 }'
    ' Preview your plugin before submit for review.'
)


@pytest.fixture(autouse=True)
def fresh_ledger(monkeypatch):
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    return ledger


def kinds(rows, kind: str) -> list[str]:
    return [path for k, path in rows if k == kind]


# -- 1. 实例路径：id 取已观测到的具体值，已存在的路径不重复 ----------------

def test_instance_paths_use_observed_ids_only():
    rows = _structural_candidates(COUNTS, BLOB)
    instance = kinds(rows, "实例")
    assert "/api/notes/43" in instance, "href 里的具体 id 要能派生实例路径"
    assert "/api/notes/note_d6e7380c" in instance
    assert "/api/notes/42" not in instance, "已发现的路径不该再进候选"
    assert all(path.startswith("/api/notes/") for path in instance)


def test_no_instance_candidates_without_any_observed_id():
    counts = {"/api/notes": 1, "/api/plugins/stats": 1}
    blob = "<p>Preview your plugin before submit for review.</p>"
    rows = _structural_candidates(counts, blob)
    assert kinds(rows, "实例") == [], "页面没有 id 时不得凭空造实例路径"


# -- 2. 台账去重：已请求过的 URL 一条都不输出 -----------------------------

def test_requested_urls_are_never_emitted():
    requested = {
        "/api/notes/43",
        "http://h.test/api/plugins/preview",
        "http://h.test/api/notes/42?q=1",
    }
    rows = _structural_candidates(COUNTS, BLOB, requested=requested)
    paths = [path for _, path in rows]
    assert "/api/notes/43" not in paths
    assert "/api/plugins/preview" not in paths
    assert "/api/notes/42?q=1" not in paths, "query 也必须按完整 URL 比较"
    assert paths, "只去掉命中的，不该把整节清空"


# -- 3. 总量上限 -----------------------------------------------------------

def test_total_candidates_capped_at_twenty():
    counts = {f"/api/fam{i}/${{id}}": 1 for i in range(6)}
    for i in range(6):
        counts[f"/api/fam{i}/{100 + i}"] = 1
    blob = " ".join(f"zebra{i} token{i}" for i in range(40))
    blob += ' <input name="alpha"> <input name="beta">'
    rows = _structural_candidates(counts, blob)
    assert len(rows) <= 20
    assert len(rows) == 20, "构造了足够多的候选时应打满上限而不是溢出"
    assert len({path for _, path in rows}) == len(rows), "同一路径不许出现两次"


# -- 4. 参数名只能来自页面词汇，不得来自静态字典 --------------------------

def test_param_names_must_be_written_on_the_page():
    rows = _structural_candidates({"/api/search": 1}, '<input name="q">')
    used = [path for path in kinds(rows, "参数")]
    assert used and all("?q=1" in path for path in used)

    # 页面里没写任何字段/查询串/对象键时，参数面必须是空的。
    silent = _structural_candidates({"/api/search": 1}, "<p>Hello world.</p>")
    assert kinds(silent, "参数") == [], "不得从静态大字典里取参数名"


# -- 5. 确定性：同输入两次调用逐字相同 ------------------------------------

def test_same_input_yields_identical_output():
    first = _structural_candidates(COUNTS, BLOB)
    second = _structural_candidates(COUNTS, BLOB)
    assert first == second


def test_module_never_imports_random():
    from ctf_strix import discovery

    source = Path(discovery.__file__).read_text(encoding="utf-8")
    assert not re.search(r"^\s*(?:import|from)\s+random\b", source, re.M)


# -- 6. route_map 集成：新节追加在末尾，原有路径表不变 --------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: bytes, ctype: str = "text/html"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send(
                (
                    '<html><body>'
                    '<a href="/api/notes/42">note</a>'
                    '<span data-note-id="7">draft</span>'
                    '<form action="/api/search"><input name="q"></form>'
                    '<script type="module" src="/app.js"></script>'
                    '</body></html>'
                ).encode()
            )
        elif self.path == "/app.js":
            self._send(
                (
                    'const routes = ["/api/notes/${id}", "/api/plugins/stats"];'
                    'fetch("/api/notes?sort=desc");'
                    'const copy = "Preview your plugin before submit for review";'
                ).encode(),
                "application/javascript",
            )
        else:
            self._send(b"{}", "application/json")


@pytest.fixture()
def site_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_route_map_appends_structural_section(site_url, monkeypatch):
    monkeypatch.setenv("CTF_STRUCTURAL", "1")
    out = asyncio.run(route_map(site_url))
    lines = out.splitlines()

    numbered = [line for line in lines if re.match(r"^\d+\.\s+/", line)]
    assert 0 < len(numbered) <= 30, "原有路径表仍是 <=30 条"

    head = [i for i, line in enumerate(lines) if "结构派生候选" in line]
    assert head, out
    section = lines[head[0]:]
    assert "从未请求" in section[0], "新节必须明确标注从未请求"
    assert any("[实例] /api/notes/7" in line for line in section), section
    assert any("?q=1" in line for line in section), section
    assert section[-1].startswith("next:"), "新节末尾要留一条建议"

    # 本工具的抓取（首页/chunk）已在台账里，它们不该作为候选回显。
    assert not any(re.search(r"\]\s+https?://", line) for line in section)
    assert not any("/app.js" in line for line in section)


def test_structural_section_is_absent_unless_enabled(site_url, monkeypatch):
    """默认关：没开开关时输出必须与旧版逐字节等价（除台账 id 外）。"""
    monkeypatch.delenv("CTF_STRUCTURAL", raising=False)
    out = asyncio.run(route_map(site_url))
    assert "结构派生候选" not in out