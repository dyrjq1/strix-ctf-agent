"""path_variants: the variant matrix must actually vary the path.

095 regression: DeepSeek stayed on one decoding hypothesis for 29 calls and
never tried uppercase. These tests pin the generation logic and the
"differing vs baseline" filter, without any network.
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
from ctf_strix.variants import (  # noqa: E402
    _VARIANT_KINDS,
    _encode_pct,
    _variant_paths,
    path_variants,
)


@pytest.fixture(autouse=True)
def fresh_ledger(monkeypatch):
    """In-memory ledger per test; nothing lands in the repository root."""
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    return ledger


def test_upper_variant_is_generated():
    """/internal/banner -> /INTERNAL/BANNER. This is the 095 miss."""
    out = dict(_variant_paths("/internal/banner", ("upper",)))
    assert out["upper"] == "/INTERNAL/BANNER"


def test_case_variants_keep_the_hierarchy():
    for kind in ("upper", "lower", "title"):
        for _kind, path in _variant_paths("/api/Plugin/Stats", (kind,)):
            assert path.count("/") == 3, path


def test_pct_keeps_slashes_so_it_hits_a_real_path():
    """Encoding the whole string would collapse it into one bogus segment."""
    assert _encode_pct("a b") == "a%20b"
    assert "/" not in _encode_pct("ab")
    for _kind, path in _variant_paths("/a/b", ("pct",)):
        assert path.startswith("/") and path.count("/") == 2


def test_dot_semicolon_and_slash_variants_differ_from_input():
    for kind in ("dot", "semi", "slash"):
        pairs = _variant_paths("/internal/banner", (kind,))
        assert pairs, kind
        assert pairs[0][1] != "/internal/banner", kind


def test_as_is_is_not_returned_as_a_variant():
    """A no-op variant would double the request count for zero information."""
    for kind in _VARIANT_KINDS:
        assert all(p != "/a" for _k, p in _variant_paths("/a", (kind,)))


def _call(fn, *args, **kwargs):
    """`path_variants` is async (function_tool requires it); await it plainly."""
    return asyncio.run(fn(*args, **kwargs))


def test_unknown_kind_is_rejected_before_any_request():
    out = _call(path_variants, "/a", base_url="https://example.test", kinds="bogus")
    assert "unknown kinds" in out


def test_relative_path_without_base_url_is_rejected():
    out = _call(path_variants, "/a")
    assert "needs base_url" in out


def test_empty_urls_is_rejected():
    assert "urls empty" in _call(path_variants, "   ")

def test_registers_as_a_real_async_tool():
    """A sync handler silently fails registration.

    `agents.function_tool(timeout=...)` only accepts async handlers; a sync one
    raises `ValueError: FunctionTool timeout_seconds is only supported for
    async ... handlers`, which `capabilities._install` records as an error and
    an empty tool list. The tool then simply is not there -- no exception at
    call time, just a missing name in the tool surface. Caught on 2026-10-31
    when `installed["variants"] == []` while everything else looked fine.
    """
    import asyncio
    import inspect

    from agents import function_tool

    from ctf_strix import variants

    assert inspect.iscoroutinefunction(variants.path_variants)

    # Registration itself is the assertion: before the fix this raised
    # ValueError, which capabilities._install turned into variants: [].
    tool = function_tool(timeout=180)(variants.path_variants)
    assert tool.name == "path_variants"
    assert tool.timeout_seconds == 180


def test_register_returns_the_tool_name():
    from ctf_strix import variants

    seen: list[str] = []

    def register_fn(*tools):
        seen.extend(t.name for t in tools)

    names = variants.register(register_fn=register_fn)

    assert names == ["path_variants"]
    assert seen == ["path_variants"]


# -- WEB-7：`methods` 说几个方法就发几个方法，报几条就真发几条 -----------------

_hits: list[tuple[str, str]] = []


class _OkHandler(BaseHTTPRequestHandler):
    """答 200 给任何路径：变体与 baseline 同码同成功，全部进结果行。"""

    def log_message(self, *args):
        pass

    def _ok(self):
        _hits.append((self.command, self.path))
        body = ('{"ok":true,"path":%r}' % self.path).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _ok
    do_POST = _ok
    do_OPTIONS = _ok


@pytest.fixture(scope="module")
def ok_base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_every_listed_method_is_actually_sent(ok_base):
    """081 报告 WEB-7：`methods="GET,POST"` 只发 GET，统计行却写 2 个方法。"""
    _hits.clear()
    out = _call(path_variants, "/probe", base_url=ok_base,
                kinds="upper", methods="GET,POST")

    sent = {method for method, _path in _hits}
    assert sent == {"GET", "POST"}, f"只发了 {sent}，结果行却自称两个方法：\n{out}"


def test_the_reported_request_count_is_the_real_one(ok_base):
    """统计行的数字必须等于线上真实请求数，否则它就是一句自我安慰。"""
    _hits.clear()
    out = _call(path_variants, "/probe", base_url=ok_base,
                kinds="upper", methods="GET,POST")
    head = out.splitlines()[0]

    reported = int(re.search(r"= (\d+) requests", head).group(1))
    assert reported == len(_hits), f"报 {reported} 条，实际 {len(_hits)} 条：\n{head}"
    # 两行额外断言：方法列是实发集合，不是入参原样回显。
    assert re.search(r"= \d+ requests \| differing \d+", head), head


def test_a_row_id_resolves_to_the_stored_exchange(ok_base, fresh_ledger):
    """每行都带台账 id，且这个 id 能取回同一个请求的完整响应。"""
    _hits.clear()
    out = _call(path_variants, "/probe", base_url=ok_base,
                kinds="upper", methods="GET")

    rows = [line for line in out.splitlines() if re.search(r"id=r\d+", line)]
    assert len(rows) == 2, out  # as-is + upper
    for row in rows:
        rid = re.search(r"id=(r\d+)", row).group(1)
        saved = fresh_ledger.get(rid)
        assert saved is not None, f"{rid} 只出现在文本里，台账取不回：{row}"
        assert saved.url.lower().endswith("/probe")
        assert '"ok":true' in saved.resp_body


def test_a_refused_variant_is_recorded_with_its_phase(fresh_ledger):
    """连不上的变体也要入台账——"这条拼法被拒"正是停止重试的那条观测。"""
    out = _call(path_variants, "/a", base_url="http://127.0.0.1:1",
                kinds="upper", methods="GET")

    rows = [line for line in out.splitlines() if line.startswith("ERR ")]
    assert len(rows) == 2, out
    for row in rows:
        saved = fresh_ledger.get(row.rsplit("id=", 1)[-1])
        assert saved is not None
        assert saved.status is None
        assert saved.phase, "传输失败的阶段要落盘，否则同一条死路会被重试"


def test_the_result_ends_with_a_read_back_pointer(ok_base):
    """看完矩阵要先回台账读，而不是把同样的请求再发一遍。"""
    out = _call(path_variants, "/probe", base_url=ok_base, kinds="upper")
    last = out.splitlines()[-1]
    assert "traffic_view(" in last
    assert "traffic_list(url_contains=" in last
