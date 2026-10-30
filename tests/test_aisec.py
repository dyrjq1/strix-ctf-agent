"""A.I.G 探测层的回归测试。

每条测试都对应一个**真实出现过的缺陷**，不是为覆盖率凑数：

===== ================================================== ==========================
编号   缺陷                                                对应用例
===== ================================================== ==========================
D1    无 matcher 的块按 2xx 判命中 → 一个靶机报 11 个组件   test_no_matcher_...
D2    version 块被当命中依据 → 幽灵组件                     test_version_block_...
D3    Dify 版本在响应头 X-Version，只读 body 取不到         test_header_version
D4    三个 mock 共用类变量，type_ 被覆盖 → 组件串台          test_each_mock_...
D5    SSRF：urlopen 直接跟 30x 跳到元数据服务               test_redirect_...
D6    正则灾难性回溯 / 超长 body 拖死扫描                   test_regex_bomb
D7    版本段缺失语义错 → 已修复版本被判有漏洞               test_cmp_padding
===== ================================================== ==========================

运行::

    PYTHONPATH=src:vendor/src .venv/bin/python -m pytest tests/test_aisec.py -q
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from ctf_strix.aisec import aig_probe, mock_multi
from ctf_strix.aisec.aig_probe import BlockedTarget, Probe, Rulebook, UrlGuard, match_probe
from ctf_strix.aisec.verrule import cmp_ver, evaluate


# --------------------------------------------------------------- 规则库 fixture

#: 最小规则集：够覆盖「有 matcher / 无 matcher / 版本在 body / 版本在头」四种形态。
_FIXTURE_FP: list[dict[str, Any]] = [
    {
        "component": "gradio",
        "vendor": "gradio",
        "probes": [
            {
                "path": "/",
                "method": "GET",
                "kind": "fp",
                "matchers": [{"type": "body", "value": ["gradio_config"], "negative": False}],
            },
            {
                "path": "/config",
                "method": "GET",
                "kind": "ver",
                "version_regex": r'"version"\s*:\s*"([\d.]+)"',
                "version_group": 1,
                "version_part": "body",
            },
        ],
    },
    {
        "component": "dify",
        "vendor": "langgenius",
        "probes": [
            {
                "path": "/",
                "method": "GET",
                "kind": "fp",
                "matchers": [{"type": "body", "value": ["Dify"], "negative": False}],
            },
            {
                "path": "/",
                "method": "GET",
                "kind": "ver",
                "version_regex": r"([\d.]+)",
                "version_group": 1,
                "version_part": "header",
                "version_header": "x-version",
            },
        ],
    },
    {
        "component": "comfyui",
        "vendor": "comfyanonymous",
        "probes": [
            {
                "path": "/",
                "method": "GET",
                "kind": "fp",
                "matchers": [{"type": "body", "value": ["ComfyUI"], "negative": False}],
            },
            {
                "path": "/system_stats",
                "method": "GET",
                "kind": "ver",
                "version_regex": r'"comfyui_version"\s*:\s*"([\d.]+)"',
                "version_group": 1,
                "version_part": "body",
            },
        ],
    },
    # D1 的载体：只探路径、没有任何 matcher。正确实现必须不产生结果。
    {
        "component": "clickhouse",
        "vendor": None,
        "probes": [{"path": "/", "method": "GET", "kind": "fp"}],
    },
    # D2 的载体：只有版本块，没有 fp 块。正确实现必须整条跳过。
    {
        "component": "ghost",
        "vendor": None,
        "probes": [
            {
                "path": "/",
                "method": "GET",
                "kind": "ver",
                "version_regex": r"APP_VERSION\S*\s*=\s*[\"']([\d.]+)",
                "version_group": 1,
                "version_part": "body",
            }
        ],
    },
]

_FIXTURE_INDEX: dict[str, list[dict[str, Any]]] = {
    "ollama": [
        {
            "file": "vuln/ollama/CVE-2024-37032.yaml",
            "cve": "CVE-2024-37032",
            "severity": "critical",
            "summary": "Ollama path traversal in /api/pull allows arbitrary file write",
            "rule": 'version < "0.1.34"',
        },
        {
            "file": "vuln/ollama/CVE-2024-39719.yaml",
            "cve": "CVE-2024-39719",
            "severity": "high",
            "summary": "Ollama file existence disclosure",
            "rule": 'version < "0.3.0"',
        },
    ],
}


@pytest.fixture()
def rulebook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """把全局 ``_RULES`` 指向临时规则库，避免测试依赖真实上游数据。"""
    (tmp_path / "fingerprints.json").write_text(
        json.dumps(_FIXTURE_FP, ensure_ascii=False), encoding="utf-8"
    )
    (tmp_path / "vuln_index.json").write_text(json.dumps(_FIXTURE_INDEX), encoding="utf-8")
    monkeypatch.setattr(aig_probe, "_RULES", Rulebook(tmp_path))
    return tmp_path


@pytest.fixture()
def mocks() -> Any:
    """启动四个 mock 服务（gradio / dify / comfyui / decoy），用完逐个关掉。

    端口由内核分配：上一条用例没退干净时固定端口会 ``Address already in use``，
    那是测试自身的脆弱，不该算到被测代码头上。
    """
    urls, servers = mock_multi.serve(0)
    yield urls
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _allow(*urls: str) -> UrlGuard:
    """把 mock 地址放进白名单（模拟评测脚本写 CTF_AISEC_ALLOW）。"""
    hosts: set[str] = set()
    for u in urls:
        p = urllib_parse(u)
        hosts.add(f"{p[0]}:{p[1]}")
    return UrlGuard(allow_hosts=hosts)


def urllib_parse(url: str) -> tuple[str, int, str]:
    import urllib.parse

    p = urllib.parse.urlsplit(url)
    return (p.hostname or "", p.port or 80, p.path or "/")


# --------------------------------------------------------------- D1/D2/D3/D4


def test_no_matcher_block_never_matches() -> None:
    """D1：无 matcher 的块不能按 2xx 判命中。

    clickhouse 规则只探 ``/``、没有 matcher。旧实现返回 200 即命中，
    一个 Ollama 靶机上因此同时报出 11 个组件。
    """
    ok = Probe(200, "<html>anything</html>", {})
    assert match_probe({"path": "/", "kind": "fp"}, ok) is False
    assert match_probe({"path": "/", "kind": "fp", "matchers": []}, ok) is False


def test_matcher_and_semantics() -> None:
    """同一 matcher 内多值是「与」，不同 matcher 之间也是「与」。"""
    entry = {
        "matchers": [
            {"type": "body", "value": ["a", "b"], "negative": False},
            {"type": "status", "value": ["200"], "negative": False},
        ]
    }
    assert match_probe(entry, Probe(200, "a and b", {})) is True
    assert match_probe(entry, Probe(200, "only a", {})) is False  # 少一个值
    assert match_probe(entry, Probe(404, "a and b", {})) is False  # status 不符


def test_negative_matcher() -> None:
    """negative 表示取反：404 页才算命中（很多框架的「未授权」就是这个形态）。"""
    entry = {"matchers": [{"type": "body", "value": ["login"], "negative": True}]}
    assert match_probe(entry, Probe(200, "dashboard", {})) is True
    assert match_probe(entry, Probe(200, "please login", {})) is False


def test_version_block_is_not_a_hit_basis(rulebook: Path, mocks: dict[str, str]) -> None:
    """D2：只有版本块、没有 fp 块的组件不能被报出来。

    decoy 页面含 ``APP_VERSION = "9.9.9"``，正好能命中 ghost 的版本正则。
    旧实现把 version 块当命中依据，于是报出「ghost 9.9.9」这个幽灵组件。
    """
    hits = aig_probe.fingerprint(mocks["decoy"], _allow(mocks["decoy"]))
    names = [h["component"] for h in hits]
    assert "ghost" not in names, f"幽灵组件被报出：{names}"
    # decoy 只有版本号，任何组件都不该命中
    assert hits == [], f"decoy 应报 0 个组件，实际 {names}"


def test_each_mock_is_identified_independently(rulebook: Path, mocks: dict[str, str]) -> None:
    """D4：三组件同时在线时各归各位，不串台、不互相污染。"""
    expect = {"gradio": "4.44.1", "dify": "0.6.9", "comfyui": "0.3.27"}
    for kind, want_ver in expect.items():
        url = mocks[kind]
        hits = aig_probe.fingerprint(url, _allow(url))
        names = [h["component"] for h in hits]
        assert kind in names, f"{kind} 未被识别，实际 {names}"
        # 关键：不能把别的组件也报出来
        others = set(names) - {kind}
        assert not others, f"{kind} 靶场误报 {others}"


def test_header_version(rulebook: Path, mocks: dict[str, str]) -> None:
    """D3：Dify 版本只在响应头 X-Version，必须能取到。"""
    url = mocks["dify"]
    hits = aig_probe.fingerprint(url, _allow(url))
    dify = next(h for h in hits if h["component"] == "dify")
    assert dify["version"] == "0.6.9"
    assert dify["confidence"] == "high"


def test_lookup_filters_by_version(rulebook: Path) -> None:
    """CVE 查询按版本约束过滤：旧版本多命中，新版本一条都没有。"""
    old = aig_probe.lookup("ollama", "0.1.29")
    assert {v["cve"] for v in old} == {"CVE-2024-37032", "CVE-2024-39719"}
    # 0.1.34 已修 CVE-2024-37032，只剩后者
    mid = aig_probe.lookup("ollama", "0.1.34")
    assert {v["cve"] for v in mid} == {"CVE-2024-39719"}
    # 0.3.0 两个都已修复
    assert aig_probe.lookup("ollama", "0.3.0") == []


# --------------------------------------------------------------- D5/D6 SSRF


class _Redirector(BaseHTTPRequestHandler):
    """把任何请求 302 到指定地址，用来验证重定向不被跟随。"""

    location = "http://169.254.169.254/latest/meta-data/"

    def log_message(self, *a: object) -> None:  # noqa: ANN002
        return

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_redirect_to_metadata_is_not_followed() -> None:
    """D5：靶机用 302 把请求引向元数据服务时，不能跟随。

    ``urlopen`` 默认跟 30x。只要靶机回 ``Location: http://169.254.169.254/``，
    「已校验的目标」就变成「未校验的元数据服务」——这是 SSRF 最常见的绕过。
    正确行为：返回 3xx 本身，不跟。
    """
    srv = ThreadingHTTPServer(("127.0.0.1", 18410), _Redirector)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        g = UrlGuard(allow_hosts={"127.0.0.1:18410"})
        pr = aig_probe._get("http://127.0.0.1:18410/", g)
        assert pr.status == 302, f"应当停在 302，实际 {pr.status}"
        assert "meta-data" not in pr.body
    finally:
        srv.shutdown()


def test_ssrf_guard_blocks_metadata_and_private() -> None:
    """闸门的硬拒绝项：元数据、回环、IPv4-mapped 绕过、非 http scheme。"""
    g = UrlGuard(allow_hosts={"10.0.0.5:11434"})
    assert g.check("10.0.0.5:11434/api/tags") == "http://10.0.0.5:11434/api/tags"
    for bad in (
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:80/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[::ffff:169.254.169.254]/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "http://10.0.0.5:80/",  # 白名单里没这个端口
        "http://example.com/",  # 有白名单时，白名单外一律拒
    ):
        with pytest.raises(BlockedTarget):
            g.check(bad)


def test_ssrf_guard_allows_listed_private_target() -> None:
    """白名单内的私网目标必须放行：CTF 靶机本身就是私网地址。

    如果先做网段检查再看白名单，合法靶机也会被拦，工具在真实场景直接不可用。
    """
    g = UrlGuard(allow_hosts={"172.16.15.2:31313"})
    assert g.check("http://172.16.15.2:31313/") == "http://172.16.15.2:31313/"


def test_ssrf_guard_default_denies_private() -> None:
    """没有白名单时默认拒绝私网，只放行公网。"""
    g = UrlGuard()
    with pytest.raises(BlockedTarget):
        g.check("http://10.0.0.5:11434/")
    assert g.check("http://8.8.8.8/")


def test_regex_bomb_is_bounded() -> None:
    """D6：灾难性回溯正则 + 超长输入不能把扫描拖死。

    规则来自第三方、body 来自靶机，两者都可控，必须限长。
    """
    bomb = r"(a+)+$"
    huge = "a" * 30_000 + "!"
    probe = Probe(200, huge, {})
    entry = {"matchers": [{"type": "regex", "value": [bomb], "negative": False}]}
    import time

    t0 = time.monotonic()
    match_probe(entry, probe)
    # 限长后是毫秒级；不加限制时 30k 个 a 会让它跑上几分钟
    assert time.monotonic() - t0 < 2.0


def test_illegal_regex_does_not_raise() -> None:
    """规则库里的非法正则必须被隔离，不能中断整个扫描。"""
    entry = {"matchers": [{"type": "regex", "value": ["([unclosed"], "negative": False}]}
    assert match_probe(entry, Probe(200, "x", {})) is False


# --------------------------------------------------------------- D7 版本比较


@pytest.mark.parametrize(
    ("a", "b", "want"),
    [
        ("1.0", "1.0.0", 0),
        ("1.0", "1.0.1", -1),
        ("1.0.0", "1.0.1", -1),
        ("1.10", "1.9", 1),
        ("1.53.1", "1.53.1.dev1", 1),
        ("1.53.1rc1", "1.53.1.dev1", 1),
        ("1.0", "1.0.post1", -1),
        ("v1.2.3", "1.2.3", 0),
    ],
)
def test_cmp_padding(a: str, b: str, want: int) -> None:
    """D7：版本段缺失的语义。

    旧实现遇到对面还有数字段时直接 ``return -1``，于是 ``1.0 < 1.0.0``，
    ``version >= "1.0.0"`` 判 1.0 不满足，把已修复版本报成有漏洞。
    """
    assert cmp_ver(a, b) == want


def test_missing_version_never_matches() -> None:
    """版本未知时版本类规则一律不命中：宁可漏报，不可误报。"""
    assert evaluate('version < "9.9.9"', None) is False
    assert evaluate('version < "9.9.9"', "1.0") is True
    # 无版本约束的规则（逻辑漏洞类）不受影响
    assert evaluate("", None) is True


def test_build_kb_normalizes_probe_path() -> None:
    """路径规范化：模板变量与查询串要去掉，否则请求打不到。"""
    from ctf_strix.aisec.build_kb import norm_probe

    assert norm_probe("/v1/models/{id}") == "/v1/models"
    assert norm_probe("/api/v1?foo={{bar}}") == "/api/v1"
    assert norm_probe("//a//b") == "/a/b"
    assert norm_probe("health") == "/health"
    assert norm_probe(None) is None


def test_build_kb_compact_matcher_escaped_quote() -> None:
    """紧凑写法里的转义引号不能被截断。

    旧实现用 ``"[^"]*"``，遇到 ``body="\\"checks\\": "`` 把值截成 ``\\``，
    于是所有 JSON 页面都命中。
    """
    from ctf_strix.aisec.build_kb import _parse_compact

    out = _parse_compact('body="\\"checks\\": "')
    assert out[0]["value"] == ['"checks": '], out


def test_tools_are_generated_from_docstrings() -> None:
    """工具必须是可直接注册的 function_tool（strix 用 docstring 生成 schema）。"""
    pytest.importorskip("agents", reason="openai-agents SDK 未安装（镜像内必然有）")
    from agents import function_tool

    from ctf_strix.aisec.tools import TOOLS

    for fn in TOOLS:
        t = function_tool(timeout=60)(fn)
        assert t.name == fn.__name__
        # 有参数的工具必须能从 docstring 解析出 Args
        assert fn.__doc__ and "Args:" in fn.__doc__


def test_data_dir_reads_env_at_runtime(rulebook: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """规则目录必须在**调用时**读环境变量，不能在导入期固化。

    评测脚本是「启动进程 → 解析题目端点 → 才写 CTF_AISEC_DATA」的顺序。
    早期版本在模块导入时算好候选列表，于是工具能注册、一调用就报
    「规则库缺失」——单测因为直接替换 _RULES 反而看不到，靠端到端验证才抓到。
    """
    # 一个未显式指定 root 的 Rulebook 应能感知事后注入的路径
    monkeypatch.setenv("CTF_AISEC_DATA", str(rulebook))
    fresh = Rulebook()
    assert fresh.root == rulebook
    assert fresh.available is True


def test_tool_blocks_out_of_scope_target() -> None:
    """工具层要把闸门异常转成可读文本，而不是抛给 agent。

    顺带锁死一个顺序问题：闸门必须在规则库检查**之前**。
    否则越界目标会因为「规则库缺失」提前返回，把安全拒绝说成环境没配好。
    """
    from ctf_strix.aisec.tools import ai_fingerprint

    # 不用 pytest-asyncio：这两条本来就没有并发语义，少一个测试期依赖。
    out = asyncio.run(ai_fingerprint("http://169.254.169.254/latest/meta-data"))
    assert "拒绝" in out, out
