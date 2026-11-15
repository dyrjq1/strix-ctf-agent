"""事实台账（fact ledger）的单测：正向与反例。

反例比正例重要——台账列错一条就是把人往死胡同里带，所以这里覆盖：
已请求的候选不再出现、同族全 4xx 的候选被丢掉、框架/静态噪声被过滤、
外站响应不算目标事实、没有可指名条目时返回空串（零注入）。
"""

from __future__ import annotations

import pytest

from ctf_strix import fact_ledger
from ctf_strix.fact_ledger import FactLedger
from ctf_strix.finish_guard import FinishGuard

ROUTE_MAP = """\
[route_map] https://h.test | html 812B | chunks 3/3 | 候选 12 条（列前 12 条）
⚠️ 上面就是全部路由，不要再下载或阅读 bundle 原文。下一步：method_sweep。
（首页=ab12；bundle 原文已在台账：index.js=cd34；用 traffic_view(id, offset=N) 分页读，不要重下）
1. /api/tasks  x3  (index.js)
2. /api/tasks/create  x2  (index.js)
3. /api/tasks/export  x1  (index.js)
4. /_next/static/chunks/main  x9  (index.js)
5. /a/b  x2  (index.js)
6. /api/static/app.js  x1  (index.js)
7. /u/{id}  x1  (index.js)
候选（页面词汇 × API 前缀，未验证，先 method_sweep）：
  ? /api/users/me
next: 把这些路径喂给 method_sweep。
"""

SWEEP_ALIVE = """\
[method_sweep] 2 路径 × 5 方法 = 10 请求 | 有信息量 2 条（列前 2）
ab12  200 GET     https://h.test/api/tasks | 95B | {"ok":true}
cd34  405 OPTIONS https://h.test/api/tasks/create | 0B allow=GET
"""

PROBE_HTML = """\
[HTTP 200] GET https://h.test/ | 0.03s | 812B | text/html; charset=utf-8 | id=ef56
hdr: server: nginx
body: <html></html>
next: read the forms.
"""

PROBE_404 = """\
[HTTP 404] GET https://h.test/api/x/one | 0.01s | 9B | text/plain | id=aa01
body: not found
"""


def _ledger_with(*calls: tuple[str, str, str]) -> FactLedger:
    ledger = FactLedger()
    for name, args, out in calls:
        ledger.observe(name, args, out)
    return ledger


def test_renders_only_untried_candidates_in_a_live_family() -> None:
    ledger = _ledger_with(
        ("route_map", '{"base_url": "https://h.test/"}', ROUTE_MAP),
        ("method_sweep", '{"urls": "/api/tasks", "base_url": "https://h.test"}', SWEEP_ALIVE),
    )
    text = ledger.render()
    assert "/api/tasks/create" in text
    assert "/api/tasks/export" in text
    assert "/api/users/me" in text
    # 已请求过的不再列（减法），框架/静态/模板/噪声路径全部过滤掉
    assert "\n  /api/tasks\n" not in text
    assert "_next" not in text
    assert "/a/b" not in text
    assert "app.js" not in text
    assert "/u/{id}" not in text
    # 同族已有 200，所以措辞必须是「同族能答」而不是「从没探测」
    assert "same path family already answers" in text


def test_requested_url_in_args_removes_the_candidate() -> None:
    ledger = _ledger_with(
        ("route_map", '{"base_url": "https://h.test/"}', ROUTE_MAP),
        ("http_probe", '{"url": "https://h.test/api/tasks/create"}', PROBE_404),
    )
    text = ledger.render()
    assert "/api/tasks/create" not in text


def test_dead_family_is_dropped() -> None:
    route_map = """\
[route_map] https://h.test | html 100B | chunks 1/1 | 候选 2 条（列前 2 条）
1. /api/x/one  x1  (index.js)
2. /api/x/two  x1  (index.js)
"""
    ledger = _ledger_with(
        ("route_map", "{}", route_map),
        ("http_probe", '{"url": "https://h.test/api/x/one"}', PROBE_404),
    )
    # /api/x/one 请求过被减掉；/api/x/two 同族全 4xx → 不列；没有别的东西 → 空串
    assert ledger.render() == ""


def test_nothing_to_say_means_zero_injection() -> None:
    assert FactLedger().render() == ""
    ledger = _ledger_with(
        ("route_map", "{}", "1. /api/tasks/create  x1  (index.js)"),
        ("http_probe", '{"url": "https://h.test/api/tasks/create"}', PROBE_HTML),
    )
    assert ledger.render() == ""


def test_render_is_capped_at_fifteen_lines() -> None:
    lines = ["[route_map] https://h.test | html 1B | chunks 1/1 | 候选 20 条（列前 20 条）"]
    lines += [f"{i}. /api/fam{i}/item  x1  (index.js)" for i in range(20)]
    ledger = _ledger_with(
        ("route_map", "{}", "\n".join(lines)),
        ("http_probe", '{"url": "https://h.test/"}', PROBE_HTML),
    )
    text = ledger.render()
    assert text
    assert len(text.splitlines()) <= 15
    entries = [ln for ln in text.splitlines() if ln.startswith("  /")]
    assert len(entries) == 8


def test_confirmed_facts_are_capped_deduped_and_host_filtered() -> None:
    ledger = FactLedger()
    ledger.observe("route_map", "{}", "[route_map] https://h.test | 1B | 1/1 | 候选 1 条\n1. /api/a/b  x1  (index.js)")
    for i in range(6):
        ledger.observe(
            "http_probe",
            f'{{"url": "https://h.test/api/f{i}/list"}}',
            f"[HTTP 200] GET https://h.test/api/f{i}/list | 0.01s | {i + 1}B | application/json | id=x",
        )
    ledger.observe(
        "http_probe",
        '{"url": "https://evil.test/api/ssrf"}',
        "[HTTP 200] GET https://evil.test/api/ssrf | 0.01s | 9B | text/plain | id=y",
    )
    text = ledger.render()
    confirmed = [ln for ln in text.splitlines() if ln.startswith("  GET ")]
    assert len(confirmed) == 4
    assert "evil.test" not in text
    assert all("json" in row for row in confirmed)


def test_observe_survives_odd_result_shapes() -> None:
    ledger = FactLedger()
    ledger.observe("http_probe", '{"url": "https://h.test/x"}', {"ok": True})
    ledger.observe("exec_command", "curl -s https://h.test/api/a/b", None)
    assert isinstance(ledger.stats(), dict)


def test_malformed_ipv6_url_does_not_drop_the_observation() -> None:
    """历史 run 里真出现过 ``http://[::1`` 这类字面量：urlparse 会抛 ValueError。"""
    ledger = FactLedger()
    ledger.observe("exec_command", "curl -g http://[::1/api/a/b", None)
    ledger.observe("route_map", "{}", ROUTE_MAP)
    assert ledger.render()  # 观测量还在，台账照常渲染
    # 8 条候选行里只有 4 条通过过滤：tasks / tasks/create / tasks/export / users/me
    assert ledger.stats()["candidates"] == 4


def test_opt_in_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    """预检证伪后默认关：不设变量或 =0 都不装，只有显式 =1 才装。"""
    monkeypatch.delenv("CTF_FACT_LEDGER", raising=False)
    assert fact_ledger.enabled() is False
    assert fact_ledger.install() is None
    monkeypatch.setenv("CTF_FACT_LEDGER", "0")
    assert fact_ledger.enabled() is False
    assert fact_ledger.install() is None
    monkeypatch.setenv("CTF_FACT_LEDGER", "1")
    assert fact_ledger.enabled() is True


def _armed_ledger() -> FactLedger:
    return _ledger_with(
        ("route_map", "{}", ROUTE_MAP),
        ("method_sweep", '{"urls": "/api/tasks"}', SWEEP_ALIVE),
    )


def test_finish_refusal_carries_the_ledger() -> None:
    guard = FinishGuard(ledger=_armed_ledger())
    refusal = guard.check('{"summary": "no answer yet"}')
    assert refusal is not None
    assert "[FACT LEDGER]" in refusal["error"]
    assert "/api/tasks/create" in refusal["error"]
    assert guard.stats()["ledger_injections"] == 1


def test_finish_allowed_has_no_ledger_and_empty_ledger_is_silent() -> None:
    guard = FinishGuard(ledger=FactLedger())
    refusal = guard.check('{"summary": "no answer yet"}')
    assert refusal is not None
    assert "[FACT LEDGER]" not in refusal["error"]
    assert guard.stats()["ledger_injections"] == 0

    plain = FinishGuard()
    refusal = plain.check('{"summary": "no answer yet"}')
    assert refusal is not None
    assert "[FACT LEDGER]" not in refusal["error"]


def test_ledger_failure_never_changes_finish_policy() -> None:
    class Broken:
        def render(self) -> str:
            raise RuntimeError("boom")

    guard = FinishGuard(ledger=Broken())
    refusal = guard.check('{"summary": "no answer yet"}')
    assert refusal is not None
    assert refusal["success"] is False
    assert "REFUSED" in refusal["error"]
    assert guard.stats()["ledger_injections"] == 0