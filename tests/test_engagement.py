"""engagement 报告投递的回归测试。

每一条都锁一个会让 GAUNTLET 直接 0 分的具体失败：

1. 端点拼错（少了 competition 段）→ 404，报告永远存不上；
2. 字段名猜错 → 400，正文根本没落库；
3. 网络失败抛异常 → 整个 run 崩掉，连 flag 题的产物都没有；
4. engagement 的 goal 里出现"不要写报告"→ 模型主动放弃交付物；
5. 空正文也发请求 → 用空报告覆盖掉一份有证据的版本。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from ctf_strix import engagement
from ctf_strix.agent import _challenge_kind, _read_goal


def _task(**over: Any) -> dict[str, Any]:
    task: dict[str, Any] = {
        "run_mode": "engagement",
        "challenge": {"id": "CH-9", "name": "Meridian", "description": "corp net"},
        "competition_id": "COMP-7",
        "scope": ["edge.meridian.test", "10.20.0.0/16"],
        "target_instance": "inst-1",
        "questions": [],
    }
    task.update(over)
    return task


def test_report_url_contains_both_ids() -> None:
    """端点必须同时带 competition 与 challenge，少一段就是 404。"""
    url = engagement.report_url("https://ctfy.example/", "COMP-7", "CH-9")
    assert url == "https://ctfy.example/api/v1/competitions/COMP-7/challenges/CH-9/report"


def test_ids_prefer_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """平台用环境变量下发 id；环境变量比 task.json 更权威。"""
    monkeypatch.setenv("CTFY_EVAL_COMPETITION_ID", "ENV-COMP")
    monkeypatch.setenv("CTFY_EVAL_CHALLENGE_ID", "ENV-CH")
    monkeypatch.setenv("CTFY_PLATFORM_URL", "https://env.example")
    task = _task()
    assert engagement.competition_id_of(task) == "ENV-COMP"
    assert engagement.challenge_id_of(task) == "ENV-CH"
    assert engagement.platform_of(task) == "https://env.example"


def test_unconfigured_publisher_refuses_without_network() -> None:
    """缺 token / id 时必须当场拒绝，而不是发一个必然 401 的请求。"""
    pub = engagement.ReportPublisher("", "", "", "")
    ok, note = pub.publish("# report", force=True)
    assert ok is False
    assert "not configured" in note
    assert pub.attempts == 0


def test_empty_report_is_never_sent() -> None:
    """空正文会覆盖掉上一版有证据的报告，必须拦住。"""
    pub = engagement.ReportPublisher("https://x.example", "tok", "C", "H")
    ok, note = pub.publish("   \n ", force=True)
    assert ok is False and "empty" in note
    assert pub.attempts == 0


def test_network_failure_does_not_raise() -> None:
    """连不上平台只返回 False——报告投递失败不能拖垮 run。"""
    pub = engagement.ReportPublisher(
        "http://127.0.0.1:1", "tok", "C", "H", min_interval=0
    )
    ok, note = pub.publish("# report", force=True)
    assert ok is False
    assert note
    assert pub.successes == 0


class _Recorder(BaseHTTPRequestHandler):
    """记录收到的 PUT，并按 ``accept_key`` 决定是否接受。"""

    accept_key = "content"
    bodies: list[dict[str, Any]] = []
    status = 200

    def do_PUT(self) -> None:  # noqa: N802 — http.server 的约定
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).bodies.append(body)
        if type(self).status == 200 and self.accept_key not in body:
            self.send_response(422)
            self.end_headers()
            self.wfile.write(b'{"detail":"missing content"}')
            return
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args: Any) -> None:
        return


@pytest.fixture()
def server() -> Any:
    _Recorder.bodies = []
    _Recorder.accept_key = "content"
    _Recorder.status = 200
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_publish_retries_body_key_on_schema_error(server: str) -> None:
    """字段名不对（422）时要换下一个候选，成功后记住它。"""
    _Recorder.accept_key = "markdown"
    pub = engagement.ReportPublisher(server, "tok", "C", "H", min_interval=0)
    ok, note = pub.publish("# Finding\n\nGET /api/doc/42 -> 200", force=True)
    assert ok, note
    assert pub.body_key == "markdown"
    assert [sorted(b) for b in _Recorder.bodies[:2]] == [["content"], ["markdown"]]

    # 记住之后不再重复试错：直接一次成功。
    _Recorder.bodies = []
    pub.publish("second version", force=True)
    assert [sorted(b) for b in _Recorder.bodies] == [["markdown"]]


def test_auth_failure_is_not_retried(server: str) -> None:
    """401/403 换字段也没用，只该发一次。"""
    _Recorder.status = 401
    pub = engagement.ReportPublisher(server, "tok", "C", "H", min_interval=0)
    ok, note = pub.publish("# report", force=True)
    assert ok is False
    assert "401" in note
    assert len(_Recorder.bodies) == 1


def test_unchanged_report_is_skipped(server: str) -> None:
    """正文没变时不重复 PUT，避免周期性保存把平台打爆。"""
    pub = engagement.ReportPublisher(server, "tok", "C", "H", min_interval=0)
    assert pub.publish("# same", force=True)[0]
    before = len(_Recorder.bodies)
    ok, note = pub.publish("# same")
    assert ok and "skipped" in note
    assert len(_Recorder.bodies) == before


def test_auto_save_does_not_overwrite_authored_report(server: str) -> None:
    """自动摘要晚于模型手写正文落地时，不能把它盖掉。

    后台线程是「先启动、后完成」的：第 8 条工具输出时快照一份摘要发出去，
    模型此时调了 save_report，线程随后才到达平台——若允许覆盖，报告就退回
    成只有「做了什么」的活动记录，「影响是什么」这个计分点全丢。
    """
    pub = engagement.ReportPublisher(server, "tok", "C", "H", min_interval=0)
    assert pub.publish("# Finding: IDOR on /api/doc/42", force=True, source="agent")[0]
    sent = len(_Recorder.bodies)
    ok, note = pub.publish("# auto summary", force=True, source="auto")
    assert ok, note
    assert "precedence" in note
    assert len(_Recorder.bodies) == sent


def test_authored_report_can_still_be_resent_at_finish(server: str) -> None:
    """收工时的最终保存要以 agent 身份重发手写正文，不能被上一条规则挡掉。"""
    pub = engagement.ReportPublisher(server, "tok", "C", "H", min_interval=0)
    text = "# Finding: IDOR on /api/doc/42"
    assert pub.publish(text, force=True, source="agent")[0]
    before = len(_Recorder.bodies)
    ok, note = pub.publish(pub.last_text, force=True, source="agent")
    assert ok, note
    assert len(_Recorder.bodies) == before + 1


class _FakeTool:
    """最小 FunctionTool 替身：只保留 ``install_tool`` 用到的那两个属性。"""

    def __init__(self, fn: Any) -> None:
        self.fn = fn
        self.name = fn.__name__

    async def on_invoke_tool(self, ctx: Any, raw_input: str) -> Any:
        return await self.fn(raw_input)


class _StubPublisher:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def publish(self, markdown: str, **_: Any) -> tuple[bool, str]:
        self.calls.append(markdown)
        return True, "ok"


def _install_fake_sdk(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """把 ``agents`` / factory 换成最小假实现，只验证注册行为本身。

    真实 SDK 不在本机（镜像里才有），但这条规则与 SDK 无关：工具名必须唯一，
    否则 ``register_agent_tools`` 抛 ValueError，报告工具就静默消失了。
    """
    import sys
    import types

    fake_agents = types.ModuleType("agents")
    fake_agents.function_tool = lambda fn=None, **_: _FakeTool(fn) if fn else (lambda f: _FakeTool(f))
    monkeypatch.setitem(sys.modules, "agents", fake_agents)

    registered: list[Any] = []

    # 连 factory 一起假掉：真的 ``strix.agents.factory`` 在 import 期就要
    # ``agents.agent`` 等一整套 SDK 符号，本机没有，强行注入只会让测试
    # 变成"环境探测"。
    fake_factory = types.ModuleType("strix.agents.factory")
    fake_factory.register_agent_tools = lambda *tools: registered.extend(tools)
    fake_factory.registered_agent_tools = lambda: tuple(registered)
    fake_strix = types.ModuleType("strix.agents")
    fake_strix.factory = fake_factory
    monkeypatch.setitem(sys.modules, "strix.agents", fake_strix)
    monkeypatch.setitem(sys.modules, "strix.agents.factory", fake_factory)
    return registered


def test_install_tool_registers_once_and_rebinds_publisher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同进程第二次装工具不能重复注册，但必须指向本次 run 的投递器。"""
    import asyncio

    registered = _install_fake_sdk(monkeypatch)
    first, second = _StubPublisher(), _StubPublisher()

    assert engagement.install_tool(first) == ["save_report"]
    assert engagement.install_tool(second) == ["save_report"]
    assert len(registered) == 1

    tool = registered[0]
    asyncio.run(tool.on_invoke_tool(None, "# report"))
    assert second.calls == ["# report"]
    assert first.calls == []


def test_engagement_goal_is_report_oriented() -> None:
    """engagement 的 goal 必须要求交报告，不能出现"不要写报告"。"""
    text = _read_goal("engagement")
    assert "report" in text.lower()
    assert "Do not write reports" not in text


def test_flag_goal_does_not_talk_about_reports() -> None:
    """flag 题反过来不能被 engagement 的交付物要求稀释。"""
    text = _read_goal("web")
    assert "FLAG{" in text
    assert "penetration-test report" not in text.lower()


@pytest.mark.parametrize(
    ("task", "expected"),
    [
        ({"run_mode": "engagement", "scope": ["h.test"]}, "engagement"),
        ({"run_mode": "instance", "questions": [{"id": "x", "mode": "checker"}]}, "checker"),
        ({"run_mode": "instance", "scope": ["10.0.0.5:1337"]}, "tcp"),
        ({"run_mode": "instance", "scope": ["https://a.test"]}, "web"),
    ],
)
def test_challenge_kind(task: dict[str, Any], expected: str) -> None:
    assert _challenge_kind(task) == expected


def test_build_report_keeps_evidence_parts() -> None:
    """报告要有 where/how/evidence，只有结论的正文平台抽不出分。"""
    text = engagement.build_report(
        _task(),
        findings=["### Finding: IDOR\n\n- **Where**: `GET /api/doc/42`\n"],
        activity=["- `curl` /api/doc/42"],
        summary="read another user's document",
        elapsed=42,
    )
    assert "/api/doc/42" in text
    assert "Activity log" in text
    assert "42s" in text


def test_report_omits_vague_only_headers() -> None:
    """没有任何素材时也要给出可读的最小报告，而不是空串。"""
    text = engagement.build_report(_task(), elapsed=0)
    assert "No finding has been written yet" in text


def test_redact_removes_known_token_but_keeps_evidence() -> None:
    """报告会被平台保存：抹掉 token，但**不能**抹掉作为证据的长 id / 哈希。

    这条锁的是一个很容易写错的方向：按"长串"一刀切会把文档 id、MD5、
    session 片段一起掩掉，而那些正是计分要看的东西。
    """
    token = "tok_" + "a" * 40
    text = engagement.redact(
        f"Authorization: Bearer {token}\n"
        "GET /api/doc/5f4dcc3b5aa765d61d8327deb882cf99 -> 200\n"
        "doc_id=9c1f8a2b7d4e6f0a1b2c3d4e5f6a7b8c",
        [token],
    )
    assert token not in text
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in text
    assert "9c1f8a2b7d4e6f0a1b2c3d4e5f6a7b8c" in text


def test_redact_masks_jwt_even_without_known_secret() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"
    assert jwt not in engagement.redact(f"cookie: {jwt}")
