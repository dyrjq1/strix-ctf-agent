"""``recovery_notice``: 失败形态 → 一句确定性的下一步。

纪律：每条规则只在**该响的时候**响（正例逐类覆盖），并且
**不该响的时候不响**（正常 200、空文本、已提示过的类别）。
建议文本必须过命名测试——不含题号、路径、IP、flag。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import recovery_notice  # noqa: E402


@pytest.fixture(autouse=True)
def _clean():
    recovery_notice.reset_run()
    yield
    recovery_notice.reset_run()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "r6    405 POST    https://h/ | 153B allow=HEAD, OPTIONS, GET | "
            "<h1>Method Not Allowed</h1>",
            "http_405",
        ),
        ("[HTTP 403] GET https://h/admin | 0.1s | 21B | text/html", "http_auth_gate"),
        ("[HTTP 401] GET https://h/api/me | 0.1s | 0B |", "http_auth_gate"),
        (
            "ConnectionRefusedError: [Errno 111] Connection refused",
            "unreachable",
        ),
        ("SSLError: certificate verify failed: self signed", "unreachable"),
        (
            "[HTTP 200] GET https://h/start | 0.1s | 0B | text/html | id=r3",
            "empty_200",
        ),
        ("Command timed out after 30s", "cmd_timeout"),
        ("[tcp] connection closed by peer (reset)", "tcp_closed"),
    ],
)
def test_each_failure_shape_classifies(text: str, expected: str) -> None:
    hit = recovery_notice.classify(text)
    assert hit is not None
    assert hit[0] == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[HTTP 200] GET https://h/ | 0.2s | 2.1kB | text/html | id=r1",
        "r10 GET 200 265B https://h/api/items",
        "wrote 12 files to /tmp/out",
    ],
)
def test_healthy_output_produces_no_notice(text: str) -> None:
    assert recovery_notice.classify(text) is None
    assert recovery_notice.notice("http_probe", text) == ""


def test_same_class_notifies_once_per_run() -> None:
    text = "[HTTP 403] GET https://h/a | 21B"
    first = recovery_notice.notice("http_probe", text)
    second = recovery_notice.notice("http_probe", text)
    assert first.startswith("\n[NEXT] ")
    assert second == ""
    # 另一个工具命中同一类时仍可提示：噪声是按 (工具, 类) 收敛的。
    assert recovery_notice.notice("method_sweep", text).startswith("\n[NEXT] ")


def test_reset_run_reopens_the_hint() -> None:
    text = "Connection refused"
    assert recovery_notice.notice("tcp", text)
    recovery_notice.reset_run()
    assert recovery_notice.notice("tcp", text)


def test_advice_passes_the_naming_test() -> None:
    """建议里不许出现题号、URL、flag 形态的字符串。"""
    for name, _pattern, advice in recovery_notice._RULES:  # noqa: SLF001
        assert "FLAG{" not in advice, name
        assert "http://" not in advice and "https://" not in advice, name
        assert "CTFARENA" not in advice and "CYBENCH" not in advice, name
        assert len(advice) < 400, f"{name} advice is too long for a hint"


def test_attach_appends_once_and_keeps_the_result_otherwise() -> None:
    class _Tool:
        name = "http_probe"

        def __init__(self):
            self.calls = 0

        async def on_invoke_tool(self, ctx, raw):
            self.calls += 1
            return "[HTTP 405] POST https://h/ | allow=GET"

    tool = recovery_notice._attach(_Tool())  # noqa: SLF001
    first = asyncio.run(tool.on_invoke_tool(None, {}))
    second = asyncio.run(tool.on_invoke_tool(None, {}))
    assert first.endswith("\n") and "[NEXT]" in first
    assert "[NEXT]" not in second  # 每类每 run 只提示一次
    assert tool._ctf_recovery is True  # noqa: SLF001


def test_attach_is_idempotent() -> None:
    class _Tool:
        name = "http_probe"

        async def on_invoke_tool(self, ctx, raw):
            return "x"

    tool = recovery_notice._attach(_Tool())  # noqa: SLF001
    wrapped = tool.on_invoke_tool
    again = recovery_notice._attach(tool)  # noqa: SLF001
    assert again is tool
    assert again.on_invoke_tool is wrapped


def test_install_is_gated_by_the_shared_seam(monkeypatch) -> None:
    """开关关闭时 install_ctf_toolset 不得改动工具面。"""
    from strix.agents import factory

    from ctf_strix import tool_trim

    tool_trim.restore_base_tools()
    before = factory._with_bounded_result  # noqa: SLF001
    monkeypatch.delenv("CTF_RECOVERY_NOTICE", raising=False)
    tool_trim.install_ctf_toolset()
    assert factory._with_bounded_result is before  # noqa: SLF001
    tool_trim.restore_base_tools()