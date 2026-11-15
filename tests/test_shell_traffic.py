"""shell 里的 HTTP 要进台账，否则台账上的每个工具都是摆设。

277 个 run：``exec_command`` 占 64% 的调用，``http_probe`` 只占 14%；
``traffic_list`` 被调用 27 次、``viability_probe`` **0 次**。原因不是模型
"不听话"，而是台账读不到它真正发的请求（台账 §4.182）。

这些用例钉住三件事：认得对（curl/requests/变量 base）、不乱认（XML 命名空间）、
记录层绝不改变行为（返回值一个字节都不动，失败不崩）。
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix import shell_traffic, traffic  # noqa: E402

extract = shell_traffic.extract_requests


@pytest.fixture(autouse=True)
def fresh_ledger(monkeypatch):
    """每个用例一个内存台账，不落盘、不串味。"""
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    shell_traffic.reset_for_tests()
    yield ledger
    shell_traffic.reset_for_tests()


@pytest.fixture
def factory(monkeypatch):
    pytest.importorskip("strix.agents")
    from strix.agents import factory as strix_factory

    monkeypatch.setattr(strix_factory, "_with_bounded_result", lambda tool: tool)
    monkeypatch.setattr(strix_factory, "_ctf_mounted", True, raising=False)
    return strix_factory


class FakeTool:
    def __init__(self, name: str, result: str = "ran") -> None:
        self.name = name
        self.result = result
        self.seen: list[str] = []

    async def on_invoke_tool(self, ctx, raw_input: str) -> str:  # noqa: ANN001, ARG002
        self.seen.append(raw_input)
        return self.result


# ------------------------------------------------------------------ extraction


def test_curl_get_with_literal_url():
    assert extract("curl -s https://t.test/api/notes -o out.json") == [
        ("GET", "https://t.test/api/notes")
    ]


def test_body_and_upload_flags_infer_method():
    assert extract('curl -d "a=1" https://t.test/login') == [("POST", "https://t.test/login")]
    assert extract("curl -F file=@x.png https://t.test/up") == [("POST", "https://t.test/up")]
    assert extract("curl -T a.txt https://t.test/put") == [("PUT", "https://t.test/put")]
    assert extract("curl -X DELETE https://t.test/item/1") == [
        ("DELETE", "https://t.test/item/1")
    ]


def test_python_verb_is_honoured():
    cmd = 'python3 -c "import requests; requests.post(\'https://t.test/login\', json={})"'
    assert extract(cmd) == [("POST", "https://t.test/login")]


def test_variable_base_covers_scripts_that_build_urls():
    """最常见的形态：脚本先赋值 base，客户端行里只写 ``$B``/``B``。"""
    cmd = (
        'B="https://t.test"\n'
        "python3 - <<EOF\n"
        "import requests\n"
        'r = requests.get(B + "/api/notes")\n'
        "EOF"
    )
    assert extract(cmd) == [("GET", "https://t.test")]


def test_xml_namespace_without_a_client_is_ignored():
    """XXE/SVG payload 里的 w3.org 命名空间不是请求，记进去就是污染。"""
    cmd = 'echo \'<svg xmlns="http://www.w3.org/2000/svg"></svg>\' > /tmp/x.svg'
    assert extract(cmd) == []


def test_duplicates_collapse_and_cap_holds():
    cmd = "curl https://t.test/a https://t.test/a " + " ".join(
        f"https://t.test/p{i}" for i in range(30)
    )
    pairs = extract(cmd)
    assert len(pairs) == shell_traffic._MAX_PER_COMMAND
    assert pairs[0] == ("GET", "https://t.test/a")


def test_empty_command_is_safe():
    assert extract("") == []
    assert extract("ls -la") == []


# ------------------------------------------------------------------- recording


def test_wrapper_records_after_the_command_and_returns_it_unchanged(factory, fresh_ledger):
    tool = FakeTool("exec_command", result="HTTP/1.1 200 OK\n{\"notes\":[]}")
    guard = shell_traffic.install()
    wrapped = factory._with_bounded_result(tool)

    out = asyncio.run(
        wrapped.on_invoke_tool(None, json.dumps({"command": "curl -s https://t.test/api/notes"}))
    )

    assert out == tool.result, "recording must not touch what the model sees"
    assert tool.seen and json.loads(tool.seen[0])["command"]
    items = fresh_ledger.items()
    assert [(i.method, i.url, i.phase) for i in items] == [
        ("GET", "https://t.test/api/notes", "shell")
    ]
    assert items[0].status is None, "no response was captured; saying otherwise is worse"
    assert "response not captured" in items[0].note
    assert guard is not None and guard.recorded == 1


def test_sdk_field_name_cmd_is_recognised(factory, fresh_ledger):
    """SDK 的字段叫 ``cmd`` 不叫 ``command``——实测日志里全是 ``cmd``。

    第一版只读 ``command``，于是真跑一场 13 次调用、SOLVED，台账却一条没有：
    静默失效，正是本层最该防的东西。
    """
    shell_traffic.install()
    wrapped = factory._with_bounded_result(FakeTool("exec_command"))

    asyncio.run(
        wrapped.on_invoke_tool(None, json.dumps({"cmd": "curl -s https://t.test/x"}))
    )

    assert [(i.method, i.url) for i in fresh_ledger.items()] == [("GET", "https://t.test/x")]


def test_traffic_list_marks_shell_entries_as_such(factory, fresh_ledger):
    shell_traffic.install()
    wrapped = factory._with_bounded_result(FakeTool("exec_command"))
    asyncio.run(wrapped.on_invoke_tool(None, '{"command": "curl https://t.test/x"}'))

    out = traffic.traffic_list()
    assert "/x" in out
    assert "shell" in out, "the status column must not look like a real HTTP status"


def test_other_tools_are_not_touched(factory, fresh_ledger):
    tool = FakeTool("http_probe")
    shell_traffic.install()
    wrapped = factory._with_bounded_result(tool)

    assert asyncio.run(wrapped.on_invoke_tool(None, '{"url": "https://t.test/x"}')) == "ran"
    assert fresh_ledger.items() == []


def test_bad_json_does_not_crash_and_records_nothing(factory, fresh_ledger):
    tool = FakeTool("exec_command")
    shell_traffic.install()
    wrapped = factory._with_bounded_result(tool)

    assert asyncio.run(wrapped.on_invoke_tool(None, "{not json")) == "ran"
    assert fresh_ledger.items() == []


def test_command_that_raises_records_nothing(factory, fresh_ledger):
    class Boom(FakeTool):
        async def on_invoke_tool(self, ctx, raw_input):  # noqa: ANN001, ARG002
            raise RuntimeError("sandbox died")

    shell_traffic.install()
    wrapped = factory._with_bounded_result(Boom("exec_command"))

    with pytest.raises(RuntimeError):
        asyncio.run(wrapped.on_invoke_tool(None, '{"command": "curl https://t.test/x"}'))
    assert fresh_ledger.items() == []


# ------------------------------------------------------------------- switches


def test_env_switch_turns_it_off_for_ablation(factory, monkeypatch):
    monkeypatch.setenv("CTF_SHELL_LEDGER", "0")
    assert shell_traffic.install() is None


def test_install_requires_the_mount_hook(factory, monkeypatch):
    monkeypatch.setattr(factory, "_ctf_mounted", False, raising=False)
    with pytest.raises(RuntimeError):
        shell_traffic.install()


def test_both_entrypoints_install_the_ledger():
    """评测入口装、交付入口没装 = 正赛里台账还是空的。"""
    for rel in ("src/ctf_strix/agent.py", "scripts/run_strix_ctf.py"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "shell_traffic import install as install_shell_traffic" in text, rel
        assert "install_shell_traffic()" in text, rel