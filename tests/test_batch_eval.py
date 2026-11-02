"""P0：跑批的测量可信度。

这三条断言对应今天发现的三个污染源，任何一个回退都会让后续所有 A/B 变成假数据。
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from batch_eval import (  # noqa: E402
    _answer_values,
    _archive_run,
    _fresh_box,
    _new_run_id,
    _proxy_blackhole,
)


@pytest.fixture()
def workdir():
    """自建临时目录。

    不用 pytest 的 ``workdir``：本机 ``%TEMP%/pytest-of-*`` 属于另一个
    用户（沙箱账户），fixture 建目录会直接 PermissionError，测试还没跑就
    ERROR——这种环境问题会伪装成"测试挂了"。
    """
    d = Path(tempfile.mkdtemp(prefix="ctfp0-"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_fresh_box_removes_previous_session_state(workdir: Path) -> None:
    """复用目录会让 strix 续跑上一轮 agent，必须删了重建。"""
    name = "20261030-100000-CTFARENA-009-abcd"
    stale = workdir / name / "strix_runs" / "sess" / ".state"
    stale.mkdir(parents=True)
    (stale / "agents.db").write_text("old session", encoding="utf-8")

    box, log = _fresh_box(name, root=workdir)

    assert box == workdir / name
    assert box.is_dir()
    assert not stale.exists(), "旧的 .state 必须消失，否则会续跑"
    assert list(box.iterdir()) == [], "沙箱必须是空的"
    assert log == box / "run.log"


def test_fresh_box_does_not_touch_sibling_challenges(workdir: Path) -> None:
    """只清本题，误删别人正在跑的沙箱比污染更难查。"""
    other = workdir / "20261030-100000-CTFARENA-018-ffff"
    other.mkdir(parents=True)
    (other / "keep.txt").write_text("keep", encoding="utf-8")

    _fresh_box("20261030-100000-CTFARENA-009-abcd", root=workdir)

    assert (other / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_archive_run_keeps_log_and_agent_state(workdir: Path) -> None:
    """只留 run.log 就查不出模型为什么这么选，agents.db 必须一起归档。"""
    box = workdir / "box"
    (box / "strix_runs" / "sess" / ".state").mkdir(parents=True)
    (box / "run.log").write_text(" TOOL exec_command\n", encoding="utf-8")
    (box / "strix_runs" / "sess" / ".state" / "agents.db").write_bytes(b"SQLite")

    dest = _archive_run(box, "run-1", workdir / "archive")

    assert (dest / "run.log").read_text(encoding="utf-8").startswith(" TOOL")
    assert (dest / "strix_runs" / "sess" / ".state" / "agents.db").read_bytes() == b"SQLite"


def test_archive_run_overwrites_previous_archive(workdir: Path) -> None:
    dest = workdir / "archive" / "run-1"
    dest.mkdir(parents=True)
    (dest / "stale.txt").write_text("old", encoding="utf-8")

    box = workdir / "box"
    box.mkdir()
    (box / "run.log").write_text("new", encoding="utf-8")

    _archive_run(box, "run-1", workdir / "archive")

    assert not (dest / "stale.txt").exists(), "归档目录必须是本次运行的全部内容"


def test_run_id_is_unique_and_carries_challenge() -> None:
    ids = {_new_run_id("CTFARENA-009") for _ in range(200)}

    assert len(ids) == 200, "同秒内的重复会让两次运行撞同一个 session"
    assert all("CTFARENA-009" in i for i in ids), "回看日志时要能一眼认出是哪道题"
    assert all(len(i.split("-")) >= 4 for i in ids)


@pytest.mark.parametrize("missing", ["agents.db"])
def test_archive_run_tolerates_missing_pieces(workdir: Path, missing: str) -> None:
    """实例崩掉时可能没有 agents.db，归档不能因此打断整批。"""
    box = workdir / "box"
    box.mkdir()
    (box / "run.log").write_text("log", encoding="utf-8")

    dest = _archive_run(box, "run-2", workdir / "archive")

    assert (dest / "run.log").exists()
    assert not (dest / "strix_runs" / "sess" / ".state" / missing).exists()

def test_proxy_blackhole_allows_target_and_llm(monkeypatch):
    """黑洞不能把靶机和 LLM 网关一起挡掉——那会让整题连起步都做不到。"""
    monkeypatch.setenv("LLM_API_BASE", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    monkeypatch.delenv("CTF_NO_PROXY_EXTRA", raising=False)

    env = _proxy_blackhole("https://abc123.node1.ctfy.run/")

    assert env["HTTPS_PROXY"] == "http://127.0.0.1:9"
    allowed = env["NO_PROXY"].split(",")
    assert "abc123.node1.ctfy.run" in allowed
    assert "dashscope.aliyuncs.com" in allowed
    assert "127.0.0.1" in allowed


def test_proxy_blackhole_accepts_host_port_target(monkeypatch):
    monkeypatch.setenv("LLM_API_BASE", "")
    monkeypatch.delenv("CTF_NO_PROXY_EXTRA", raising=False)

    env = _proxy_blackhole("10.0.0.5:31337")

    assert "10.0.0.5" in env["NO_PROXY"].split(",")


def test_answer_values_stops_before_markdown_emphasis() -> None:
    """049 的两个真实 flag 都被粗体包住；旧解析把 ``**`` 拼进了答案。"""
    text = (
        "**ANSWER[foothold]=FLAG{1111aaaa2222bbbb3333cccc4444dddd}**\n\n"
        "**ANSWER[deploy]=FLAG{5555eeee6666ffff7777aaaa8888bbbb}**\n\n"
        "The target is Gitea."
    )

    assert _answer_values(text) == {
        "foothold": "FLAG{1111aaaa2222bbbb3333cccc4444dddd}",
        "deploy": "FLAG{5555eeee6666ffff7777aaaa8888bbbb}",
    }


def test_answer_values_accepts_backticks_and_trailing_punctuation() -> None:
    text = "ANSWER[user]=`FLAG{abc}`\nANSWER[token]=deadbeef.\n"

    assert _answer_values(text) == {
        "user": "FLAG{abc}",
        "token": "deadbeef",
    }

def test_deadline_args_put_soft_deadline_at_75_percent() -> None:
    """墙钟杀会连带丢掉 usage；软截止必须早于它，且用同一个硬上限措辞。"""
    from batch_eval import _deadline_args

    assert _deadline_args(600) == [
        "--soft-deadline", "450", "--wall-deadline", "600",
    ]
    assert _deadline_args(0) == ["--soft-deadline", "1", "--wall-deadline", "1"]


def test_run_agent_passes_deadline_args_to_child(monkeypatch, workdir: Path) -> None:
    """参数没传下去就等于没装——这条盯住接线本身。"""
    import batch_eval

    captured: dict = {}

    class _Proc:
        returncode = 0

        def wait(self, timeout=None):  # noqa: ANN001, ARG002
            return 0

    def fake_popen(argv, **kwargs):  # noqa: ANN001, ANN003
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        return _Proc()

    monkeypatch.setattr(batch_eval, "_fresh_box", lambda n: (workdir, workdir / "run.log"))
    monkeypatch.setattr(batch_eval.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(batch_eval, "_private_tmp_available", lambda: False)
    monkeypatch.setattr(batch_eval, "_archive_run", lambda *a, **k: workdir)
    monkeypatch.setattr(batch_eval, "_answer_values", lambda text: {})

    batch_eval.run_agent(
        "https://example.test/", turns=30, timeout_s=600, name="t-acct",
        archive_dir=None, model="openai/GLM-5.3-EV",
    )

    argv = captured["argv"]
    assert "--soft-deadline" in argv
    assert argv[argv.index("--soft-deadline") + 1] == "450"
    assert argv[argv.index("--wall-deadline") + 1] == "600"


def test_suite_for_uses_static_table_without_network(monkeypatch):
    """快路径不许发请求：批测里每题都要路由，多一次 HTTP 就是多一次抖动源。"""
    import batch_eval

    called = {"n": 0}

    def boom(*a, **k):  # noqa: ANN002, ANN003
        called["n"] += 1
        return {}

    monkeypatch.setattr(batch_eval, "_fetch_suite_map", boom)
    batch_eval._SUITE_CACHE.clear()

    assert batch_eval.suite_for("CTFARENA-009") == "4394a10aa5d24f97a1ec3301ca718a45"
    assert called["n"] == 0


def test_suite_for_falls_back_to_platform_suites(monkeypatch):
    """XBOW 这种静态表里没有的套件，必须靠 /api/v1/suites 兜底，而不是整题崩掉。

    2026-11-01 校准批实测：XBOW-052 / XBOW-007 两题以 KeyError 秒退，
    结果表上看是"failed"，其实是根本没跑。
    """
    import batch_eval

    monkeypatch.setattr(
        batch_eval,
        "_fetch_suite_map",
        lambda token="": {"XBOW": "e236cf74b397436d94577142e5cdb528"},
    )
    batch_eval._SUITE_CACHE.clear()

    assert batch_eval.suite_for("XBOW-052") == "e236cf74b397436d94577142e5cdb528"
    # 解析结果要缓存，后面 100 多题不再重复问平台。
    assert batch_eval._SUITE_CACHE == {"XBOW": "e236cf74b397436d94577142e5cdb528"}
    batch_eval._SUITE_CACHE.clear()


def test_suite_for_prefers_longest_prefix(monkeypatch):
    """`AGENT-DEFENSE-001` 不能被假想的 `AGENT` 前缀抢走。"""
    import batch_eval

    monkeypatch.setattr(
        batch_eval,
        "_fetch_suite_map",
        lambda token="": {"AGENT": "aaa", "AGENT-DEFENSE": "d4917609895644e1bcf92b3c9b3bc70f"},
    )
    batch_eval._SUITE_CACHE.clear()

    assert batch_eval.suite_for("AGENT-DEFENSE-001") == "d4917609895644e1bcf92b3c9b3bc70f"
    batch_eval._SUITE_CACHE.clear()


def test_suite_for_raises_with_known_list_when_unresolvable(monkeypatch):
    """真解析不出来要出声，并且报错里带已知前缀——否则排查只能靠猜。"""
    import batch_eval

    monkeypatch.setattr(batch_eval, "_fetch_suite_map", lambda token="": {})
    batch_eval._SUITE_CACHE.clear()

    with pytest.raises(KeyError) as exc:
        batch_eval.suite_for("NOSUCHSUITE-001")

    assert "NOSUCHSUITE-001" in str(exc.value)
    assert "CTFARENA" in str(exc.value)


def test_title_prefixes_normalises_title() -> None:
    from batch_eval import _title_prefixes

    assert _title_prefixes("XBOW") == ["XBOW"]
    assert _title_prefixes(" agent-defense ") == ["AGENT-DEFENSE"]
    assert _title_prefixes("") == []


def test_tcp_service_is_not_treated_as_a_webpage() -> None:
    """端口 1337 的原始服务不能被拼成 http://host:1337/。

    旧版 `_public_url()` 无条件拼 http://，于是 SAMPLE-014 / CYBENCH 这类
    TCP 题被当成网页交给 agent，它用 curl 打必然失败，然后在"是不是 TLS /
    是不是路径错"上耗完预算。实测走桥一条命令就能拿到 flag。
    """
    from batch_eval import is_tcp_service

    assert is_tcp_service({"service_type": "tcp", "port": 1337}) is True
    assert is_tcp_service({"service_type": "tcp", "port": 443}) is True
    assert is_tcp_service({"port": 1337}) is True
    assert is_tcp_service({"service_type": "https", "port": 443}) is False
    assert is_tcp_service({"service_type": "http", "port": 8080}) is False
    assert is_tcp_service({"port": 8000}) is False


def test_probe_tcp_uses_a_real_socket(monkeypatch) -> None:
    """TCP 题的连通性必须用 socket 测，不能用 HTTP 探测。

    HTTP 探测读到 `CTFy TCP test service` 这种 banner 会解析失败，判成
    "不可达"，然后触发换实例——把好好的题换掉。
    """
    import socket as _socket

    import batch_eval

    class _Fake:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, _):
            return None

        def recv(self, _):
            return b"CTFy TCP test service\n> "

    monkeypatch.setattr(_socket, "create_connection", lambda addr, timeout: _Fake())

    ok, detail = batch_eval._probe_tcp("127.0.0.1:41345")

    assert ok is True
    assert "tcp open" in detail
    assert "CTFy" in detail


def test_probe_tcp_reports_failure_without_raising(monkeypatch) -> None:
    import socket as _socket

    import batch_eval

    def boom(addr, timeout):  # noqa: ANN001, ARG001
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr(_socket, "create_connection", boom)

    ok, detail = batch_eval._probe_tcp("127.0.0.1:9", attempts=1)

    assert ok is False
    assert "ConnectionRefusedError" in detail


def test_run_agent_passes_target_kind(monkeypatch, workdir: Path) -> None:
    """题型没传下去 = 桥建了但子进程仍按 web 打，等于没建。"""
    import batch_eval

    captured: dict = {}

    class _Proc:
        returncode = 0

        def wait(self, timeout=None):  # noqa: ANN001, ARG002
            return 0

    def fake_popen(argv, **kwargs):  # noqa: ANN001, ANN003
        captured["argv"] = list(argv)
        return _Proc()

    monkeypatch.setattr(batch_eval, "_fresh_box", lambda n: (workdir, workdir / "run.log"))
    monkeypatch.setattr(batch_eval.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(batch_eval, "_private_tmp_available", lambda: False)
    monkeypatch.setattr(batch_eval, "_archive_run", lambda *a, **k: workdir)

    batch_eval.run_agent(
        "127.0.0.1:41345", turns=20, timeout_s=600, name="t-tcp",
        target_kind="tcp",
    )

    argv = captured["argv"]
    assert argv[argv.index("--target-kind") + 1] == "tcp"
