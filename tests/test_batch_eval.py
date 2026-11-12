"""P0：跑批的测量可信度。

这三条断言对应今天发现的三个污染源，任何一个回退都会让后续所有 A/B 变成假数据。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402
from batch_eval import (  # noqa: E402
    _answer_values,
    _archive_run,
    _fresh_box,
    _guard_state_path,
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


def test_guard_state_path_agrees_with_fresh_box(workdir: Path, monkeypatch) -> None:
    """Both sides must follow the live ``_BOX_ROOT``, not an import-time copy.

    A default argument is evaluated once at import, so a signature-level
    ``root=_BOX_ROOT`` freezes the box directory while the sidecar path reads
    the global on every call: the two then disagree as soon as the root is
    overridden.  Only the explicit-argument form was covered before, which is
    why the frozen default survived.
    """
    monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(workdir / "boxes"))

    box, _ = _fresh_box("run-name")
    sidecar = _guard_state_path("run-name")

    assert box == workdir / "boxes" / "run-name"
    assert sidecar == box / "guard_state.json"


def test_main_records_guard_without_name_error(workdir: Path, monkeypatch) -> None:
    """A result row must carry guard counters read from the run's own box."""
    plan = workdir / "plan.json"
    plan.write_text(
        json.dumps([{"id": "SMOKE-001", "difficulty": "easy"}]), encoding="utf-8"
    )
    out = workdir / "results.jsonl"
    monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(workdir / "boxes"))

    class FakeClient:
        def __init__(self, token: str) -> None:
            self.token = token

        def launch(self, cid: str, attempts: int = 5) -> str:
            return "iid-1"

        def wait_ready(self, iid: str, timeout: int = 180) -> str:
            return "http://127.0.0.1:8080/"

        def probe_reachable(self, url: str, attempts: int = 3) -> tuple[bool, str]:
            return True, "ok"

        def detail(self, cid: str) -> dict:
            return {}

        def teardown(self, iid: str) -> None:
            return None

    def fake_run_agent(target, turns, timeout_s, name, **kwargs):
        state_path = _guard_state_path(name)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "reach": 7,
                    "enum_keys": 2,
                    "journey": {
                        "wall": 1,
                        "authed": True,
                        "created": False,
                        "payloads": 3,
                        "prompts": 0,
                    },
                    "finish": {"refused": 1, "allowed": 2},
                    "mount_verified": True,
                }
            ),
            encoding="utf-8",
        )
        return "[sandbox] fake run\n", 1.0

    monkeypatch.setattr(batch_eval, "Client", FakeClient)
    monkeypatch.setattr(batch_eval, "run_agent", fake_run_agent)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch_eval.py",
            "--plan",
            str(plan),
            "--out",
            str(out),
            "--token",
            "t",
            "--no-archive",
        ],
    )

    assert batch_eval.main() == 0

    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert "guard" in rows[0]
    assert rows[0]["guard"]["reach"] == 7
    assert rows[0]["guard"]["mount_broken"] is False


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
        "--soft-deadline", "435", "--wall-deadline", "580",
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
    assert argv[argv.index("--soft-deadline") + 1] == "435"
    assert argv[argv.index("--wall-deadline") + 1] == "580"


def test_launch_ready_replaces_a_stuck_instance_once() -> None:
    """wait_ready 超时不应直接丢题：旧实例要销毁，新实例要再等一次。"""
    from batch_eval import _launch_ready

    class Client:
        def __init__(self) -> None:
            self.launches = 0
            self.teardowns: list[str] = []

        def launch(self, cid: str) -> str:
            self.launches += 1
            return f"iid-{self.launches}"

        def wait_ready(self, iid: str, timeout: int = 180) -> str:
            if iid == "iid-1":
                raise TimeoutError("not ready")
            return "https://target/"

        def teardown(self, iid: str) -> None:
            self.teardowns.append(iid)

    client = Client()
    iid, target = _launch_ready(client, "CH-001")

    assert iid == "iid-2"
    assert target == "https://target/"
    assert client.teardowns == ["iid-1"]
    assert client.launches == 2


def test_launch_ready_propagates_after_second_timeout() -> None:
    """第二次仍超时要如实报错，不能把失败伪装成成功。"""
    from batch_eval import _launch_ready

    class Client:
        def __init__(self) -> None:
            self.launches = 0
            self.teardowns: list[str] = []

        def launch(self, cid: str) -> str:
            self.launches += 1
            return f"iid-{self.launches}"

        def wait_ready(self, iid: str, timeout: int = 180) -> str:
            raise TimeoutError("not ready")

        def teardown(self, iid: str) -> None:
            self.teardowns.append(iid)

    client = Client()
    with pytest.raises(TimeoutError):
        _launch_ready(client, "CH-001")

    assert client.launches == 2
    assert client.teardowns == ["iid-1"]


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


# ---------------------------------------------------------------------------
# 提交前 verify 预检：抽取层放宽前缀后，平台判分器是唯一裁判。
# ---------------------------------------------------------------------------

ANSWER_LOG = (
    "127.0.0.1 says the token is HTB{the_right_0ne}\n"
    "ANSWER[flag]=HTB{the_right_0ne}\n"
)


def _run_single(workdir: Path, monkeypatch, client_cls, log: str = ANSWER_LOG) -> dict:
    """Run one challenge end to end with a fake client and return the result row."""
    plan = workdir / "plan.json"
    plan.write_text(json.dumps([{"id": "SMOKE-001", "difficulty": "easy"}]), encoding="utf-8")
    out = workdir / "results.jsonl"
    monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(workdir / "boxes"))
    monkeypatch.setattr(batch_eval, "Client", client_cls)
    monkeypatch.setattr(batch_eval, "run_agent", lambda *a, **k: (log, 1.0))
    monkeypatch.setattr(
        sys,
        "argv",
        ["batch_eval.py", "--plan", str(plan), "--out", str(out), "--token", "t", "--no-archive"],
    )
    assert batch_eval.main() == 0
    return json.loads(out.read_text(encoding="utf-8").splitlines()[-1])


def _fake_client(submit_log: list, verify=None):
    """Minimal client; ``verify`` is attached only when the test wants it."""

    class Fake:
        def __init__(self, token: str) -> None:
            self.token = token

        def launch(self, cid: str, attempts: int = 5) -> str:
            return "iid-1"

        def wait_ready(self, iid: str, timeout: int = 180) -> str:
            return "http://127.0.0.1:8080/"

        def probe_reachable(self, url: str, attempts: int = 3) -> tuple[bool, str]:
            return True, "ok"

        def detail(self, cid: str) -> dict:
            return {}

        def teardown(self, iid: str) -> None:
            return None

        def submit(self, iid: str, answer: str, qid: str = "flag") -> dict:
            submit_log.append((qid, answer))
            return {"correct": True}

    if verify is not None:
        Fake.verify = staticmethod(verify)  # type: ignore[attr-defined]
    return Fake


def test_verify_hit_submits_only_that_answer(workdir: Path, monkeypatch) -> None:
    """判分器认出候选中的一条：只交那一条，不浪费 attempts 试错。"""
    submitted: list = []

    def verify(iid: str, answer: str, qid: str = "flag"):
        return answer == "HTB{the_right_0ne}"

    rec = _run_single(workdir, monkeypatch, _fake_client(submitted, verify))

    assert rec["verify_precheck"] == "hit"
    assert submitted == [("flag", "HTB{the_right_0ne}")]
    assert rec["correct"] is True
    assert isinstance(rec["flag_shaped_tokens"], int) and rec["flag_shaped_tokens"] >= 1


def test_verify_miss_suppresses_submission(workdir: Path, monkeypatch) -> None:
    """全部候选都被判 false：不提交，只记数字——交上去只会污染台账。"""
    submitted: list = []

    def verify(iid: str, answer: str, qid: str = "flag"):
        return False

    rec = _run_single(workdir, monkeypatch, _fake_client(submitted, verify))

    assert submitted == []
    assert rec["verify_precheck"] == "miss"
    assert rec["flag_shaped_but_unsubmitted"] >= 1
    assert rec["correct"] is False


def test_verify_exception_falls_back_to_first_candidate(workdir: Path, monkeypatch) -> None:
    """预检抛异常必须 fail-open：原首选照交，否则一次抖动就等于零提交。"""
    submitted: list = []

    def verify(iid: str, answer: str, qid: str = "flag"):
        raise RuntimeError("verifier exploded")

    rec = _run_single(workdir, monkeypatch, _fake_client(submitted, verify))

    assert rec["verify_precheck"] == "unavailable"
    assert submitted == [("flag", "HTB{the_right_0ne}")]
    assert rec["correct"] is True


def test_client_without_verify_still_submits(workdir: Path, monkeypatch) -> None:
    """旧 client（或任何没有 verify 的实现）不能被 getattr 之外的东西碰到。"""
    submitted: list = []

    rec = _run_single(workdir, monkeypatch, _fake_client(submitted))

    assert rec["verify_precheck"] == "unavailable"
    assert submitted == [("flag", "HTB{the_right_0ne}")]
