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

from batch_eval import _archive_run, _fresh_box, _new_run_id, _proxy_blackhole  # noqa: E402


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
