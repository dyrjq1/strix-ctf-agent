"""P3：无进展收场后的「换策略重开」（``--max-samples``）。

分工是这一轮机制的核心：agent 只负责把「停在哪」落盘（host + path family +
mechanism + 响应签名）并结束 run；**要不要再跑一次由 harness 判断**——它看
``stop_reason`` 和剩余样本数，不看 flag 有没有出现。

这里钉住四件事：

① ``_stop_reason_of`` 从日志读出收场原因，且墙钟优先于信号退出码
   （超时必然同时留下 ``WALLCLOCK TIMEOUT`` 与 ``rc=-9``，判反了就会把
   「预算用尽」误记成「基础设施崩溃」，进而重开烧钱）；
② 只有四种「有证据的早停」允许重开，solved / error / wallclock 不重开；
③ 子进程经 ``CTFY_STALL_MARKERS`` 拿到的路径，与父进程读回的路径是同一个；
④ 换向提示只带结构事实，不带响应正文；标记文件缺失或损坏时也要能给出提示。
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
    _fresh_box,
    _resample_allowed,
    _resume_steer,
    _stall_markers_path,
    _stop_reason_of,
)


@pytest.fixture()
def workdir():
    """自建临时目录：``%TEMP%/pytest-of-*`` 归另一个账户，用它会 PermissionError。"""
    d = Path(tempfile.mkdtemp(prefix="ctfms-"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


#: 一次「整轮没有新观测」的收场，形状与 ``run_strix_ctf.py`` 打印的一致。
STALL_LOG = (
    "[stopped] NoProgress: 整轮探测没有新观测\n"
    "[stop] reason=no_progress host=h.test family=http://h.test/admin "
    "mechanism=access-control signature=abc123def456\n"
)
#: 一次正常拿到答案的收场。
SOLVED_LOG = "[answer] flag={x}\n[stop] reason=solved\n"
#: 墙钟杀：两条痕迹同时出现，这是父进程超时分支的实际输出。
WALLCLOCK_LOG = "\n[WALLCLOCK TIMEOUT after 600s]\n\n[agent-exit] rc=-9\n"


# -- 从日志读出「怎么收场的」 ---------------------------------------------


def test_stop_reason_reads_the_stop_line() -> None:
    assert _stop_reason_of(STALL_LOG) == "no_progress"
    assert _stop_reason_of("[stop] reason=enum_exhausted host=h.test\n") == "enum_exhausted"
    assert _stop_reason_of(SOLVED_LOG) == "solved"


def test_stop_reason_reads_wallclock_before_the_signal_exit() -> None:
    """超时同时留下 rc=-9；先判退出码就会把「预算用尽」记成崩溃。"""
    assert _stop_reason_of(WALLCLOCK_LOG) == "wallclock"


def test_stop_reason_reads_watchdog_hard_stop_line() -> None:
    """进程内 watchdog 击杀：exit 0、没有 [agent-exit] 行，日志行是唯一归因。

    （改动3 契约后果：HARD_EXIT_CODE 改 0 后 rc 不再是信号，认不出这条
    行会把「预算用尽」记成 unknown——分类退化且难排查。）
    """
    log = "[ctfy] wallclock hard stop after 600s; main thread did not unwind\n"
    assert _stop_reason_of(log) == "wallclock"


@pytest.mark.parametrize(
    "log",
    [
        "[stopped] error\n[run-error] agents.exceptions.MaxTurnsExceeded: too many\n",
        "[agent-exit] rc=1\n",
        "[agent-exit] rc=-15\n",
    ],
)
def test_stop_reason_maps_crash_shapes_to_error(log: str) -> None:
    assert _stop_reason_of(log) == "error"


def test_stop_reason_of_a_quiet_run_is_unknown() -> None:
    """没有收场行的日志不能让 harness 猜出「值得重开」。"""
    assert _stop_reason_of("") == "unknown"
    assert _stop_reason_of("[done] 60.0s calls=12\n") == "unknown"


# -- 哪些收场值得换策略重开 ---------------------------------------------


@pytest.mark.parametrize(
    "reason", ["no_progress", "enum_exhausted", "target_absent", "agent_idle"]
)
def test_evidenced_stops_allow_a_resample(reason: str) -> None:
    assert _resample_allowed(reason) is True


@pytest.mark.parametrize(
    "reason", ["solved", "completed", "wallclock", "wallclock_hard", "error", "unknown"]
)
def test_solved_budget_and_infrastructure_do_not_resample(reason: str) -> None:
    """已经拿到东西不再跑；预算/基础设施问题重开只是重复烧钱。"""
    assert _resample_allowed(reason) is False


# -- 两侧拼的是同一个路径 --------------------------------------------------


def test_stall_markers_path_agrees_with_fresh_box(workdir: Path, monkeypatch) -> None:
    monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(workdir / "boxes"))

    box, _ = _fresh_box("run-name")

    assert _stall_markers_path("run-name") == box / "stall_markers.jsonl"


def test_run_agent_hands_the_marker_path_to_the_child(
    workdir: Path, monkeypatch
) -> None:
    """环境变量没传下去，第二轮就会永远读到一个空文件。"""
    captured: dict = {}

    class _Proc:
        returncode = 0

        def wait(self, timeout=None):  # noqa: ANN001, ARG002
            return 0

    def fake_popen(argv, **kwargs):  # noqa: ANN001, ANN003
        captured["kwargs"] = kwargs
        return _Proc()

    monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(workdir / "boxes"))
    monkeypatch.setattr(batch_eval, "_fresh_box", lambda n: (workdir, workdir / "run.log"))
    monkeypatch.setattr(batch_eval.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(batch_eval, "_private_tmp_available", lambda: False)
    monkeypatch.setattr(batch_eval, "_archive_run", lambda *a, **k: workdir)

    batch_eval.run_agent(
        "https://example.test/", turns=20, timeout_s=60, name="t-stall",
        archive_dir=None,
    )

    env = captured["kwargs"]["env"]
    assert env["CTFY_STALL_MARKERS"] == str(
        workdir / "boxes" / "t-stall" / "stall_markers.jsonl"
    )


# -- 换向提示：带事实，不带响应正文 ---------------------------------------


def test_steer_carries_the_marked_facts(tmp_path: Path) -> None:
    markers = tmp_path / "stall_markers.jsonl"
    markers.write_text(
        json.dumps(
            {
                "ts": 1,
                "host": "h2.test",
                "family": "http://h2.test/api/users",
                "mechanism": "authz",
                "signature": "deadbeefcafe",
                "streak": 6,
                "fresh_rate": 0.14,
                "probes": 7,
                "stage": "stall",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    hint = _resume_steer(markers, "no_progress", 2)

    assert "[重开 2]" in hint
    assert "no_progress" in hint
    for needle in (
        "host=h2.test",
        "family=http://h2.test/api/users",
        "mechanism=authz",
        "stage=stall",
    ):
        assert needle in hint
    assert "traffic_list" in hint, "换向不能只是口号，要给下一条请求的落点"
    assert "deadbeefcafe" not in hint, "签名是索引，不该当成提示内容"


def test_steer_reads_the_last_written_marker(tmp_path: Path) -> None:
    """同一个文件会追加多条；第二轮的起点是最后一条，不是第一条。"""
    markers = tmp_path / "stall_markers.jsonl"
    markers.write_text(
        json.dumps({"host": "old.test", "stage": "stall"}) + "\n"
        + json.dumps({"host": "new.test", "stage": "deep_exhausted"}) + "\n",
        encoding="utf-8",
    )

    hint = _resume_steer(markers, "no_progress", 3)

    assert "host=new.test" in hint
    assert "old.test" not in hint


@pytest.mark.parametrize("content", [None, "", "  \n", "not json\n", "[]\n", '"x"\n'])
def test_steer_survives_missing_or_broken_markers(
    tmp_path: Path, content: str | None
) -> None:
    """标记读不到不是错误：退回通用换向提示，别把重开也一起弄崩。"""
    markers = tmp_path / "stall_markers.jsonl"
    if content is not None:
        markers.write_text(content, encoding="utf-8")

    hint = _resume_steer(markers, "no_progress", 2)

    assert "[重开 2]" in hint
    assert "（上一轮没留下可用的停滞事实）" in hint
    assert "traffic_list" in hint


# -- 端到端：main() 里真的会重开，也真的会停 -----------------------------


def _client():
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
            return {"correct": True}

    return Fake


def _run_plan(workdir: Path, monkeypatch, fake_run_agent, argv_extra=()) -> dict:
    plan = workdir / "plan.json"
    plan.write_text(
        json.dumps([{"id": "SMOKE-001", "difficulty": "easy"}]), encoding="utf-8"
    )
    out = workdir / "results.jsonl"
    monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(workdir / "boxes"))
    monkeypatch.setattr(batch_eval, "Client", _client())
    monkeypatch.setattr(batch_eval, "run_agent", fake_run_agent)
    monkeypatch.setattr(
        sys,
        "argv",
        ["batch_eval.py", "--plan", str(plan), "--out", str(out), "--token", "t",
         "--no-archive", *argv_extra],
    )
    assert batch_eval.main() == 0
    return json.loads(out.read_text(encoding="utf-8").splitlines()[-1])


def test_max_samples_reopens_with_a_new_direction(workdir: Path, monkeypatch) -> None:
    calls: list[dict] = []

    def fake_run_agent(target, turns, timeout_s, name, **kwargs):
        calls.append({"name": name, "extra": kwargs.get("extra", "")})
        # 子进程就是这么落盘的：写进本次样本自己的标记文件。
        markers = _stall_markers_path(name)
        markers.parent.mkdir(parents=True, exist_ok=True)
        markers.write_text(
            json.dumps(
                {
                    "ts": 1,
                    "host": "h.test",
                    "family": "http://h.test/admin",
                    "mechanism": "access-control",
                    "signature": "abc123def456",
                    "streak": 6,
                    "fresh_rate": 0.0,
                    "probes": 7,
                    "stage": "deep_exhausted",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        if len(calls) == 1:
            return STALL_LOG, 3.0
        return SOLVED_LOG, 3.0

    rec = _run_plan(workdir, monkeypatch, fake_run_agent, ["--max-samples", "2"])

    assert rec["samples_used"] == 2
    assert rec["stop_reasons"] == ["no_progress", "solved"]
    assert rec["stop_reason"] == "solved"
    assert rec["agent_s"] == 6.0

    assert len(calls) == 2
    assert calls[1]["name"] == calls[0]["name"] + "-s2", "样本名唯一 == 沙箱唯一"
    assert "[重开 2]" in calls[1]["extra"]
    assert "family=http://h.test/admin" in calls[1]["extra"]
    assert "[重开 2]" not in calls[0]["extra"], "第一次跑不该带着换向提示"


def test_a_solved_first_sample_is_not_rerun(workdir: Path, monkeypatch) -> None:
    names: list[str] = []

    def fake_run_agent(target, turns, timeout_s, name, **kwargs):
        names.append(name)
        return SOLVED_LOG, 1.5

    rec = _run_plan(workdir, monkeypatch, fake_run_agent, ["--max-samples", "3"])

    assert names == ["SMOKE-001"] or len(names) == 1
    assert rec["samples_used"] == 1
    assert rec["stop_reason"] == "solved"


def test_a_wallclock_stop_is_not_rerun(workdir: Path, monkeypatch) -> None:
    """墙钟是预算问题：换策略重开只会在同一个预算里再耗尽一次。"""

    def fake_run_agent(target, turns, timeout_s, name, **kwargs):
        return WALLCLOCK_LOG, 600.0

    rec = _run_plan(workdir, monkeypatch, fake_run_agent, ["--max-samples", "3"])

    assert rec["samples_used"] == 1
    assert rec["stop_reasons"] == ["wallclock"]
    assert rec["wallclock_hit"] is True


def test_without_the_flag_each_challenge_gets_one_shot(
    workdir: Path, monkeypatch
) -> None:
    """默认语义不变：每题一次机会，失败就记失败。"""

    def fake_run_agent(target, turns, timeout_s, name, **kwargs):
        return STALL_LOG, 2.0

    rec = _run_plan(workdir, monkeypatch, fake_run_agent)

    assert rec["samples_used"] == 1
    assert rec["stop_reason"] == "no_progress"
    assert rec["agent_s"] == 2.0