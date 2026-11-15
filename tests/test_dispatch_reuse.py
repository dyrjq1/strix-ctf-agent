"""实例抖动后的第二次机会：沿用同一实例，不销毁重起。

背景（docs/40 §5 / §8-B）：189 道有过结果行的题里有 7 道**从未进入 agent 也
从未解出**，死因全是单次平台抖动——"两个实例都不可达"、"not ready in 180s"。
换实例要重新排队、占配额，节点级故障时还落到同一个坏节点。这里钉三件事：

1. 不可达先在同一实例上重探（30s / 60s 两轮），成功了就不换实例。
2. ``wait_ready`` 超时不拆实例，同实例再等一轮（默认 180s）。
3. 两个开关都能关掉，关掉后行为与改动前一致；重探失败仍走原来的换实例路径。
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
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import batch_eval  # noqa: E402


@pytest.fixture()
def workdir():
    """同 test_batch_eval.py：本机 ``%TEMP%/pytest-of-*`` 属别的账户。"""
    d = Path(tempfile.mkdtemp(prefix="ctfp0-"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------ 探测口径


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("udp", (True, "udp relay open")), ("file", (True, "file-only"))],
)
def test_probe_endpoint_never_marks_udp_or_file_unreachable(kind, expected) -> None:
    """UDP 无连接、附件题无网络目标：探测失败会把好实例换掉。"""
    client = batch_eval.Client("t")
    assert batch_eval._probe_endpoint(client, "x", kind) == expected


def test_probe_endpoint_uses_tcp_probe_for_tcp(monkeypatch) -> None:
    monkeypatch.setattr(batch_eval, "_probe_tcp", lambda target: (False, "refused:x"))
    client = batch_eval.Client("t")
    assert batch_eval._probe_endpoint(client, "host:1", "tcp") == (False, "refused:x")


def test_probe_endpoint_uses_http_probe_for_web(monkeypatch) -> None:
    client = batch_eval.Client("t")
    monkeypatch.setattr(client, "probe_reachable", lambda url: (True, "http 200"))
    assert batch_eval._probe_endpoint(client, "http://a/", "web") == (True, "http 200")


# ------------------------------------------------------------------ 重探


def test_reprobe_stops_at_first_success() -> None:
    seen: list[str] = []

    def probe() -> tuple[bool, str]:
        seen.append("probe")
        return (len(seen) == 2, f"try{len(seen)}")

    slept: list[float] = []
    ok, detail, waited = batch_eval._reprobe(probe, (30, 60), sleep=slept.append)

    assert ok is True and detail == "try2"
    assert waited == 90.0, "第二次探测才成功 ⇒ 等过 30+60"
    assert slept == [30, 60]


def test_reprobe_reports_last_detail_when_never_reachable() -> None:
    calls = iter([(False, "a"), (False, "b")])
    ok, detail, waited = batch_eval._reprobe(
        lambda: next(calls), (30, 60), sleep=lambda _s: None
    )
    assert (ok, detail, waited) == (False, "b", 90.0)


def test_reprobe_with_no_waits_does_not_probe() -> None:
    def probe():  # pragma: no cover - 不应被调用
        raise AssertionError("空等待序列不得探测")

    assert batch_eval._reprobe(probe, (), sleep=lambda _s: None) == (False, "", 0.0)


def test_probe_reuse_switch_env() -> None:
    assert batch_eval._probe_reuse_waits({}) == batch_eval._PROBE_REUSE_WAITS
    assert batch_eval._probe_reuse_waits({"CTF_PROBE_REUSE": "0"}) == ()
    assert batch_eval._probe_reuse_waits({"CTF_PROBE_REUSE": "1"}) == (
        batch_eval._PROBE_REUSE_WAITS
    )


# ------------------------------------------------------------------ ready 复用


def test_ready_reuse_default_and_off_switch() -> None:
    assert batch_eval._ready_reuse_timeout({}) == 180
    for off in ("0", "false", "off", "no"):
        assert batch_eval._ready_reuse_timeout({"CTF_READY_REUSE": off}) == 0
    assert batch_eval._ready_reuse_timeout({"CTF_READY_REUSE": "90"}) == 90


# ------------------------------------------------------------------ 端到端

ANSWER_LOG = "ANSWER[flag]=HTB{late_but_ready}\n"


class _Fake:
    """wait_ready 前 ``fails`` 次抛 TimeoutError，之后返回靶机地址。"""

    fails = 0
    launch_calls = 0
    teardown_calls = 0

    def __init__(self, token: str) -> None:
        self.token = token
        self._waits = 0

    def launch(self, cid: str, attempts: int = 5) -> str:
        type(self).launch_calls += 1
        return "iid-1"

    def wait_ready(self, iid: str, timeout: int = 600) -> str:
        self._waits += 1
        if self._waits <= type(self).fails:
            msg = f"instance {iid} not ready in {timeout}s"
            raise TimeoutError(msg)
        return "http://127.0.0.1:8080/"

    def probe_reachable(self, url: str, attempts: int = 3) -> tuple[bool, str]:
        return True, "ok"

    def detail(self, cid: str) -> dict:
        return {}

    def teardown(self, iid: str) -> None:
        type(self).teardown_calls += 1

    def submit(self, iid: str, answer: str, qid: str = "flag") -> dict:
        return {"correct": True}


def _run(workdir: Path, monkeypatch, fake_cls) -> dict:
    plan = workdir / "plan.json"
    plan.write_text(json.dumps([{"id": "SMOKE-001", "difficulty": "easy"}]), encoding="utf-8")
    out = workdir / "results.jsonl"
    monkeypatch.setattr(batch_eval, "_BOX_ROOT", str(workdir / "boxes"))
    monkeypatch.setattr(batch_eval, "Client", fake_cls)
    monkeypatch.setattr(batch_eval, "run_agent", lambda *a, **k: (ANSWER_LOG, 1.0))
    monkeypatch.setattr(
        sys,
        "argv",
        ["batch_eval.py", "--plan", str(plan), "--out", str(out), "--token", "t",
         "--no-archive", "--no-canary"],
    )
    assert batch_eval.main() == 0
    return json.loads(out.read_text(encoding="utf-8").splitlines()[-1])


def test_second_wait_on_same_instance_saves_the_run(workdir: Path, monkeypatch) -> None:
    """第一次 wait_ready 超时：同实例再等一轮就绪 ⇒ 照常跑，不拆实例。"""
    monkeypatch.setenv("CTF_READY_REUSE", "180")

    class Fake(_Fake):
        fails = 1

    rec = _run(workdir, monkeypatch, Fake)

    assert rec["correct"] is True
    assert not rec.get("skipped")
    assert rec["ready_reuse_s"] == 180
    assert Fake.launch_calls == 1, "不得重新起实例（teardown 只有跑完后的正常清理）"


def test_reuse_off_keeps_old_skip_behaviour(workdir: Path, monkeypatch) -> None:
    """开关关掉：与改动前一致——超时即 SKIP，题不计能力失败。"""
    monkeypatch.setenv("CTF_READY_REUSE", "0")

    class Fake(_Fake):
        fails = 99

    rec = _run(workdir, monkeypatch, Fake)

    assert rec["skipped"] is True
    assert rec["error"].startswith("SKIPPED(实例未就绪)")
    assert Fake.launch_calls == 1