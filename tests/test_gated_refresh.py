# -*- coding: utf-8 -*-
"""G1 gated 题轮内解锁 + G4 competition_paused 等待（合规报告 2026-11-13）。

G1：协议 §2 要求 ``gated_questions > 0`` 时每答对一题重读
``GET /api/v1/challenges/{id}``——新解锁的问题只暴露在 challenge 端点，
轮内看不到就得多烧一整轮靠平台 rounds 补救。刷新结果不自动进提交循环
（旧候选打新题只烧次数），只写进 verdict["unlocked"] 与 decorate 回写。
G4：协议 §4 的 403 ``competition_paused`` 带 ``next_session_starts_at`` /
``retry_after_s``——睡过去重试一次，而不是把整段会话中断窗口内的提交
静默折算成错误。
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402

from ctf_strix import autosubmit as as_mod  # noqa: E402
from ctf_strix.autosubmit import AutoSubmitter  # noqa: E402

AG_SRC = (ROOT / "src" / "ctf_strix" / "agent.py").read_text(encoding="utf-8")
RS_SRC = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
BE_SRC = (ROOT / "scripts" / "batch_eval.py").read_text(encoding="utf-8")


def _http_error(code: int, body: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://p/api", code, "err", None, io.BytesIO(body.encode())  # type: ignore[arg-type]
    )


# -------------------------------------------------------------------- G4
def test_pause_wait_reads_retry_after_s() -> None:
    raw = json.dumps({"error": "competition_paused", "retry_after_s": 30})
    assert as_mod._pause_wait_seconds(raw, 403) == 30.0


def test_pause_wait_reads_next_session_starts_at() -> None:
    starts = (datetime.now(timezone.utc) + timedelta(seconds=120)).isoformat()
    raw = json.dumps({"error": "competition_paused", "next_session_starts_at": starts})
    wait = as_mod._pause_wait_seconds(raw, 403)
    assert wait is not None and 100 < wait < 140


def test_pause_wait_ignores_non_pause_and_non_403() -> None:
    assert as_mod._pause_wait_seconds('{"error": "other"}', 403) is None
    assert as_mod._pause_wait_seconds('{"error": "competition_paused"}', 500) is None
    assert as_mod._pause_wait_seconds("not json", 403) is None


def test_pause_wait_caps_in_run_budget() -> None:
    # 超出轮内等待上限的暂停不值得睡——白烧墙钟，交给 rounds。
    raw = json.dumps({"error": "competition_paused", "retry_after_s": 99999})
    assert as_mod._pause_wait_seconds(raw, 403) is None
    raw_neg = json.dumps({"error": "competition_paused", "retry_after_s": -5})
    assert as_mod._pause_wait_seconds(raw_neg, 403) is None


def test_post_sleeps_and_retries_on_pause(monkeypatch) -> None:
    sub = AutoSubmitter("http://p", "i1", "tok")

    paused = _http_error(
        403,
        json.dumps({"error": "competition_paused", "retry_after_s": 7}),
    )
    ok_body = io.BytesIO(json.dumps({"correct": True}).encode())
    calls = {"n": 0}
    sleeps: list[float] = []

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1:
            raise paused
        return ok_body

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(as_mod.time, "sleep", sleeps.append)

    assert sub._post("/api/v1/submissions", {"a": 1}) == {"correct": True}
    assert calls["n"] == 2
    assert sleeps == [7.0]


def test_post_non_pause_403_is_plain_error(monkeypatch) -> None:
    sub = AutoSubmitter("http://p", "i1", "tok")
    err = _http_error(403, json.dumps({"error": "forbidden"}))

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        raise err

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(as_mod.time, "sleep", lambda s: None)
    res = sub._post("/api/v1/submissions", {})
    assert res["error"].startswith("HTTP 403")


# -------------------------------------------------------------------- G1
def test_questions_from_challenge_parses(monkeypatch) -> None:
    sub = AutoSubmitter("http://p", "i1", "tok", challenge_id="CH1")
    body = io.BytesIO(json.dumps({"questions": [{"id": "slug"}]}).encode())

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        assert "challenges/CH1" in req.full_url
        return body

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert sub._questions_from_challenge() == [{"id": "slug"}]


def test_questions_from_challenge_needs_challenge_id_and_not_qa() -> None:
    sub = AutoSubmitter("http://p", "i1", "tok")
    assert sub._questions_from_challenge() == []
    qa = AutoSubmitter(
        "http://p", "", "tok", run_mode="qa", challenge_id="CH1"
    )
    assert qa._questions_from_challenge() == []


def test_submit_reports_unlocked_without_burning_them(monkeypatch) -> None:
    sub = AutoSubmitter("http://p", "i1", "tok", challenge_id="CH1")

    monkeypatch.setattr(
        sub, "_questions", lambda: [{"id": "slug", "mode": "dynamic"}]
    )
    monkeypatch.setattr(
        sub, "_questions_from_challenge", lambda: [{"id": "slug"}, {"id": "flag"}]
    )
    monkeypatch.setattr(
        sub,
        "_verify",
        lambda qid, ans, multiple=False: None,  # 预检不可用 → 直接提交
    )

    def fake_post(path, body):
        return {"correct": True, "question_id": "slug", "challenge_fully_solved": False}

    monkeypatch.setattr(sub, "_post", fake_post)

    verdict = sub.submit('{"summary": "answer: slugvalue"}')
    assert "slug=slugvalue" in verdict["correct"]
    # 答对 slug 后 challenge 端点暴露了 gated 的 flag 题：报解锁、不自动喂候选。
    assert verdict["unlocked"] == ["flag"]
    assert verdict["challenge_fully_solved"] is False
    # 提交记录里只有 slug——flag 没被旧候选打过一次。
    assert all(row["qid"] == "slug" for row in verdict["tried"])


def test_decorate_carries_unlocked_line() -> None:
    sub = AutoSubmitter("http://p", "i1", "tok")
    out = sub.decorate(
        "summary", {"tried": [], "correct": ["slug=x"], "unlocked": ["flag"]}
    )
    assert "UNLOCKED" in out and "flag" in out


def test_no_unlock_without_correct_answer(monkeypatch) -> None:
    sub = AutoSubmitter("http://p", "i1", "tok", challenge_id="CH1")
    monkeypatch.setattr(
        sub, "_questions", lambda: [{"id": "slug", "mode": "dynamic"}]
    )
    monkeypatch.setattr(
        sub, "_questions_from_challenge", lambda: [{"id": "slug"}, {"id": "flag"}]
    )
    monkeypatch.setattr(sub, "_verify", lambda qid, ans, multiple=False: None)

    def fake_post(path, body):
        return {"correct": False, "question_id": "slug"}

    monkeypatch.setattr(sub, "_post", fake_post)
    verdict = sub.submit('{"summary": "answer: slugvalue"}')
    assert "unlocked" not in verdict


# ---------------------------------------------------------------- 接线钉
def test_agent_instance_path_passes_challenge_id() -> None:
    """实例路径的 AutoSubmitter 与 install 都要带 challenge_id（qa 原本就有）。"""
    assert AG_SRC.count("challenge_id=challenge_id_of(task),") >= 2


def test_harness_wires_challenge_id_through() -> None:
    assert '"--challenge-id"' in RS_SRC
    assert "challenge_id=args.challenge_id" in RS_SRC
    assert '"--challenge-id"' in BE_SRC
    assert "challenge_id=cid" in BE_SRC
