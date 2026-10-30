"""``autosubmit`` 的回归测试。

每一条都对应一个真实故障，不是凑覆盖率：

1. 候选顺序错了 → 把哈希/session id 当答案先交，白白浪费一次提交；
2. 没有候选也发请求 → 空答案会污染平台账本；
3. 串行投递未去重 → 同一 question 被反复提交，日志无法判读；
4. HTTP 失败让收工本身崩掉 → agent 的最后一步炸了，整轮日志丢失；
5. 裁决没写回 summary → 复盘时只能从状态码猜平台说了什么。
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from ctf_strix.autosubmit import AutoSubmitter


def _mk(questions: list[dict[str, Any]]) -> tuple[AutoSubmitter, list[dict[str, Any]]]:
    """造一个 submitter，``_questions`` 返回给定列表，``_post`` 记录所有请求。"""
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok")
    sent: list[dict[str, Any]] = []

    sub._questions = lambda: questions  # type: ignore[method-assign]

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        sent.append(body)
        # 只有交 "right" 才算对，其余判错
        return {"correct": body["answer"] == "right"}

    sub._post = fake_post  # type: ignore[method-assign]
    return sub, sent


def test_explicit_flag_ranks_before_bare_hex() -> None:
    """``FLAG{...}`` 必须排在裸 hex 之前。

    SAMPLE-001 的 slug 是 32 位 hex，而 summary 里同时可能夹着 MD5、session
    id、提交哈希。先交裸 hex 就是把一次提交浪费在噪声上。
    """
    cands = AutoSubmitter.candidates(
        "hash=0123456789abcdef0123456789abcdef real=FLAG{yes_this_one}"
    )
    assert cands[0] == "FLAG{yes_this_one}"
    assert "0123456789abcdef0123456789abcdef" in cands


def test_candidates_dedupe_and_cap() -> None:
    """重复候选要去重，且总量有上限，避免一次收工打出几十个请求。"""
    many = " ".join(f"FLAG{{x{i}}}" for i in range(20))
    cands = AutoSubmitter.candidates(many)
    assert len(cands) <= 6
    assert len(set(cands)) == len(cands)


def test_no_candidate_sends_nothing() -> None:
    """summary 里没有答案形态时，一个请求都不该发。

    空答案提交会污染平台账本，而且会让"没解出"和"解出来但没写对"混为一谈。
    """
    sub, sent = _mk([{"id": "q1", "mode": "dynamic"}])
    verdict = sub.submit("I looked around and found nothing.")
    assert sent == []
    assert verdict["tried"] == []
    assert verdict["note"]


def test_answered_correctly_does_not_block_submission() -> None:
    """``answered_correctly=true`` **不该**挡住提交。

    这条测试是"反向"的，因为它锁死的是一个我自己犯过的错：第一版按这个字段
    过滤，SAMPLE-001 收工时打印 "NOT SUBMITTED: 没有待答的 question"，
    而 slug 明明就在 summary 里。

    平台实测：``answered_correctly=true`` 时提交错误答案是 ``correct:false``，
    提交正确答案是 ``correct:true``——这个标记根本不拦提交，拿它当闸门是自伤。
    """
    sub, sent = _mk([
        {"id": "slug", "mode": "dynamic", "answered_correctly": True},
        {"id": "flag", "mode": "dynamic", "answered_correctly": True},
    ])
    verdict = sub.submit("FLAG{abc}")
    assert [b["question_id"] for b in sent] == ["slug", "flag"]
    assert verdict["tried"], verdict


def test_checker_question_is_skipped() -> None:
    """checker 走 ``/check`` 通道，往 ``/submissions`` 交只会得到 correct:false。"""
    sub, sent = _mk([{"id": "outage", "mode": "checker"}])
    verdict = sub.submit("FLAG{abc}")
    assert sent == []
    # 提示里要说明是"只有非 flag 类 question"，不能笼统说"没有 flag 类"
    assert "非 flag 类" in verdict["note"], verdict


def test_correct_answer_stops_trying_more_candidates() -> None:
    """一个 question 投中后就换下一个 question，别把剩余候选也打出去。"""
    sub, sent = _mk(
        [{"id": "q1", "mode": "dynamic"}, {"id": "q2", "mode": "dynamic"}]
    )
    calls = {"n": 0}

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        sent.append(body)
        calls["n"] += 1
        # q1 的第一个候选就中；q2 全部判错
        return {"correct": body["question_id"] == "q1"}

    sub._post = fake_post  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{right_here}")
    q1_calls = [b for b in sent if b["question_id"] == "q1"]
    assert len(q1_calls) == 1
    assert verdict["correct"] == ["q1=FLAG{right_here}"]


def test_http_error_does_not_raise() -> None:
    """网络失败必须折算成 ``error`` 字段，不能让收工本身炸掉。"""
    sub, _ = _mk([{"id": "q1", "mode": "dynamic"}])
    sub._post = lambda *a, **k: {"error": "HTTP 429"}  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{abc}")
    assert verdict["tried"][0]["error"] == "HTTP 429"
    assert verdict["correct"] == []


def test_decorate_puts_verdict_into_summary() -> None:
    """裁决要写进 summary，否则日志里没有"平台说对/错"的硬证据。"""
    sub, _ = _mk([])
    ok = sub.decorate("done", {"correct": ["q1=FLAG{a}"], "tried": []})
    assert "ACCEPTED" in ok and "q1=FLAG{a}" in ok

    bad = sub.decorate("done", {"correct": [], "tried": [{"qid": "q1"}]})
    assert "REJECTED" in bad

    none = sub.decorate("done", {"correct": [], "tried": [], "note": "无候选"})
    assert "NOT SUBMITTED" in none and "无候选" in none


def test_question_fetch_failure_is_reported_not_swallowed() -> None:
    """拉 question 失败必须说出原因，不能静默变成"本题没有 flag 类 question"。

    这条锁死的是一个排查花了两轮的真实 bug：``_TIMEOUT`` 被写成
    ``(10, 45)`` 元组（requests 的写法），而 urllib 只吃单个浮点数，
    ``urlopen`` 直接抛 TypeError，又被 ``except Exception: return []`` 吞掉。
    日志只有"没有待答的 question"，看起来像题目本身没有 flag 题。
    """
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok")
    sub.platform = "http://127.0.0.1:1"  # 必定连不上
    verdict = sub.submit("FLAG{abc}")
    assert verdict["tried"] == []
    # note 必须是真实错误，而不是那句容易误读的"没有 flag 类 question"
    assert "flag 类 question" not in verdict["note"], verdict
    assert verdict["note"], verdict


def test_verdict_json_serialisable() -> None:
    """tried 里含平台原始字段，必须能直接 json 序列化写进结果文件。"""
    sub, _ = _mk([{"id": "q1", "mode": "dynamic"}])
    verdict = sub.submit("FLAG{abc}")
    json.dumps(verdict)  # 不抛异常即可
