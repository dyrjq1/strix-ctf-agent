"""QA 提交通道：无实例的题答对了必须落账。

线上缺陷：``run_mode == "qa"`` 的题没有 ``target_instance``，旧代码在
``_autosubmit_target`` 处直接返回 ``None``，整条提交链被跳过 —— 答对也是 0 分。
"""

from __future__ import annotations

from typing import Any

from ctf_strix.autosubmit import AutoSubmitter
from ctf_strix.success_stop import answer_verdict, question_correct


class _Success:
    def __init__(self) -> None:
        self.marks: list[tuple[str, str]] = []

    def mark(self, kind: str, detail: str, **_: Any) -> None:
        self.marks.append((kind, detail))


def _qa(**kwargs: Any) -> tuple[AutoSubmitter, list[tuple[str, dict[str, Any]]], _Success]:
    success = _Success()
    sub = AutoSubmitter(
        "https://example.invalid",
        "",
        "tok",
        success=success,
        fallback_question_ids=["q1"],
        fallback_question_modes={"q1": "dynamic"},
        run_mode="qa",
        challenge_id="CHAL",
        competition_id="COMP",
    )
    for key, value in kwargs.items():
        setattr(sub, key, value)
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        calls.append((path, body))
        return {"correct": True, "question_id": body["question_id"], "solve_rank": 1}

    sub._post = fake_post  # type: ignore[method-assign]
    return sub, calls, success


def test_qa_submission_goes_to_qa_endpoint_without_instance_id() -> None:
    """QA 题：端点必须是 ``/api/v1/qa/submissions``，body 不带 instance_id。"""
    sub, calls, success = _qa()
    verdict = sub.submit('we found it, answer: ctf{r34l_qa_answer}')

    assert [path for path, _ in calls] == ["/api/v1/qa/submissions"], calls
    body = calls[0][1]
    assert "instance_id" not in body, body
    assert body == {
        "challenge_id": "CHAL",
        "competition_id": "COMP",
        "question_id": "q1",
        "answer": "ctf{r34l_qa_answer}",
    }
    assert verdict["correct"] == ["q1=ctf{r34l_qa_answer}"], verdict
    assert success.marks == [("platform_submit", "correct=true")], success.marks


def test_qa_never_touches_instance_metadata_endpoint() -> None:
    """``instance`` 为空时不能去 GET ``/api/v1/instances//``。"""
    sub, calls, _ = _qa()
    questions = sub._questions()

    assert questions == [{"id": "q1", "mode": "dynamic"}], questions
    assert calls == []
    assert sub.last_error is None


def test_qa_without_fallback_question_id_sends_nothing() -> None:
    """拿不到 question id 时要安静退出，不抛异常、不发请求。"""
    sub, calls, _ = _qa()
    sub.fallback_question_ids = []

    verdict = sub.submit("answer: ctf{r34l_qa_answer}")

    assert calls == []
    assert verdict["tried"] == []
    assert verdict["correct"] == []
    assert "questions[].id" in verdict["note"], verdict


def test_qa_without_challenge_or_competition_sends_nothing() -> None:
    """请求体缺 challenge_id/competition_id 时不许发 —— 422 会被误读成平台故障。"""
    sub, calls, _ = _qa()
    sub.competition_id = ""

    verdict = sub.submit("answer: ctf{r34l_qa_answer}")

    assert calls == []
    assert "competition_id" in verdict["note"], verdict


def test_instance_submission_is_unchanged() -> None:
    """回归：实例通道仍是 ``/submissions`` + instance_id，且 verify 先跑。"""
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok")
    sub._questions = lambda: [{"id": "q1", "mode": "dynamic"}]  # type: ignore[method-assign]
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        calls.append((path, body))
        if path.endswith("/verify-answer"):
            return {"correct": True, "question_id": body["question_id"]}
        return {
            "correct": True,
            "question_id": body["question_id"],
            "challenge_fully_solved": True,
        }

    sub._post = fake_post  # type: ignore[method-assign]
    verdict = sub.submit("answer: ctf{r34l_qa_answer}")

    assert calls[0][0] == "/api/v1/instances/inst-1/verify-answer", calls
    assert calls[1][0] == "/api/v1/submissions", calls
    assert calls[1][1]["instance_id"] == "inst-1", calls
    assert verdict["correct"] == ["q1=ctf{r34l_qa_answer}"], verdict


def test_qa_placeholder_is_still_filtered() -> None:
    """占位符在 QA 通道同样不许发请求。"""
    sub, calls, _ = _qa()

    verdict = sub.submit("answer: FLAG{...}")

    assert calls == []
    assert verdict["tried"] == []
    assert "没有任何答案候选" in verdict["note"], verdict

def test_qa_stops_at_attempt_cap_and_reports_untried() -> None:
    """qa 每题只有 3 次机会：第 4 个以后不许再打，且要写进 skipped。

    平台对 qa 的作答上限是 3，而 task.json 不带 ``attempts_remaining``。
    不自己记账就会一次把 6 个候选全发出去：正确答案排在后面时机会已经被
    误报耗光，日志里却只看到"试过了"。
    """
    sub, calls, _ = _qa()
    sent: list[dict[str, Any]] = []

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        calls.append((path, body))
        sent.append(body)
        return {"correct": False, "question_id": body["question_id"]}

    sub._post = fake_post  # type: ignore[method-assign]
    summary = "\n".join(f"answer: wrong{i:02d}x" for i in range(5))
    verdict = sub.submit(summary)

    assert len(sent) == 3, sent
    assert all(path == "/api/v1/qa/submissions" for path, _ in calls), calls
    assert "instance_id" not in sent[0], sent[0]
    assert verdict["correct"] == []
    assert any("qa attempt cap 3 reached" in s for s in verdict["skipped"]), verdict
    assert any("2 candidates untried" in s for s in verdict["skipped"]), verdict


def test_instance_mode_without_instance_id_is_not_treated_as_qa() -> None:
    """空 instance 在 instance 模式下是配置错，不能悄悄改走 qa 通道。"""
    sub = AutoSubmitter("https://example.invalid", "", "tok")
    calls: list[tuple[str, dict[str, Any]]] = []
    sub._post = lambda path, body: calls.append((path, body)) or {}  # type: ignore[method-assign]

    verdict = sub.submit("answer: ctf{r34l_qa_answer}")

    assert calls == []
    assert verdict["note"] == "instance mode without instance_id", verdict


#: 平台 qa/submissions 的真实响应形状（2026-11-06 实测）。
_QA_RESPONSE = {
    "id": "8f14e45fceea167a5a36dedd4bea2543",
    "correct": True,
    "question_id": "flag",
    "challenge_fully_solved": True,
    "solve_rank": 56,
}


def test_qa_response_contract_is_graded_correctly() -> None:
    """锁定平台 qa 响应契约：回显 question_id + challenge_fully_solved。

    平台若改了字段名，这里先炸，而不是等到线上"答对记 0 分"才发现。
    """
    assert question_correct(_QA_RESPONSE, "flag")
    assert answer_verdict(_QA_RESPONSE, "flag")
    assert answer_verdict(_QA_RESPONSE, "flag", multiple=True)
    assert not question_correct(_QA_RESPONSE, "other")

    without_flag = {
        k: v for k, v in _QA_RESPONSE.items() if k != "challenge_fully_solved"
    }
    assert not answer_verdict(without_flag, "flag", multiple=True)
