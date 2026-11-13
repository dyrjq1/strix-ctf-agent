"""compete.py 调度策略的纯函数单测（无网络）。

钉的是比赛日会反复发生的四类决策：
  1. 先做哪些题——难度/类别/可解性证据/门控的排序；
  2. 什么时候放弃——连败次数进 deferred；
  3. 后期是否重跑——deferred 题的 solves_count 跳变是「其实可解」信号；
  4. 跨题记忆的简略层——digest 一行一题，且不含任何答案细节
     （全局记忆与题内上下文必须隔开）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import compete  # noqa: E402


def _chal(cid: str, **kw) -> dict:
    base = {
        "id": cid,
        "category": "web",
        "difficulty": "easy",
        "solves_count": 10,
        "questions": [],
        "closed": False,
        "is_qa_only": False,
    }
    base.update(kw)
    return base


def test_solved_closed_are_not_queued_but_qa_only_is() -> None:
    """qa_only 是**可交付**题型（/qa/submissions），不再被排除。

    2026-11-13 夜：平台 questions 带 mode=single_select/multi_select/static，
    QA 题库题没有实例但有题面；旧码在入口把 is_qa_only 直接判 None，
    整类题从未进过队列。已由 batch_eval 的无实例分支接管。
    """
    chals = [
        _chal("A"),
        _chal("B", closed=True),
        _chal("C", is_qa_only=True),
        _chal("D"),
    ]
    queue, _ = compete.rank_queue(chals, {}, {"D"})
    # QA 题有 +30 权重（不占实例、无启动开销），同档位排在前面。
    assert [c["id"] for c in queue] == ["C", "A"]


def test_easier_difficulty_ranks_first() -> None:
    """动态积分：早解优先，easy 先打。"""
    chals = [_chal("hard-1", difficulty="hard"), _chal("easy-1")]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["easy-1", "hard-1"]


def test_proven_solvable_ranks_above_zero_solve() -> None:
    """solves_count 是唯一难度代理：零解出题压后，等可解性证据。"""
    chals = [_chal("solo", solves_count=0), _chal("known", solves_count=5)]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["known", "solo"]


def test_web_ranks_above_other_categories_at_same_tier() -> None:
    """web 是实测强项（解出率 83%），同档位优先。"""
    chals = [_chal("crypto-1", category="crypto"), _chal("web-1")]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["web-1", "crypto-1"]


def test_consecutive_failures_defer_the_question() -> None:
    state = {"A": {"status": "active", "fails": 2, "runs": 2}}
    queue, notes = compete.rank_queue([_chal("A")], state, set(), max_failures=2)
    assert queue == []
    assert state["A"]["status"] == compete.DEFERRED
    assert any("deferred" in n for n in notes)


def test_deferred_requeues_when_solves_count_jumps() -> None:
    """他队解出数上涨 = 可解性证据：后期重跑的唯一触发条件。"""
    state = {"A": {"status": "deferred", "fails": 2, "solves_count_seen": 3}}
    chal = _chal("A", solves_count=6)  # +3 达标
    queue, notes = compete.rank_queue([chal], state, set())
    assert [c["id"] for c in queue] == ["A"]
    assert state["A"]["status"] == compete.ACTIVE
    assert any("deferred→active" in n for n in notes)


def test_deferred_stays_put_without_a_jump() -> None:
    state = {"A": {"status": "deferred", "fails": 2, "solves_count_seen": 3}}
    queue, _ = compete.rank_queue([_chal("A", solves_count=4)], state, set())
    assert queue == []
    assert state["A"]["status"] == compete.DEFERRED


def test_gating_bonus_when_prerequisites_are_solved() -> None:
    """门控题：前置问题已解 → 解一个解锁一串（优先级上调）。"""
    chal = _chal("B", questions=[{"id": "b1", "requires": ["a1"]}])
    without = compete.challenge_score(chal, {}, set())
    with_pre = compete.challenge_score(chal, {}, {"a1"})
    assert without is not None and with_pre is not None
    assert with_pre - without == 40


def test_digest_is_one_line_per_question_and_leaks_no_secrets() -> None:
    """简略层只有状态/类别/解出数/一句话——答案细节永远不进 digest。"""
    state = {
        "A": {"status": "solved", "runs": 1, "one_line": "solved"},
        "B": {"status": "failed", "runs": 2, "one_line": "rounds_exhausted"},
    }
    chals = [_chal("A"), _chal("B", category="pwn"), _chal("C", difficulty="hard")]
    digest = compete.build_digest(state, chals)
    for cid in ("A", "B", "C"):
        assert f"| {cid} |" in digest
    assert "FLAG{" not in digest
    assert "answer" not in digest.lower()


def test_read_last_result_takes_the_last_record_for_that_challenge(tmp_path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "A.jsonl").write_text(
        json.dumps({"challenge": "A", "correct": False}) + "\n"
        + json.dumps({"challenge": "X", "correct": True}) + "\n"
        + json.dumps({"challenge": "A", "correct": True}) + "\n",
        encoding="utf-8",
    )
    rec = compete.read_last_result(tmp_path, "A")
    assert rec is not None and rec["correct"] is True
    assert compete.read_last_result(tmp_path, "Z") is None



# ---------------------------------------------------------------- 隔离不变量
def test_plan_item_carries_only_the_question_not_the_global_memory() -> None:
    """派单项只允许 id/difficulty：全局记忆（state/digest/既往报告）绝不进题内。

    这是「上下文分割」的执行点——上一题的结论、失败原因、别的题的
    答案，任何东西漏进去都等于把题内上下文污染了。
    """
    chal = _chal(
        "A",
        description="ANSWER[flag: secret",
        notes="prior failure notes",
        state={"solved": True},
    )
    item = compete.build_plan_item("A", chal)
    assert set(item) == {"id", "difficulty"}
    assert item["id"] == "A"
    assert "secret" not in str(item)
    assert "prior" not in str(item)


def test_plan_item_allow_pools_flag_is_the_only_extra_key() -> None:
    item = compete.build_plan_item("A", _chal("A"), allow_pools=True)
    assert set(item) == {"id", "difficulty", "allow_burned", "allow_sealed"}


# --- B-23：基础设施型跳过（SKIPPED）不得无限重派 ---------------------------
#
# run2 实录：三道题各被重派 20+ 次，每次都在接入阶段判死（skipped:true），
# 但 skipped 不计入 fails，放弃判据永远不触发。必须单独计数并同样 defer；
# 同时它不是题目不可解的证据，不该混进 fails 压优先级。


def _write_run(state_dir, cid: str, rec: dict) -> None:
    runs = state_dir / "runs"
    runs.mkdir(exist_ok=True)
    with open(runs / f"{cid}.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"challenge": cid, **rec}) + "\n")


def test_collect_counts_skip_as_infra_not_failure(tmp_path) -> None:
    state: dict = {}
    _write_run(tmp_path, "A", {"skipped": True, "error": "SKIPPED(需隧道)"})
    assert compete._collect("A", state, tmp_path) == compete.FAILED
    assert state["A"]["skips"] == 1
    assert state["A"].get("fails", 0) == 0


def test_collect_real_run_resets_the_skip_streak(tmp_path) -> None:
    state = {"A": {"skips": 1, "fails": 0, "runs": 1}}
    _write_run(
        tmp_path, "A",
        {"skipped": False, "correct": False, "stop_reason": "rounds_exhausted"},
    )
    compete._collect("A", state, tmp_path)
    assert state["A"]["skips"] == 0
    assert state["A"]["fails"] == 1


def test_consecutive_infra_skips_defer_without_counting_as_fails() -> None:
    state = {"A": {"status": "failed", "fails": 0, "skips": 2, "runs": 2}}
    queue, notes = compete.rank_queue([_chal("A")], state, set(), max_failures=2)
    assert queue == []
    assert state["A"]["status"] == compete.DEFERRED
    assert state["A"]["fails"] == 0
    assert any("infra-skip" in n for n in notes)


def test_single_skip_does_not_defer_or_penalize() -> None:
    """偶发一次 infra-skip 不判死，也不吃连败惩罚分。"""
    state = {"A": {"status": "failed", "fails": 0, "skips": 1, "runs": 1}}
    queue, _ = compete.rank_queue([_chal("A")], state, set(), max_failures=2)
    assert [c["id"] for c in queue] == ["A"]


def test_reactivation_clears_the_skip_streak_too() -> None:
    state = {"A": {"status": "deferred", "skips": 2, "solves_count_seen": 3}}
    queue, _ = compete.rank_queue([_chal("A", solves_count=6)], state, set())
    assert [c["id"] for c in queue] == ["A"]
    assert state["A"]["skips"] == 0


def test_platform_solved_ids_backfill_state() -> None:
    """平台说已解 → state 立刻 solved；未解的不动；本地计数保留。"""
    state = {
        "A": {"status": "active", "runs": 3, "fails": 1},
        "B": {"status": "deferred", "fails": 2},
    }

    added = compete.merge_platform_solves(state, {"B", "C"})

    assert added == ["B", "C"]
    assert state["A"]["status"] == "active"
    assert state["B"]["status"] == "solved"
    assert state["B"]["fails"] == 2, "回灌不得抹掉本地记账"
    assert state["C"]["status"] == "solved"


def test_platform_solved_merge_is_idempotent() -> None:
    state = {"B": {"status": "solved"}}

    assert compete.merge_platform_solves(state, {"B"}) == []


def test_fetch_my_solves_parses_both_shapes(monkeypatch) -> None:
    """平台返回 list[dict] 或 {"items": [...]} 都要吃得下。"""

    class _R:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    monkeypatch.setattr(
        compete.requests,
        "get",
        lambda *a, **k: _R([{"challenge_id": "A"}, "B", {"nope": 1}, {"challenge_id": ""}]),
    )
    assert compete.fetch_my_solves("tok", "comp") == {"A", "B"}

    monkeypatch.setattr(
        compete.requests, "get", lambda *a, **k: _R({"items": [{"challenge_id": "C"}]})
    )
    assert compete.fetch_my_solves("tok", "comp") == {"C"}


def test_deadline_reached_accepts_none_and_epochs() -> None:
    """B-30：--until 的判据在等待循环里也要能用。"""
    import time

    assert compete.deadline_reached(None) is False
    assert compete.deadline_reached(time.time() - 1) is True
    assert compete.deadline_reached(time.time() + 600) is False
