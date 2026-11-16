"""compete.py 调度策略的纯函数单测（无网络）。

钉的是比赛日会反复发生的四类决策：
  1. 先做哪些题——按动态积分剩余价值（``solves_count``）、类别/门控的排序；
  2. 什么时候放弃——连败次数进 deferred（尾巴题有独立预算）；
  3. 后期是否重跑——deferred 题的 solves_count 跳变是「其实可解」信号；
  4. 跨题记忆的简略层——digest 一行一题，且不含任何答案细节
     （全局记忆与题内上下文必须隔开）。
"""

from __future__ import annotations

import json
import re
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
    """同价值档位内 easy 先打（tie-break：更快出分、早解优先）。"""
    chals = [_chal("hard-1", difficulty="hard"), _chal("easy-1")]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["easy-1", "hard-1"]


def test_zero_solve_ranks_above_widely_solved_tail() -> None:
    """动态积分：他队解得越少，剩余分值越高——先打尾巴题。

    2026-11-15 改。旧策略（零解出压后 + 难度 hard 最低权重）在"每题固定分值"
    下成立，在 ``dynamic_points`` 下正好反了：入围赛实测 2 队解出的 crypto 题
    值 970 分、占榜首总分 68.7%，200+ 队解出的 misc 题只剩地板价；而名次
    3–79 共 77 队分数完全相同（442），说明中位题对名次零贡献。
    """
    chals = [_chal("tail", solves_count=2), _chal("crowd", solves_count=200)]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["tail", "crowd"]


def test_value_ordering_is_monotone_in_solver_count() -> None:
    """价值代理只需单调：解出数越少排越前，跨难度标签成立。"""
    chals = [
        _chal("many", solves_count=25),
        _chal("few", solves_count=1, difficulty="hard"),
        _chal("none", solves_count=0, difficulty="hard"),
    ]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["none", "few", "many"]


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


def test_tail_question_keeps_retrying_past_the_short_budget() -> None:
    """尾巴题（他队解出 ≤5 队）有独立重试预算：连败 2 次不判死。

    依据：独立重试是弱模型上证据最强的杠杆（多一次新上下文单题 27.3%→45.5%，
    NDSS LASTx 2026；InterCode-CTF @1 89%→@5 95%）。而在 0–2 队解出的题上，
    deferred 复活所需的 solves_count +3 整场比赛都可能等不到——旧策略等于
    让最值钱的题在第二次失败后永久出局。
    """
    state = {"A": {"status": "active", "fails": 2, "runs": 2}}
    queue, _ = compete.rank_queue(
        [_chal("A", solves_count=1)], state, set(), max_failures=2
    )
    assert [c["id"] for c in queue] == ["A"]
    assert state["A"]["status"] != compete.DEFERRED


def test_tail_question_still_defers_at_its_own_budget() -> None:
    """预算不是无限：到 _TAIL_RETRY_BUDGET 仍要判死，否则会锁死车道。"""
    state = {"A": {"status": "active", "fails": compete._TAIL_RETRY_BUDGET, "runs": 5}}
    queue, notes = compete.rank_queue([_chal("A", solves_count=0)], state, set())
    assert queue == []
    assert state["A"]["status"] == compete.DEFERRED
    assert any("连败" in n for n in notes)


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


# ---------------------------------------------------------------- 会话窗口
def test_session_allows_dispatch_without_sessions() -> None:
    """单场制（无 sessions 字段）：永远放行。"""
    assert compete.session_allows_dispatch(1000.0, None, None, 900) == (True, 0.0)


def test_session_blocks_when_remaining_is_short() -> None:
    """会话只剩 10 分钟、这单要 15 分钟 → 不派，等下一场。

    这是 run2 的真实形态：15:45 会话结束删实例，派单在 15:37 发出，
    跑到一半靶机消失，记成 error/ready 超时。
    """
    ok, wait = compete.session_allows_dispatch(
        1000.0, session_end=1600.0, next_start=2500.0, needed_s=900
    )
    assert ok is False
    assert wait == 1505.0  # 2500-1000+5


def test_session_allows_when_remaining_fits_with_margin() -> None:
    # 剩 1500s，要 900s + 180s 余量 → 放行。
    assert compete.session_allows_dispatch(
        1000.0, 2500.0, 3000.0, 900
    ) == (True, 0.0)
    # 剩 1080s 恰好等于 900+180 → 放行；再少 1 秒就不行。
    assert compete.session_allows_dispatch(1000.0, 2080.0, 3000.0, 900)[0] is True
    assert compete.session_allows_dispatch(1000.0, 2079.0, 3000.0, 900)[0] is False


def test_session_inside_pause_waits_for_next() -> None:
    ok, wait = compete.session_allows_dispatch(
        1700.0, session_end=1600.0, next_start=2500.0, needed_s=60
    )
    assert ok is False
    assert wait == 805.0


def test_wall_tier_matches_batch_eval() -> None:
    """派单判窗用的放大倍数必须与 batch_eval 的 tiers 一致。"""
    for diff, wall_mult in (("easy", 1.0), ("medium", 1.5), ("hard", 2.3)):
        assert compete._WALL_TIER[diff] == wall_mult

def test_each_lane_gets_its_own_vpn_relay_ports(monkeypatch) -> None:
    """三车道并行时中转端口必须互不相同。

    共用一套端口 = B 车道把 A 车道的 target 覆盖掉，隧道握手成功却打在
    别人实例上——最隐蔽的"打错地方"。这里钉住端口随车道线性错开。
    """
    monkeypatch.delenv("CTF_VPN_RELAY_BASE", raising=False)
    envs = [compete._lane_env(i) for i in range(3)]
    relays = [e["CTF_VPN_RELAY"] for e in envs]
    controls = [e["CTF_VPN_RELAY_CONTROL"] for e in envs]
    assert len(set(relays)) == 3
    assert len(set(controls)) == 3
    assert set(relays) & set(controls) == set()
    assert relays[0].endswith(":47444")
    assert controls[0].endswith(":47445")
    assert relays[2].endswith(":47448")


def test_pool_blocked_ids_reads_burned_and_sealed(tmp_path: Path) -> None:
    """池闸门名单必须同时收 sealed_excluded 与 burned。

    漏一边的后果不对称：漏 burned 的题会被派出去、被 batch_eval 拒跑，
    然后在车道里退避重派（2026-11-16 冒烟实测空转 8 分钟）。
    """
    exp = tmp_path / "experiments"
    exp.mkdir()
    (exp / "pools.json").write_text(
        json.dumps(
            {
                "sealed_excluded": ["CTFARENA-047"],
                "burned": ["CTFARENA-064", "SAMPLE-009"],
                "dev": ["CTFARENA-001"],
            }
        ),
        encoding="utf-8",
    )
    assert compete.pool_blocked_ids(tmp_path) == {
        "CTFARENA-047",
        "CTFARENA-064",
        "SAMPLE-009",
    }


def test_pool_blocked_ids_tolerates_missing_and_broken_file(tmp_path: Path) -> None:
    """没有池文件 = 没切池子，不拦；坏文件同样按空集处理（与 batch_eval 同口径）。"""
    assert compete.pool_blocked_ids(tmp_path) == set()
    exp = tmp_path / "experiments"
    exp.mkdir()
    (exp / "pools.json").write_text("{not json", encoding="utf-8")
    assert compete.pool_blocked_ids(tmp_path) == set()


def test_drop_pool_blocked_keeps_order_and_other_ids() -> None:
    """剔除只按题号命中，未列入的题保持原顺序——排序结果不能被抖乱。"""
    chals = [_chal("A"), _chal("B"), _chal("C"), _chal("D")]
    assert [c["id"] for c in compete.drop_pool_blocked(chals, {"B", "D"})] == [
        "A",
        "C",
    ]
    assert [c["id"] for c in compete.drop_pool_blocked(chals, set())] == [
        "A",
        "B",
        "C",
        "D",
    ]


def test_lane_relay_base_is_overridable(monkeypatch) -> None:
    monkeypatch.setenv("CTF_VPN_RELAY_BASE", "50000")
    assert compete._lane_env(1)["CTF_VPN_RELAY"].endswith(":50002")
    assert compete._lane_env(1)["CTF_VPN_RELAY_CONTROL"].endswith(":50003")


def test_attempt_box_is_the_measured_break_even_point() -> None:
    """时间盒基准钉在 300s：它是实测的边际收益拐点，不是随手调小。

    依据（docs/47 §2.3.2，389 条真值 run 离线重放）：73.5% 的解出在 300s 内完成；
    分档盒 300/450/690 丢 10.1% 解出、腾出 31.6% 车道时间（170 次额外尝试），
    盈亏平衡只需 12.3% 的额外尝试解出，而实测同题失败后再试的解出率是 29.2%。
    改这个数字必须重跑那组测量，所以这里把它钉住。
    """
    assert compete._ATTEMPT_BOX_S == 300


def test_parser_default_wallclock_tracks_the_attempt_box() -> None:
    """CLI 默认值必须与常量同源，否则文档与行为会悄悄分叉。"""
    args = compete.build_parser().parse_args(["--token", "t", "--competition", "c"])
    assert args.wallclock == compete._ATTEMPT_BOX_S


def test_tiered_box_matches_the_documented_triple() -> None:
    """难度放大后的实际盒子就是文档里那组 300/450/690。"""
    base = compete._ATTEMPT_BOX_S
    assert [round(base * compete._WALL_TIER[d]) for d in ("easy", "medium", "hard")] == [
        300,
        450,
        690,
    ]


def test_attempt_box_leaves_a_hard_attempt_room_to_finish() -> None:
    """反方向：盒子不能小到连一个正常搜索都放不下。

    p10 的解出尝试要 60s、中位 114s；hard 档 690s 必须显著大于中位解出耗时，
    否则「省时间」会变成「全都跑不完」。
    """
    assert compete._ATTEMPT_BOX_S * compete._WALL_TIER["hard"] >= 4 * 114


# ---------------------------------------------------------------- 题表分页
class _Resp:
    """只够 fetch_challenges 用的最小响应对象。"""

    def __init__(self, body: dict) -> None:
        self._body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._body


def _fake_pages(monkeypatch, total_ids: list[str], *, total=None, ignore_offset=False):
    """装一个按 offset/limit 切页的假平台，返回调用记录。"""
    calls: list[tuple[int, int]] = []

    def fake_get(url, headers=None, params=None, timeout=None):
        params = params or {}
        off = 0 if ignore_offset else int(params.get("offset") or 0)
        lim = int(params.get("limit") or 50)
        calls.append((off, lim))
        page = [{"id": cid} for cid in total_ids[off:off + lim]]
        body = {"items": page, "limit": lim, "offset": off}
        if total is not None:
            body["total"] = total
        return _Resp(body)

    monkeypatch.setattr(compete.requests, "get", fake_get)
    return calls


def test_challenge_table_pages_until_total(monkeypatch) -> None:
    """真平台契约 ``{items, limit, offset, total}`` 且默认 limit=50。

    只取一页时，超过一页的比赛会静默少一半题：不入账、不派单、digest 里也不
    出现，看上去像"平台就这么多题"——是漏题而不是调度取舍。150 题必须三页到齐。
    """
    ids = [f"T-{i:03d}" for i in range(150)]
    calls = _fake_pages(monkeypatch, ids, total=len(ids))
    got = compete.fetch_challenges("t", "c")
    assert [c["id"] for c in got] == ids
    assert calls == [(0, compete._PAGE_LIMIT), (100, compete._PAGE_LIMIT)]


def test_challenge_table_without_total_stays_single_page(monkeypatch) -> None:
    """没有 ``total``（老后端 / 精简 payload）时退回一页就停，行为不变。"""
    calls = _fake_pages(monkeypatch, ["A", "B"], total=None)
    got = compete.fetch_challenges("t", "c")
    assert [c["id"] for c in got] == ["A", "B"]
    assert len(calls) == 1


def test_challenge_table_stops_when_a_page_repeats(monkeypatch) -> None:
    """服务端忽略 offset（永远回第一页）时不能死循环，也不能重复入账。"""
    ids = [f"T-{i:03d}" for i in range(150)]
    calls = _fake_pages(monkeypatch, ids, total=150, ignore_offset=True)
    got = compete.fetch_challenges("t", "c")
    assert [c["id"] for c in got] == ids[: compete._PAGE_LIMIT]
    assert len(calls) == 2  # 第二页没有新 id → 停


# ---------------------------------------------------------------- 失败重派：换入口方向
#
# 同题失败后重派不是原样重放：第二次起换一个机制类别起步。预算不动（同一次
# 尝试的开销与第一次一样），协议也不动（只走 --retry-notes 这一个显式文件）。


def test_first_attempt_never_gets_a_direction() -> None:
    """首跑注入方向 = 给所有题统一加偏置，那是没有对照的改动。"""
    assert compete.entry_direction(0) is None
    assert compete.entry_direction(1) is None


def test_retry_directions_rotate_through_every_class() -> None:
    total = len(compete._ENTRY_DIRECTIONS)
    picks = [compete.entry_direction(n) for n in range(2, 2 + total)]
    labels = [p[0] for p in picks]
    assert len(set(labels)) == total, "两个尝试序号给了同一个方向"
    wrap = compete.entry_direction(2 + total)
    assert wrap is not None and wrap[0] == picks[0][0], "用完之后要回到起点"


def test_retry_directions_stay_generic() -> None:
    """命名测试：方向表不得含题号、IP、路径或 flag 片段。"""
    joined = " ".join(text for _, text in compete._ENTRY_DIRECTIONS)
    assert not re.search(r"[A-Z]{3,}-\d+", joined), "题号进了方向表"
    assert "flag{" not in joined.lower()
    assert "http://" not in joined.lower() and "https://" not in joined.lower()
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", joined), "IP 进了方向表"
    for label, text in compete._ENTRY_DIRECTIONS:
        assert label.islower() and label.isascii()
        assert len(text) <= 80, f"{label} 说明过长，会挤占尝试的上下文"


def test_first_run_writes_no_retry_notes() -> None:
    assert compete.build_retry_notes(None, None, 1) == ""


def test_retry_notes_put_evidence_before_the_new_direction() -> None:
    text = compete.build_retry_notes(
        ["收场：no_progress"], compete.entry_direction(2), 2
    )
    assert "上一轮失败路径" in text and "收场：no_progress" in text
    assert "本次换入口方向" in text
    assert text.index("上一轮失败路径") < text.index("本次换入口方向")
    assert "第 2 次尝试" in text
    assert text.endswith("\n")


def test_direction_alone_still_produces_notes() -> None:
    """上一轮没有结构化失败事实（例如 infra skip）时，方向仍然要说。"""
    text = compete.build_retry_notes(None, compete.entry_direction(3), 3)
    assert "本次换入口方向" in text
    assert "上一轮失败路径" not in text


def test_each_attempt_moves_to_a_different_direction() -> None:
    """连续重派必须换向：第 2、3 次尝试不能给出同一个类别。"""
    seen = [compete.entry_direction(n)[0] for n in (2, 3, 4)]
    assert len(set(seen)) == len(seen)


def test_plan_item_is_untouched_by_the_direction() -> None:
    """换向只走 notes 文件；派单项仍然只有 id/difficulty。"""
    item = compete.build_plan_item("A", _chal("A"))
    assert set(item) == {"id", "difficulty"}


def _fake_popen(monkeypatch) -> dict:
    """拦下子进程启动，只留命令行：测的是「写了什么文件、带了什么参数」。"""
    captured: dict = {}

    def fake(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        stream = kwargs.get("stdout")
        if hasattr(stream, "close"):
            stream.close()  # 真的 Popen 会接管这个句柄；假的不接管就得自己关
        return object()

    monkeypatch.setattr(compete.subprocess, "Popen", fake)
    return captured


def _args(**kw):
    argv = ["--token", "t", "--competition", "c", *sum(([f"--{k}", str(v)] for k, v in kw.items()), [])]
    return compete.build_parser().parse_args(argv)


def test_spawn_writes_the_retry_notes_file_for_a_retry(tmp_path, monkeypatch) -> None:
    captured = _fake_popen(monkeypatch)
    args = _args()
    direction = compete.entry_direction(2)
    assert direction is not None
    compete._spawn(
        _chal("A"),
        args,
        tmp_path,
        failure_path=["收场：no_progress"],
        direction=direction,
        attempt=2,
    )
    cmd = captured["cmd"]
    assert "--retry-notes" in cmd
    notes = Path(cmd[cmd.index("--retry-notes") + 1])
    text = notes.read_text(encoding="utf-8")
    assert "上一轮失败路径" in text and "本次换入口方向" in text
    # 派单项仍然干净（隔离不变量在真 _spawn 路径上也成立）。
    plan = json.loads((tmp_path / "runs" / "plan-A.json").read_text(encoding="utf-8"))
    assert plan == [{"id": "A", "difficulty": "easy"}]


def test_spawn_on_the_first_attempt_writes_no_notes(tmp_path, monkeypatch) -> None:
    captured = _fake_popen(monkeypatch)
    compete._spawn(_chal("A"), _args(), tmp_path, failure_path=None, direction=None, attempt=1)
    assert "--retry-notes" not in captured["cmd"]
    assert not (tmp_path / "runs" / "retry-notes-A.txt").exists()
