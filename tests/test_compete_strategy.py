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

import pytest

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


def test_value_ordering_is_monotone_within_the_proven_tier() -> None:
    """同一档（他队已解出）内，解出数越少排越前——跨难度标签成立。"""
    chals = [
        _chal("many", solves_count=25),
        _chal("few", solves_count=1, difficulty="hard"),
    ]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["few", "many"]


def test_proven_solvable_ranks_above_zero_solve() -> None:
    """「别人解出来了」优先于「没人解出来」（2026-11-19 用户定调）。

    我方 agent 能力有限：0 解出的题对我们实测是 0 收益（11-19 测试赛 9 次
    尝试全在 0 解出题上，全部 wallclock 收场），可解性证据比剩余分值更值钱。
    分档隔离：未解出题的理论最高分（web easy qa 门控全给）也压不过地板价的
    已解出题。
    """
    chals = [
        _chal("none-web-easy", solves_count=0),
        _chal("proven-floor", solves_count=200, category="crypto", difficulty="hard"),
    ]
    queue, _ = compete.rank_queue(chals, {}, set())
    assert [c["id"] for c in queue] == ["proven-floor", "none-web-easy"]

    top_unsolved = _chal(
        "top",
        solves_count=0,
        is_qa_only=True,
        questions=[{"id": "q", "requires": ["pre"]}],
    )
    floor_proven = _chal(
        "floor", solves_count=200, category="crypto", difficulty="hard"
    )
    a = compete.challenge_score(top_unsolved, {}, {"pre"})
    b = compete.challenge_score(floor_proven, {}, set())
    assert a is not None and b is not None and b > a


def test_category_weight_is_neutral_without_competition_evidence() -> None:
    """类别平权：'web 是强项'的先验（练习套 40/48）在比赛条件下不成立。

    练习套的 83.3% 是题目级、有重试、预算 600–1800s 的数字；单次尝试口径
    只有 62.9%。比赛条件下的 web 样本只有入围赛一道（4 个 checkpoint 全解，
    样本量 1）。没数据就不给权重——要加回来，先有比赛条件下的解出率。
    """
    chals = [_chal("crypto-1", category="crypto"), _chal("web-1")]
    queue, _ = compete.rank_queue(chals, {}, set())
    # 同价值、同难度 → 同分，按 id 兜底排序；web 不因类别占先。
    assert [c["id"] for c in queue] == ["crypto-1", "web-1"]
    a = compete.challenge_score(_chal("c1", category="crypto"), {}, set())
    b = compete.challenge_score(_chal("w1", category="web"), {}, set())
    assert a == b


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


def test_a_retried_question_comes_back_on_a_different_lane() -> None:
    """同题重派必须换车道——车道号就是模型号。

    2026-11-19 实测：三题各自钉死一条车道连跑四轮，同一模型的同一盲区
    被重复消费。首次派单走 0，重派依次 1、2，第四轮循环回 0。
    """
    rec: dict = {}
    lanes = []
    for _ in range(4):
        lane = compete._choose_lane([0, 1, 2], rec, 3)
        rec["last_lane"] = lane
        rec["lane_history"] = (list(rec.get("lane_history") or []) + [lane])[-6:]
        lanes.append(lane)
    assert lanes == [0, 1, 2, 0]


def test_lane_choice_skips_the_lane_that_is_busy() -> None:
    """首选车道被占用时退到空闲里用得最少的那条，不撞车。"""
    rec = {"last_lane": 0, "lane_history": [0]}
    assert compete._choose_lane([1, 2], rec, 3) == 1
    assert compete._choose_lane([0], rec, 3) == 0


def test_lane_choice_is_deterministic_and_tolerates_junk() -> None:
    """空列表兜底 0；历史里的非数字被忽略，不抛异常。"""
    assert compete._choose_lane([], {}, 2) == 0
    rec = {"lane_history": ["x", None, 1.0]}
    assert compete._choose_lane([0, 1], rec, 2) == 0


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
    envs = [compete._lane_env(i, relay_up=True) for i in range(3)]
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
    env = compete._lane_env(1, relay_up=True)
    assert env["CTF_VPN_RELAY"].endswith(":50002")
    assert env["CTF_VPN_RELAY_CONTROL"].endswith(":50003")


def test_no_relay_env_when_the_host_relay_is_not_running() -> None:
    """VPS 上没有宿主机中转：不注入这两个变量，子进程直接走直连。

    11-19 实测：中转控制口每次先吃 3s 超时、再吃一次注定失败的握手，
    每个实例白花 5–20s；而真正把隧道拉起来的是后面的直连路径。
    """
    env = compete._lane_env(0, relay_up=False)
    assert "CTF_VPN_RELAY" not in env
    assert "CTF_VPN_RELAY_CONTROL" not in env


def test_relay_probe_is_cached_per_host(monkeypatch) -> None:
    """探测结果按 host 缓存，派单处不会每次派单都去连一遍。"""
    calls = []

    def fake_connect(addr, timeout=0):  # noqa: ANN001, ARG001
        calls.append(addr)
        raise OSError("nope")

    monkeypatch.setattr(compete.socket, "create_connection", fake_connect)
    monkeypatch.setattr(compete, "_relay_state", {})
    assert compete._relay_up("10.255.255.1") is False
    assert compete._relay_up("10.255.255.1") is False
    assert calls == [("10.255.255.1", 47445)]


def test_sweep_vpn_ifaces_removes_only_wireguard_ones(monkeypatch) -> None:
    """停止后清残留接口，但只碰 ``wg<pid>`` 形状的，别把 eth0 拆了。"""

    class Proc:
        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout

    calls: list[list[str]] = []

    def fake_run(cmd, **kw):  # noqa: ANN001, ARG001
        calls.append(list(cmd))
        if cmd[:3] == ["ip", "-br", "link"]:
            return Proc("wg65350  UNKNOWN\nlo  UNKNOWN\neth0  UP\n")
        return Proc()

    monkeypatch.setattr(compete.subprocess, "run", fake_run)

    assert compete._sweep_vpn_ifaces() == ["wg65350"]
    assert ["ip", "link", "del", "wg65350"] in calls
    assert all("eth0" not in " ".join(c) for c in calls)


def test_lane_stagger_defaults_to_30s() -> None:
    """车道默认错峰 30s：三条车道同一秒起跑会一起压平台/边缘节点。"""
    args = compete.build_parser().parse_args(["--token", "t", "--competition", "c"])
    assert args.lane_stagger == 30.0


def test_sweep_orphans_reaps_only_dead_owners(monkeypatch) -> None:
    """停止信号强杀子进程后，台账里主人已死的实例要被回收。"""
    deleted: list[str] = []
    forgotten: list[str] = []

    monkeypatch.setattr(
        compete.batch_eval, "_ledger_dead_ids", lambda: {"dead-1", "dead-2"}
    )
    monkeypatch.setattr(compete.batch_eval, "_ledger_forget", forgotten.append)

    class Resp:
        status_code = 202

    def fake_delete(url, headers=None, timeout=0, **kw):  # noqa: ANN001, ARG001
        deleted.append(url.rsplit("/", 1)[-1])
        return Resp()

    monkeypatch.setattr(compete.requests, "delete", fake_delete)

    assert compete._sweep_orphans("tok") == ["dead-1", "dead-2"]
    assert deleted == ["dead-1", "dead-2"]
    assert forgotten == ["dead-1", "dead-2"]


def test_sweep_orphans_keeps_the_ledger_entry_on_failure(monkeypatch) -> None:
    """DELETE 失败时不能抹台账——否则下次没人认领这具尸体。"""
    forgotten: list[str] = []

    monkeypatch.setattr(compete.batch_eval, "_ledger_dead_ids", lambda: {"dead-1"})
    monkeypatch.setattr(compete.batch_eval, "_ledger_forget", forgotten.append)

    class Resp:
        status_code = 503

    monkeypatch.setattr(compete.requests, "delete", lambda *a, **kw: Resp())
    assert compete._sweep_orphans("tok") == []
    assert forgotten == []


def test_attempt_box_is_the_single_wall_cap() -> None:
    """时间盒基准钉在 900s = ``limits.MAX_WALLCLOCK_S``，与 agent 同一个上限。

    2026-11-19 用户改定：此前是 300s 基准 + 300/450/690 分档（依据是 docs/47
    §2.3.2 的离线重放拐点）。改的理由不是"想跑久一点"，是当天 14 次尝试**全部**
    死在墙钟、``turn_capped`` 一次都没有——切得早的不是模型。既然上限统一到
    900s，基准和上限就是同一个数，分档也不再能把它推上去。
    """
    assert compete._ATTEMPT_BOX_S == 900


def test_parser_default_wallclock_tracks_the_attempt_box() -> None:
    """CLI 默认值必须与常量同源，否则文档与行为会悄悄分叉。"""
    args = compete.build_parser().parse_args(["--token", "t", "--competition", "c"])
    assert args.wallclock == compete._ATTEMPT_BOX_S


def test_tiered_box_is_clamped_to_the_single_cap() -> None:
    """难度倍数是派单前的窗口估算，但算出来的值一律夹在 900s 以内。"""
    base = compete._ATTEMPT_BOX_S
    caps = [
        min(round(base * compete._WALL_TIER[d]), compete._LIMITS_MAX_WALL_S)
        for d in ("easy", "medium", "hard")
    ]
    assert caps == [900, 900, 900]


def test_attempt_box_leaves_a_hard_attempt_room_to_finish() -> None:
    """反方向：盒子不能小到连一个正常搜索都放不下。

    p10 的解出尝试要 60s、中位 114s；900s 必须显著大于中位解出耗时，
    否则「省时间」会变成「全都跑不完」。
    """
    assert min(
        compete._ATTEMPT_BOX_S * compete._WALL_TIER["hard"],
        compete._LIMITS_MAX_WALL_S,
    ) >= 4 * 114


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


def test_the_same_fact_is_not_written_twice_under_two_prefixes() -> None:
    """2026-11-19 实测的重试提示：
    ``异常收场：transport:httpx.ReadError；异常：transport:httpx.ReadError``。
    3 行预算里一行是重复的，等于把「上一轮做了什么」砍掉三分之一。
    """
    lines = compete._failure_lines(
        {
            "error": "transport:httpx.ReadError",
            "failure_path": ["异常：transport:httpx.ReadError；轨迹：11 次请求 / 4 组重复响应"],
        }
    )
    assert len(lines) == 2, lines
    assert sum("ReadError" in line for line in lines) == 1
    assert any("轨迹" in line for line in lines), "去重不能顺手丢掉另一条事实"


def test_three_distinct_facts_all_survive() -> None:
    lines = compete._failure_lines(
        {
            "stop_reason": "wallclock",
            "answers_rejected": {"flag": "nope"},
            "checker_checked": ["precheck"],
        }
    )
    assert len(lines) == 3


def test_the_new_digest_lines_reach_the_retry_notes() -> None:
    """失败描述四件套（收场 / 探到 / 试过 / 卡）一条都不许被 3 行上限吃掉。"""
    rec = {
        "stop_reason": "wallclock",
        "failure_path": [
            "收场：wallclock",
            "探到：host=h.test family=http://h.test/admin；码 404×7",
            "试过：GET /admin/panel→404 POST /api/login→401",
            "卡：web-auth",
        ],
    }

    lines = compete._failure_lines(rec)
    text = "\n".join(lines)

    assert len(lines) == 4
    for needle in ("收场：wallclock", "探到：", "试过：", "卡：web-auth"):
        assert needle in text


def test_each_attempt_moves_to_a_different_direction() -> None:
    """连续重派必须换向：第 2、3 次尝试不能给出同一个类别。"""
    seen = [compete.entry_direction(n)[0] for n in (2, 3, 4)]
    assert len(set(seen)) == len(seen)


@pytest.mark.parametrize("value", ["0", "false", "no", "off", " OFF ", "False"])
def test_directions_can_be_switched_off(monkeypatch, value: str) -> None:
    """关掉开关 = A/B 的对照臂：与 ``CTF_BROWSER`` 同形，只认否定的那四个词。"""
    monkeypatch.setenv(compete.DIRECTIONS_ENV, value)
    assert compete.directions_enabled() is False


@pytest.mark.parametrize("value", ["", "1", "true", "yes", "on", "anything"])
def test_directions_default_on_and_accept_no_positive_override(
    monkeypatch, value: str
) -> None:
    """没有正向覆盖：除那四个否定词外一律生效，拼错的开关不会静默改行为。"""
    monkeypatch.setenv(compete.DIRECTIONS_ENV, value)
    assert compete.directions_enabled() is True


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


# ---------------------------------------------------------------- 车道厂商配置

def _lane_conf(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "lanes.conf"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_lane_config_parses_and_skips_comments(tmp_path: Path) -> None:
    """一行一车道四段；# 注释与空行跳过；首尾空白剥掉。"""
    p = _lane_conf(
        tmp_path,
        [
            "# 三家厂商，凭据当天建会话",
            "",
            " deepseek | https://api.deepseek.com/v1 | sk-a | deepseek-v4.1-flash ",
            "bailian|https://dashscope.aliyuncs.com/compatible-mode/v1|sk-b|qwen3-max",
        ],
    )
    lanes = compete.load_lane_config(p)
    assert [l["name"] for l in lanes] == ["deepseek", "bailian"]
    assert lanes[0]["LLM_API_BASE"] == "https://api.deepseek.com/v1"
    assert lanes[0]["LLM_API_KEY"] == "sk-a"
    assert lanes[0]["model"] == "deepseek-v4.1-flash"


def test_lane_config_rejects_malformed_line(tmp_path: Path) -> None:
    """少一段/空段 = 启动即失败，报行号。半份凭据跑起来的假 401 更贵。"""
    p = _lane_conf(tmp_path, ["ok|https://x/v1|sk-a|m", "bad|https://y/v1|"])
    with pytest.raises(ValueError, match="第 2 行"):
        compete.load_lane_config(p)


def test_lane_config_rejects_empty_file(tmp_path: Path) -> None:
    p = _lane_conf(tmp_path, ["", "# 只有注释"])
    with pytest.raises(ValueError, match="没有可用行"):
        compete.load_lane_config(p)


def _lm(i: str, base: str, model: str) -> dict[str, str]:
    return {
        "name": i,
        "LLM_API_BASE": base,
        "LLM_API_KEY": f"sk-{i}",
        "model": model,
    }


def test_single_lane_needs_no_lane_config() -> None:
    """一条车道时不必分厂商（串行轮转的老用法保持不变）。"""
    assert compete.distinct_lane_error(1, None) is None


def test_three_lanes_without_config_are_refused() -> None:
    """三实例三会话共用一个 API = 用户明令禁止：实例三个、脑子一个。"""
    msg = compete.distinct_lane_error(3, None)
    assert msg and "--lane-config" in msg


def test_three_distinct_vendors_pass() -> None:
    lanes = [
        _lm("a", "https://a.llm-next.ctfy.io/v1", "m-a"),
        _lm("b", "https://b.llm-next.ctfy.io/v1", "m-b"),
        _lm("c", "https://c.llm-next.ctfy.io/v1", "m-c"),
    ]
    assert compete.distinct_lane_error(3, lanes) is None


def test_duplicate_vendor_in_parallel_lanes_is_refused() -> None:
    """同 base 同模型（哪怕尾斜杠/名字不同）也算同一个 API。"""
    lanes = [
        _lm("a", "https://a.llm-next.ctfy.io/v1", "m-a"),
        _lm("b", "https://a.llm-next.ctfy.io/v1/", "m-a"),
        _lm("c", "https://c.llm-next.ctfy.io/v1", "m-c"),
    ]
    msg = compete.distinct_lane_error(3, lanes)
    assert msg and "lane 1" in msg and "lane 0" in msg


def test_same_host_different_model_still_counts_as_one_api() -> None:
    """同一家网关换模型名不算换厂商——同一份 key 打同一个上游。"""
    lanes = [
        _lm("a", "https://gw.llm-next.ctfy.io/v1", "qwen4-max"),
        _lm("b", "https://gw.llm-next.ctfy.io/v1", "deepseek-flash"),
    ]
    assert compete.distinct_lane_error(2, lanes) is not None


def test_a_duplicate_row_beyond_the_lane_count_is_still_refused() -> None:
    """4 行配置跑 3 车道：第 4 行也可能被借去跑重派，重复行一样拒绝。"""
    lanes = [
        _lm("a", "https://a/v1", "m-a"),
        _lm("b", "https://b/v1", "m-b"),
        _lm("c", "https://c/v1", "m-c"),
        _lm("a2", "https://a/v1", "m-a"),
    ]
    assert compete.distinct_lane_error(3, lanes) is not None


def test_slot_rotation_changes_the_vendor_on_retry() -> None:
    """3 条车道配 4 家厂商时，重派要能换到第 4 家，不被车道数卡住。"""
    rec: dict = {}
    slots = []
    for busy in ([], [1, 2], [1], []):
        free = [i for i in range(4) if i not in busy]
        slot = compete._pick_slot(free, rec, fallback=0)
        rec["last_slot"] = slot
        rec["slot_history"] = (list(rec.get("slot_history") or []) + [slot])[-6:]
        slots.append(slot)
    # 首轮 0；其余两家被占时换到第 4 家 3；再下一轮换 2；全空时换 1。
    # 关键性质：每一轮都不是上一轮那一家（除非只剩它）。
    assert slots == [0, 3, 2, 1], slots
    assert all(a != b for a, b in zip(slots, slots[1:]))


def test_all_slots_busy_falls_back_to_the_lane_number() -> None:
    """厂商数 < 并发数（配置不全）时退回车道号，不崩、不重号。"""
    assert compete._pick_slot([], {"last_slot": 2}, fallback=1) == 1


def test_lane_env_uses_the_model_slot_not_the_lane() -> None:
    """车道定端口、槽位定厂商：同一个端口可以落到第二家厂商上。"""
    lanes = [
        _lm("a", "https://a/v1", "m-a"),
        _lm("b", "https://b/v1", "m-b"),
    ]
    env = compete._lane_env(0, lanes, relay_up=False, model_slot=1)
    assert env["LLM_API_BASE"] == "https://b/v1"
    assert env["STRIX_LLM"] == "openai/m-b"
    assert env["LLM_API_KEY"] == "sk-b"


def test_lane_env_without_config_is_unchanged(monkeypatch) -> None:
    """不配 lane_models 时 _lane_env 只有 VPN 中转键（默认关、行为不变）。"""
    monkeypatch.delenv("CTF_VPN_RELAY_BASE", raising=False)
    env = compete._lane_env(1)
    assert "LLM_API_BASE" not in env and "LLM_API_KEY" not in env
    assert "STRIX_LLM" not in env


def test_lane_env_maps_each_lane_to_its_own_vendor(monkeypatch) -> None:
    """车道 i 拿到第 i 行厂商的 base/key/model；模型名补 openai/ 前缀。"""
    monkeypatch.delenv("CTF_VPN_RELAY_BASE", raising=False)
    lane_models = [
        {"name": "a", "LLM_API_BASE": "https://a/v1", "LLM_API_KEY": "sk-a", "model": "m-a"},
        {"name": "b", "LLM_API_BASE": "https://b/v1", "LLM_API_KEY": "sk-b", "model": "m-b"},
    ]
    env0 = compete._lane_env(0, lane_models, relay_up=True)
    env1 = compete._lane_env(1, lane_models, relay_up=True)
    assert env0["LLM_API_BASE"] == "https://a/v1" and env0["LLM_API_KEY"] == "sk-a"
    assert env1["LLM_API_BASE"] == "https://b/v1" and env1["LLM_API_KEY"] == "sk-b"
    assert env0["STRIX_LLM"] == "openai/m-a"
    # VPN 端口隔离不因加厂商而丢。
    assert env0["CTF_VPN_RELAY"].endswith(":47444")
    assert env1["CTF_VPN_RELAY"].endswith(":47446")


def test_lane_env_keeps_prefixed_model_as_is() -> None:
    """模型名已带 provider 段（含 /）时不重复加前缀。"""
    lane_models = [
        {"name": "a", "LLM_API_BASE": "https://a/v1", "LLM_API_KEY": "k", "model": "openai/gpt-x"},
    ]
    assert compete._lane_env(0, lane_models)["STRIX_LLM"] == "openai/gpt-x"


def test_mask_key_shows_only_the_tail() -> None:
    """脱敏只露尾 4 位——横表可对配置，不可泄凭据。"""
    assert compete._mask_key("sk-1234567890abcd") == "…abcd"
    assert set(compete._mask_key("short")) <= {"…", "(", ")", "过", "短"}


def _fake_popen_capturing_env(monkeypatch) -> dict:
    """拦子进程启动，连 env 一起留——测「车道凭据真的传给了子进程」。"""
    captured: dict = {}

    def fake(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        stream = kwargs.get("stdout")
        if hasattr(stream, "close"):
            stream.close()
        return object()

    monkeypatch.setattr(compete.subprocess, "Popen", fake)
    return captured


def test_spawn_passes_lane_vendor_env_to_the_child(tmp_path, monkeypatch) -> None:
    """_spawn 的 env 合并：车道厂商覆盖父进程 LLM_*（凭据隔离的贯通点）。

    父进程有一套环境级 LLM 凭据时，车道配置必须赢——否则多厂商形同虚设。
    """
    monkeypatch.setenv("LLM_API_KEY", "ambient-key")
    monkeypatch.setenv("LLM_API_BASE", "https://ambient/v1")
    monkeypatch.setenv("STRIX_LLM", "openai/ambient")
    captured = _fake_popen_capturing_env(monkeypatch)
    lane_models = [
        {"name": "a", "LLM_API_BASE": "https://a/v1", "LLM_API_KEY": "sk-a", "model": "m-a"},
    ]
    compete._spawn(
        _chal("A"), _args(), tmp_path, lane=0, lane_models=lane_models
    )
    env = captured["env"]
    assert env["LLM_API_KEY"] == "sk-a"
    assert env["LLM_API_BASE"] == "https://a/v1"
    assert env["STRIX_LLM"] == "openai/m-a"
    # 凭据不进命令行（ps 可见面）。
    assert "sk-a" not in " ".join(captured["cmd"])


# ---------------------------------------------------------------- 题池体量档位

def test_regime_bounds_cover_small_medium_large() -> None:
    """边界值本身就是钉子：≤12 small，13–60 medium，≥61 large。

    large 的门槛由时间算术定：10h×3 lanes ≈ 108000 车道秒，N≈100 才真正
    绑死，61 是提前一个身位收紧；早于此收紧 = 白丢 29.2% 的同题重试解出率。
    """
    assert compete.regime_of(0) == "small"
    assert compete.regime_of(12) == "small"
    assert compete.regime_of(13) == "medium"
    assert compete.regime_of(60) == "medium"
    assert compete.regime_of(61) == "large"


def test_infra_skip_budget_never_shrinks_below_two() -> None:
    """环境故障的 defer 门槛不随体量档收紧（max(2, max_failures)）。

    large 档 max_failures=1 时，一次平台瞬时故障不能把题搁置到复活门槛
    之后——基础设施抖动不许替我们选题。
    """
    chal = _chal("A", solves_count=20)
    state = {"A": {"status": "active", "skips": 1, "runs": 1}}
    queue, _ = compete.rank_queue([chal], state, set(), max_failures=1)
    assert [c["id"] for c in queue] == ["A"]
    state2 = {"A": {"status": "active", "skips": 2, "runs": 2}}
    queue2, notes2 = compete.rank_queue([chal], state2, set(), max_failures=1)
    assert not queue2 and "infra-skip" in " ".join(notes2)


def test_regime_presets_scale_attempts_not_the_attempt_box() -> None:
    """分档只改调度参数，单次尝试时间盒（实测拐点）在三档里不许被动。"""
    for name, preset in compete._REGIME_PRESETS.items():
        assert set(preset) == {"max_failures", "rerun_solves_jump"}
    small = compete._REGIME_PRESETS["small"]
    medium = compete._REGIME_PRESETS["medium"]
    large = compete._REGIME_PRESETS["large"]
    assert small["max_failures"] > medium["max_failures"] > large["max_failures"]
    # 小池更容易复活 deferred，大池更保守。
    assert small["rerun_solves_jump"] < medium["rerun_solves_jump"] < large["rerun_solves_jump"]


def test_regime_off_pin_returns_the_medium_default(monkeypatch) -> None:
    """CTF_REGIME=off 时任何 N 都回到 medium 默认（= 改动前行为，对照臂）。"""
    monkeypatch.setenv("CTF_REGIME", "0")
    assert compete.regime_preset(5) == ("medium", compete._REGIME_PRESETS["medium"])
    assert compete.regime_preset(500) == ("medium", compete._REGIME_PRESETS["medium"])


def test_regime_default_is_on(monkeypatch) -> None:
    monkeypatch.delenv("CTF_REGIME", raising=False)
    assert compete.regime_enabled()
    assert compete.regime_preset(8)[0] == "small"
    assert compete.regime_preset(30)[0] == "medium"
    assert compete.regime_preset(120)[0] == "large"


def test_rank_queue_honours_the_regime_budget() -> None:
    """档位参数真的进 rank_queue：large 档一次失败即 defer，small 档扛四次。"""
    chal = _chal("A", difficulty="hard", solves_count=20)
    state = {"A": {"status": "active", "fails": 1, "runs": 1}}
    queue, notes = compete.rank_queue([chal], state, set(), max_failures=1)
    assert not queue and "deferred" in " ".join(notes)

    state2 = {"A": {"status": "active", "fails": 3, "runs": 3}}
    queue2, _ = compete.rank_queue([chal], state2, set(), max_failures=4)
    assert [c["id"] for c in queue2] == ["A"]


# ------------------------------------------------------- 竞速优先（race-first）
#
# 2026-11-17 用户拍板：开赛先竞速再分散。首跑解出概率低，分散派单会把
# 没解出的题排到后期——既丢动态积分的早解优势，尾部还可能覆盖不到。
# 竞速 = 队首题同时派所有车道先解先停（race_stop 输家 0 LLM 停车）。
# 窗口过后回到分散派单；--race-first 0（默认）维持原行为 = A/B 对照臂。


def test_race_phase_active_window_semantics() -> None:
    """0=从未启用恒关；窗口内开；过期即关。"""
    now = 1_000_000.0
    assert compete.race_phase_active(0.0, now) is False
    assert compete.race_phase_active(now + 60.0, now) is True
    assert compete.race_phase_active(now - 0.001, now) is False


def test_parser_race_first_defaults_off() -> None:
    """默认 0 = 不竞速（对照臂），显式给正数才开窗。"""
    assert _args().race_first == 0
    assert _args(**{"race-first": 900}).race_first == 900


def test_race_window_end_persists_across_restarts(tmp_path) -> None:
    """窗口属于比赛不属于进程：重启不重置，坏文件按已过期。"""
    end1 = compete._race_window_end(tmp_path, 900)
    assert end1 > 0
    # 第二次读盘必须拿到同一时刻——重启不得把窗口再拉长一遍。
    assert compete._race_window_end(tmp_path, 900) == end1
    (tmp_path / "race-window.json").write_text("{not json", encoding="utf-8")
    assert compete._race_window_end(tmp_path, 900) == 0.0


def _write_race_run(state_dir, cid: str, lane: int, rec: dict) -> None:
    runs = state_dir / "runs"
    runs.mkdir(exist_ok=True)
    with open(runs / f"{cid}-lane{lane}.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"challenge": cid, **rec}) + "\n")


def test_collect_race_any_lane_correct_is_solved(tmp_path) -> None:
    """竞速先解先停：任一车道判对 = 全队 solved，另一车道的失败不记账。"""
    state: dict = {}
    _write_race_run(tmp_path, "A", 0, {"correct": False, "stop_reason": "race_lost"})
    _write_race_run(tmp_path, "A", 1, {"correct": True})
    assert compete._collect_race("A", state, tmp_path, 2) == compete.SOLVED
    assert state["A"]["runs"] == 1
    assert state["A"].get("fails", 0) == 0
    assert "lane 1" in state["A"]["one_line"]
    assert "failure_path" not in state["A"]


def test_collect_race_all_fail_counts_one_attempt_not_per_lane(tmp_path) -> None:
    """同题同盘的车道是相关样本：全败记一次 fail，不乘车道数。"""
    state: dict = {}
    _write_race_run(
        tmp_path, "A", 0, {"correct": False, "stop_reason": "rounds_exhausted"}
    )
    _write_race_run(tmp_path, "A", 1, {"correct": False, "error": "x"})
    assert compete._collect_race("A", state, tmp_path, 2) == compete.FAILED
    assert state["A"]["fails"] == 1
    assert state["A"]["runs"] == 1
    # 失败路径取信息量最大的一条（有 stop_reason 的那条），不是随便一条。
    assert "rounds_exhausted" in state["A"]["one_line"]


def test_collect_race_all_skipped_is_skip_not_fail(tmp_path) -> None:
    """全车道接入失败 ≠ 题不可解：只记 skip 连击（B-23 口径的竞速版）。"""
    state: dict = {}
    _write_race_run(tmp_path, "A", 0, {"skipped": True, "error": "SKIPPED(需隧道)"})
    _write_race_run(tmp_path, "A", 1, {"skipped": True, "error": "SKIPPED(需隧道)"})
    assert compete._collect_race("A", state, tmp_path, 2) == compete.FAILED
    assert state["A"]["skips"] == 1
    assert state["A"].get("fails", 0) == 0


def test_collect_race_no_rows_is_infra(tmp_path) -> None:
    """一条结果行都没写 = 环境问题，不计失败稍后重派（与 _collect 同口径）。"""
    state = {"A": {"race_rows_before": [0, 0], "status": compete.RUNNING}}
    assert compete._collect_race("A", state, tmp_path, 2) == compete.INFRA
    assert state["A"]["infra_stops"] == 1
    assert state["A"].get("fails", 0) == 0


def test_collect_race_respects_platform_solved(tmp_path) -> None:
    """B-28 竞速版：平台已解回灌的题，本地竞速判负不得降级。"""
    state = {"A": {"status": compete.SOLVED, "race_rows_before": [0, 0]}}
    _write_race_run(tmp_path, "A", 0, {"correct": False, "stop_reason": "x"})
    _write_race_run(tmp_path, "A", 1, {"correct": False, "stop_reason": "y"})
    assert compete._collect_race("A", state, tmp_path, 2) == compete.SOLVED


def test_spawn_race_lane_gets_tag_and_race_env(tmp_path, monkeypatch) -> None:
    """竞速车道：out/plan 文件带 -lane{N} 后缀（互不覆盖），env 带 CTF_RACE_*。"""
    captured = _fake_popen_capturing_env(monkeypatch)
    race_dir = tmp_path / "race"
    compete._spawn(
        _chal("A"),
        _args(),
        tmp_path,
        lane=1,
        tag="-lane1",
        extra_env=compete._race_env(race_dir, "A", 1),
    )
    cmd = " ".join(captured["cmd"])
    assert "A-lane1.jsonl" in cmd and "plan-A-lane1.json" in cmd
    assert "A.jsonl" not in cmd  # 不写共享结果文件
    env = captured["env"]
    assert env["CTF_RACE_DIR"] == str(race_dir)
    assert env["CTF_RACE_CHALLENGE"] == "A"
    assert env["CTF_RACE_LANE"] == "1"


def test_spawn_disjoint_clears_stale_race_env(tmp_path, monkeypatch) -> None:
    """分散派单显式清残留 race 变量：race_stop 是纯 env 判定，父 shell
    里残留的旧 CTF_RACE_DIR 不该让不相干的题去盯旧的胜局标记。"""
    monkeypatch.setenv("CTF_RACE_DIR", "/tmp/old-race")
    monkeypatch.setenv("CTF_RACE_CHALLENGE", "OLD-999")
    monkeypatch.setenv("CTF_RACE_LANE", "3")
    captured = _fake_popen_capturing_env(monkeypatch)
    compete._spawn(_chal("A"), _args(), tmp_path)
    env = captured["env"]
    assert "CTF_RACE_DIR" not in env
    assert "CTF_RACE_CHALLENGE" not in env
    assert "CTF_RACE_LANE" not in env


def _bundle_layout(tmp_path):
    """造一个 bootstrap.sh 产出的布局：<D>/strix-ctf-agent/scripts + <D>/tools。"""
    repo = tmp_path / "strix-ctf-agent"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    bin_dir = tmp_path / "tools" / "usr" / "bin"
    sbin_dir = tmp_path / "tools" / "usr" / "sbin"
    lib_dir = tmp_path / "tools" / "usr" / "lib" / "x86_64-linux-gnu"
    lib2_dir = tmp_path / "tools" / "lib" / "x86_64-linux-gnu"
    for d in (bin_dir, sbin_dir, lib_dir, lib2_dir):
        d.mkdir(parents=True)
    return scripts


def test_ensure_bundle_tool_env_noop_outside_bundle(tmp_path, monkeypatch) -> None:
    """非 bundle 布局（开发机）必须一个字节都不改 env。"""
    scripts = tmp_path / "plain" / "scripts"
    scripts.mkdir(parents=True)
    monkeypatch.setattr(compete, "HERE", scripts)
    monkeypatch.setenv("PATH", compete.os.pathsep.join(["/usr/bin", "/bin"]))
    monkeypatch.delenv("LD_LIBRARY_PATH", raising=False)
    assert compete.ensure_bundle_tool_env() == {}
    assert compete.os.environ["PATH"] == compete.os.pathsep.join(["/usr/bin", "/bin"])
    assert "LD_LIBRARY_PATH" not in compete.os.environ


def test_ensure_bundle_tool_env_puts_bundle_bins_first(tmp_path, monkeypatch) -> None:
    """bundle 布局：tools/usr/bin|sbin 排在最前，原有 PATH 段保留在后。"""
    scripts = _bundle_layout(tmp_path)
    monkeypatch.setattr(compete, "HERE", scripts)
    monkeypatch.setenv("PATH", compete.os.pathsep.join(["/usr/bin", "/bin"]))
    changed = compete.ensure_bundle_tool_env()
    parts = compete.os.environ["PATH"].split(compete.os.pathsep)
    assert parts[0] == str(tmp_path / "tools" / "usr" / "bin")
    assert parts[1] == str(tmp_path / "tools" / "usr" / "sbin")
    assert "/usr/bin" in parts and "/bin" in parts
    assert "PATH" in changed


def test_ensure_bundle_tool_env_keeps_host_libs_first(tmp_path, monkeypatch) -> None:
    """库序：bundle 的 lib 目录只能在宿主目录之后（否则宿主二进制全挂）。"""
    scripts = _bundle_layout(tmp_path)
    monkeypatch.setattr(compete, "HERE", scripts)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/custom")
    compete.ensure_bundle_tool_env()
    libs = compete.os.environ["LD_LIBRARY_PATH"].split(compete.os.pathsep)
    bundle_usr_lib = str(tmp_path / "tools" / "usr" / "lib" / "x86_64-linux-gnu")
    bundle_lib = str(tmp_path / "tools" / "lib" / "x86_64-linux-gnu")
    assert bundle_usr_lib in libs and bundle_lib in libs
    assert "/opt/custom" in libs  # 外部已有值不被丢弃
    # 宿主目录（若本机存在）必须都排在 bundle 目录之前
    for host in ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"):
        if host in libs:
            assert libs.index(host) < libs.index(bundle_usr_lib)


def test_ensure_bundle_tool_env_is_idempotent(tmp_path, monkeypatch) -> None:
    """重复调用不再改 env（第二次返回空），避免 PATH 越跑越长。"""
    scripts = _bundle_layout(tmp_path)
    monkeypatch.setattr(compete, "HERE", scripts)
    monkeypatch.setenv("PATH", compete.os.pathsep.join(["/usr/bin", "/bin"]))
    first = compete.ensure_bundle_tool_env()
    after_first = compete.os.environ["PATH"]
    second = compete.ensure_bundle_tool_env()
    assert "PATH" in first
    assert compete.os.environ["PATH"] == after_first
    assert "PATH" not in second
