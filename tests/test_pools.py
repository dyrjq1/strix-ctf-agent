"""评测池切分不能被悄悄改掉。

这组测试守的是**尺子**，不是解题能力。尺子坏了的后果是：所有
"提升 X%" 都无法归因，而且从日志上完全看不出来——数字依然漂亮。

本仓库真发生过一次：诊断池切分把 `CTFARENA-024` / `CTFARENA-097`
同时切进了诊断池和官方封存集。跑它们等于污染封存集，而哈希校验
是自洽的（错在切法，不在文件完整性）。所以这里断言的是**结构**。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_pools import structural_errors  # noqa: E402

POOLS = ROOT / "experiments" / "pools.json"


def _load() -> dict:
    return json.loads(POOLS.read_text(encoding="utf-8"))


def test_pools_file_exists() -> None:
    assert POOLS.exists(), "评测池不见了——没有尺子就不要声称提升"


def test_no_set_overlaps() -> None:
    """四类集合必须互斥，这是唯一能防住"切错池子"的断言。"""
    assert structural_errors(_load()) == []


def test_diagnostic_is_either_full_or_empty() -> None:
    """诊断池只有两种合法形态：满 20 道（可烧），或烧完为空且有说明。

    一批跑完必须把题并入 burned 并清空诊断池，否则下一轮会在同一批题上
    "再验一次"，把已经看过的题当成留出集用。
    """
    d = _load()
    n = len(d["diagnostic"])
    if n:
        # 20 是目标，不是硬性契约：储备池被抽到某个桶见底时，抽不满 20 是
        # 正常结果，硬断言 20 只会逼人把桶放宽（那才是尺子作弊）。
        # 这里守住的是"样本量够看出失败形态"，并禁止悄悄变成 3、5 道。
        assert 15 <= n <= 20, f"诊断池应 15-20 道，现在 {n} 道"
    else:
        assert str(d.get("diagnostic_note") or "").strip(), (
            "诊断池为空时必须写 diagnostic_note，说明下一批从哪抽"
        )


def test_quota_covers_every_bucket() -> None:
    """必须覆盖 `hardest` 与 `hard`，其余桶按储备池余量取舍。

    为什么不再要求四档齐全：`easy` 桶（21+ 人解出）在储备池里已经被抽完，
    要求四档齐全的结果只能是两种——要么把 `mid` 改标成 `easy`（改数据），
    要么永远不跑（等于放弃验证）。真正决定结论的是天花板位置，也就是
    `hardest` 与 `hard`，所以这两档必须覆盖，`mid`/`easy` 有几档算几档。
    """
    buckets = {x["bucket"] for x in _load()["diagnostic"]}
    if not buckets:
        return
    assert buckets <= {"hardest", "hard", "mid", "easy"}, f"出现未知桶: {buckets}"
    assert {"hardest", "hard"} <= buckets, f"必须覆盖最硬两档，现在只有 {buckets}"


def test_burned_and_sealed_are_disjoint_from_new_pools() -> None:
    """已烧的题和封存题都不许再进诊断/储备池。"""
    d = _load()
    diag = {x["id"] for x in d["diagnostic"]}
    reserve = {x["id"] for x in d["reserve"]}
    burned = set(d["burned"])
    sealed = set(d["sealed_excluded"])
    assert not (diag | reserve) & burned
    assert not (diag | reserve) & sealed


def test_sealed_set_is_twenty_and_documented() -> None:
    """官方封存集固定 20 道，与 docs/22 §5.3 对齐。"""
    sealed = _load()["sealed_excluded"]
    assert len(sealed) == 20
    assert len(set(sealed)) == 20


def test_structural_errors_catches_sealed_leak() -> None:
    """给校验函数本身一个反向用例：它必须真的能抓到泄漏。"""
    bad = {
        "diagnostic": [{"id": "X-1"}],
        "reserve": [{"id": "X-2"}],
        "sealed_excluded": ["X-1"],
        "burned": [],
    }
    errs = structural_errors(bad)
    assert any("sealed" in e for e in errs), errs


def test_structural_errors_catches_overlap() -> None:
    bad = {
        "diagnostic": [{"id": "X-1"}],
        "reserve": [{"id": "X-1"}],
        "sealed_excluded": [],
        "burned": [],
    }
    assert structural_errors(bad)


# ---------------------------------------------------------------- 入口硬拦截

def test_plan_guard_blocks_sealed_challenge() -> None:
    """封存题混进 plan 时必须拒绝开跑——这是唯一防得住"误跑"的地方。"""
    from batch_eval import check_plan_pools

    errs = check_plan_pools([{"id": "CTFARENA-024"}])
    assert errs, "封存题没被拦下"
    assert "封存集" in errs[0]


def test_plan_guard_blocks_burned_challenge() -> None:
    from batch_eval import check_plan_pools

    errs = check_plan_pools([{"id": "CTFARENA-009"}])
    assert errs, "已烧题没被拦下"
    assert "已烧过" in errs[0]


def test_plan_guard_allows_explicit_override() -> None:
    """定稿前跑封存集是合法的，但必须显式声明——"不小心跑了"和"决定跑了"要分开。"""
    from batch_eval import check_plan_pools

    assert check_plan_pools([{"id": "CTFARENA-024", "allow_sealed": True}]) == []
    assert check_plan_pools([{"id": "CTFARENA-009", "allow_burned": True}]) == []


def test_plan_guard_passes_diagnostic_challenge() -> None:
    """诊断池的题必须能跑，否则这套机制就没法用来诊断。"""
    import json

    from batch_eval import check_plan_pools

    pools = json.loads(POOLS.read_text(encoding="utf-8"))
    if not pools["diagnostic"]:
        return
    first = pools["diagnostic"][0]["id"]
    assert check_plan_pools([{"id": first}]) == []
