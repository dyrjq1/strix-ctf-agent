"""scripts/category_stats.py：分题型汇总的口径测试。

只测「该响的时候响」不够——历史成绩里 web 一枝独秀会把 crypto/rev 的短板
平均掉，所以这里同时测「解出/未解出/只有空转」三类题是否被分到对的桶里。
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = REPO_ROOT / "scripts" / "category_stats.py"
    spec = importlib.util.spec_from_file_location("category_stats", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["category_stats"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(dirpath: Path, qid: str, recs: list[dict]) -> None:
    runs = dirpath / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    with open(runs / f"{qid}.jsonl", "w", encoding="utf-8") as f:
        for rec in recs:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def test_splits_categories_and_counts_attempts(tmp_path: Path) -> None:
    mod = _load()
    _write(
        tmp_path,
        "T-1",
        [
            {"category": "crypto", "tool_calls": 4, "total_s": 60.0, "correct": True},
        ],
    )
    _write(
        tmp_path,
        "T-2",
        [
            {"category": "crypto", "tool_calls": 9, "total_s": 300.0, "correct": False},
        ],
    )
    # 只有空转记录：实例没起来，不能算成一次尝试
    _write(
        tmp_path,
        "T-3",
        [
            {"category": "reverse", "tool_calls": 0, "total_s": 0.0,
             "usage": {"llm_calls": 0}, "correct": False},
        ],
    )
    per = mod.collect(tmp_path)

    assert per["crypto"]["chals"] == 2
    assert per["crypto"]["solved"] == 1
    assert per["crypto"]["attempts"] == 2
    assert per["crypto"]["wall"] == 360.0
    assert per["reverse"]["chals"] == 1
    assert per["reverse"]["attempts"] == 0
    assert per["reverse"]["diff"] == 1
    assert per["reverse"]["solved"] == 0


def test_state_solved_counts_even_when_records_lack_correct(tmp_path: Path) -> None:
    """旧记录没有 correct 字段时，账本里的 solved 仍然是解出。"""
    mod = _load()
    _write(tmp_path, "T-9", [{"category": "web", "tool_calls": 2, "total_s": 10.0}])
    (tmp_path / "state.json").write_text(
        json.dumps({"T-9": {"status": "solved", "category": "web"}}), encoding="utf-8"
    )

    per = mod.collect(tmp_path)

    assert per["web"]["solved"] == 1


def test_render_has_a_total_row(tmp_path: Path) -> None:
    mod = _load()
    _write(tmp_path, "T-1", [{"category": "pwn", "tool_calls": 3, "correct": True}])
    text = mod.render(mod.collect(tmp_path))

    assert "| pwn | 1 | 1 | 100% |" in text
    assert "**合计**" in text


def test_category_falls_back_to_state_ledger(tmp_path: Path) -> None:
    """记录里没写 category 时用账本里的（compete 派单时写入）。"""
    mod = _load()
    _write(tmp_path, "T-5", [{"tool_calls": 1, "correct": False}])
    (tmp_path / "state.json").write_text(
        json.dumps({"T-5": {"status": "failed", "category": "misc"}}), encoding="utf-8"
    )

    per = mod.collect(tmp_path)

    assert "misc" in per
    assert per["misc"]["chals"] == 1