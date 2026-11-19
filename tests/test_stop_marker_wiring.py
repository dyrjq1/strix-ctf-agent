"""收场标记接线：``run_strix_ctf`` 这条 harness 入口必须真的落盘。

2026-11-19 验收跑实测：三道题 wallclock 收场后，盒子里连
``stall_markers.jsonl`` 都没有——``record_stop`` 只接在 ``agent.main`` 的
``_write_result`` 上，而批次子进程走的是 ``scripts/run_strix_ctf.py``，
于是下一轮的重试提示只剩「收场：…；轨迹：…」，用户要的
「上一轮失败路径 / 选了什么方法卡」整段缺失。

这里不启 strix 运行时（那是十几分钟的真跑），只钉住两件事：
标记文件按 ``CTFY_STALL_MARKERS`` 落盘、且带的是重试提示真正读的字段。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import run_strix_ctf  # noqa: E402
from ctf_strix import progress_guard  # noqa: E402


def test_the_harness_records_a_stop_marker_where_the_retry_reads_it(
    tmp_path, monkeypatch
) -> None:
    markers = tmp_path / "sample-x" / "stall_markers.jsonl"
    monkeypatch.setenv("CTFY_STALL_MARKERS", str(markers))
    progress_guard.reset_for_tests()
    try:
        note = run_strix_ctf._record_stop_marker("wallclock")
        assert note == "", note
        assert markers.exists(), "收场标记没有落盘——重试提示就只剩「收场」一行"
        rows = [
            json.loads(line)
            for line in markers.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert rows, "标记文件是空的"
        last = rows[-1]
        # 收场原因：父进程按 stage 前缀读「上一轮停在哪」。
        assert last["stage"] == "stop:wallclock"
        # 卡与请求面：用户 2026-11-19 要求失败描述必须带这两项。
        assert "cards_state" in last
        assert last["cards_state"] in {"picked", "menu_no_pick", "no_menu", "unknown"}
    finally:
        progress_guard.reset_for_tests()


def test_an_unset_marker_path_is_a_no_op_not_a_crash(tmp_path, monkeypatch) -> None:
    """没有 CTFY_STALL_MARKERS（手动跑脚本）时不能抛：记账失败不是收场失败。"""
    monkeypatch.delenv("CTFY_STALL_MARKERS", raising=False)
    progress_guard.reset_for_tests()
    try:
        assert run_strix_ctf._record_stop_marker("wallclock") == ""
        assert not list(tmp_path.rglob("stall_markers.jsonl"))
    finally:
        progress_guard.reset_for_tests()