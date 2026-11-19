"""两条入口的接线对等（2026-11-19 审计，台账 §4.282）。

背景：比赛当天真正跑的车道是 ``scripts/compete.py`` → ``scripts/batch_eval.py``
→ ``scripts/run_strix_ctf.py``，官方入口 ``src/ctf_strix/agent.py`` 只在镜像/
平台托管评测里跑。两边各写一份装配，任何一处只修一边，都会表现为「测试全绿、
真跑没有」。这一批钉住三处：

1. goal 文本按题型选（file/tcp 题不能拿到 web 版目标）；
2. 回答形态判据覆盖任意标签（``flag{}`` / ``CTF{}`` / ``utflag{}``），不是
   只认字面量 ``FLAG{``；
3. ``target_absent`` 守卫真的装上了，``except TargetAbsent`` 不是死分支；
   装只是上半场，sink 侧还要有 raise 点（``_check_target_absent``），否则
   死靶照样烧满墙钟、``stop_reason`` 永远落不到 ``target_absent``。
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture(scope="module")
def harness():
    pytest.importorskip("strix.agents.factory", reason="vendor tree not importable here")
    return importlib.import_module("run_strix_ctf")


@pytest.fixture(scope="module")
def batch():
    pytest.importorskip("strix.agents.factory", reason="vendor tree not importable here")
    return importlib.import_module("batch_eval")


def test_goal_files_match_the_official_entry(batch):
    """车道入口的 goal 表必须与 ``agent.GOAL_FILES`` 同表，且文件都在。"""
    from ctf_strix import agent

    assert batch._GOAL_FILES == agent.GOAL_FILES
    for name in batch._GOAL_FILES.values():
        assert (ROOT / "config" / name).is_file(), f"{name} 缺失"
    # 未知题型退回 web，而不是 KeyError 把整条车道打死。
    assert batch._goal_file_for("nonsense") == "ctf_goal.txt"
    assert batch._goal_file_for("TCP") == "goal_tcp.txt"


def test_the_lane_actually_picks_the_goal_by_kind():
    """表对了不够，``run_agent`` 必须用 ``_goal_file_for(target_kind)``。"""
    src = (ROOT / "scripts" / "batch_eval.py").read_text(encoding="utf-8")
    assert "_goal_file_for(target_kind)" in src, "车道又写死了 ctf_goal.txt"
    assert '"config" / "ctf_goal.txt"' not in src, "还有一处写死 web goal"


def test_answer_shape_is_tag_agnostic(harness):
    """任意标签的 flag 与 ANSWER 行都算答案；普通文本不算。"""
    assert not harness._looks_like_answer("nothing here")
    for sample in (
        "FLAG{abc}",
        "flag{abc}",
        "CTF{abc}",
        "utflag{abc}",
        "HTB{abc}",
        "ANSWER[flag]=xyz",
    ):
        assert harness._looks_like_answer(sample), sample


def test_a_long_output_keeps_a_lowercase_flag(harness):
    """600 字节之后出现的 ``flag{}`` 不能被截掉——batch_eval 兜底读的就是日志。"""
    body = "x" * 900 + " flag{deadbeef}"
    limit = 4000 if harness._looks_like_answer(body) else 600
    assert limit == 4000
    assert "flag{deadbeef}" in body[:limit]


def test_lane_installs_the_target_absent_guard(harness):
    """官方入口装了、车道入口只 import 异常类——那就是死分支。"""
    src = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
    assert "install_target_absent()" in src
    assert '"_ctf_target_guarded"' in src, "装了但没进 verify 集合 = 静默失败"
    # 反向：异常类仍要 import，否则 except 行本身会 NameError。
    assert "TargetAbsent" in src


def test_the_shared_target_absent_predicate_behaves(harness):
    """``agent._check_target_absent`` 的四种状态，两条入口共用这一份。"""
    from ctf_strix import agent
    from ctf_strix.target_absent import TargetAbsent

    class _Guard:
        tripped = True
        tripped_origin = "http://dead.example"
        threshold = 6

        def stop_detail(self) -> str:
            return "dead"

    # 触发 + 轮边界 → 抛；其余三种都不抛。
    with pytest.raises(TargetAbsent):
        agent._check_target_absent(_Guard(), True)
    agent._check_target_absent(_Guard(), False)
    agent._check_target_absent(_Guard(), True, solved=True)
    agent._check_target_absent(None, True)


def test_the_lane_sink_actually_checks_the_guard(harness):
    """装了守卫还要有 raise 点：sink 必须调共用判据，且带轮边界参数。"""
    src = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
    assert "_check_target_absent(" in src
    assert "_is_round_boundary(event)" in src, "没有轮边界 = 会砍掉同轮的兄弟输出"
    # 有答案就不停：sink 见到答案形态的输出要给守卫记一笔。
    assert "target_guard.note_answer()" in src


def test_lane_tells_the_agent_what_is_in_its_workspace():
    """附件是静默注入的；不说一声，模型不知道 ``.b64`` 要先解码。"""
    src = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
    assert "agent_mod._attachment_section(extra_files)" in src

    from ctf_strix.agent import _attachment_section

    text = _attachment_section([{"workspace_path": "/workspace/challenge.zip.b64"}])
    assert "./challenge.zip.b64" in text
    assert "base64 -d" in text
    assert _attachment_section([]) == ""