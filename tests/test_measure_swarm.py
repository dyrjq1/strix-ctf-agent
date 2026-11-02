"""The child-agent cost meter must stay honest.

Why these tests exist: the "coordination ate ~22% of the budget" claim in
``tool_trim.py`` was never reproducible.  A meter that silently counts nothing
(empty log, renamed tool, changed log format) would make every later report say
"no coordination cost" -- which reads exactly like a good result.

So the tests run against a synthetic log whose numbers are known by
construction, plus one check that the real SAMPLE-006 log still yields the
figures quoted in the docs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import measure_swarm  # noqa: E402


def _synthetic(task_chars: int = 100) -> str:
    """Build a log with known counts.

    Args:
        task_chars: Length of the ``task`` string handed to ``create_agent``.

    Returns:
        Log text containing one root, one child, and seven tool calls.
    """
    spawn = json.dumps(
        {"name": "Kid", "task": "x" * task_chars, "skills": []}, ensure_ascii=False
    )
    return "\n".join(
        [
            '  [aaaa1111] TOOL exec_command {"cmd": "ls"}',
            "  [aaaa1111] OUT  ok",
            f"  [aaaa1111] TOOL create_agent {spawn}",
            '  [aaaa1111] OUT  {"success": true, "agent_id": "bbbb2222", "parent_id": "aaaa1111"}',
            '  [bbbb2222] TOOL exec_command {"cmd": "curl target"}',
            '  [bbbb2222] TOOL http_probe {"url": "https://t/"}',
            '  [bbbb2222] TOOL agent_finish {"result_summary": "done"}',
            '  [aaaa1111] TOOL wait_for_agents {"timeout_seconds": 60}',
            '  [aaaa1111] OUT  {"success": true, "wait_outcome": "message_arrived", "messages": []}',
            '  [aaaa1111] TOOL finish_scan {"executive_summary": "flag"}',
            "",
        ]
    )


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "run.log"
    p.write_text(text, encoding="utf-8")
    return p


def test_counts_coordination_and_work_separately(tmp_path):
    """Seven tool calls total: two coordination, three child-side, two root work."""
    result = measure_swarm.measure(_write(tmp_path, _synthetic()))
    assert result["ok"]
    assert result["agents"] == 2
    assert result["children"] == 1
    assert result["total_calls"] == 7
    # create_agent + wait_for_agents are parent-side overhead.  agent_finish is
    # the child's own lifecycle and is NOT charged to the parent.
    assert result["coordination_calls"] == 2
    # child: exec_command + http_probe; root: exec_command + finish_scan
    assert result["child_work_calls"] == 2


def test_parent_link_is_read_from_the_spawn_output(tmp_path):
    parsed = measure_swarm.parse_log(_write(tmp_path, _synthetic()))
    assert parsed["parents"] == {"bbbb2222": "aaaa1111"}


def test_task_prompt_size_is_measured(tmp_path):
    """The task prompt is a real token cost that a call count cannot see."""
    result = measure_swarm.measure(_write(tmp_path, _synthetic(task_chars=100)))
    assert result["spawn_task_chars"] == 100


def test_report_back_size_is_measured(tmp_path):
    """A completion report lands in the parent's context: also a token cost."""
    result = measure_swarm.measure(_write(tmp_path, _synthetic()))
    assert result["report_back_chars"] > 0


def test_agent_finish_is_not_charged_as_coordination(tmp_path):
    """Charging the child's own lifecycle would inflate the overhead verdict."""
    parsed = measure_swarm.parse_log(_write(tmp_path, _synthetic()))
    assert parsed["agents"]["bbbb2222"]["coord"] == 0


def test_log_without_children_is_a_valid_zero(tmp_path):
    """'No child' is a data point, not an error."""
    result = measure_swarm.measure(
        _write(
            tmp_path,
            "  [cccc3333] TOOL exec_command {}\n  [cccc3333] TOOL finish_scan {}\n",
        )
    )
    assert result["ok"]
    assert result["children"] == 0
    assert result["verdict"] == "no_child"


def test_unreadable_log_reports_reason_not_crash(tmp_path):
    result = measure_swarm.measure(_write(tmp_path, "no tool calls here\n"))
    assert result["ok"] is False
    assert "reason" in result


def test_verdict_thresholds():
    """The threshold is a policy choice; pin it so it cannot drift silently."""
    assert measure_swarm.EXPENSIVE_SHARE == 0.15
    assert measure_swarm._verdict(0, 0, 10, 0) == "no_child"
    assert measure_swarm._verdict(1, 2, 10, 0) == "child_unproven"
    assert measure_swarm._verdict(1, 3, 10, 5) == "child_expensive"  # 30% > 15%
    assert measure_swarm._verdict(1, 1, 10, 5) == "child_earned"  # 10% <= 15%


def test_real_sample_006_matches_the_documented_figure():
    """The only multi-agent run on disk; its numbers are quoted in docs/11.

    If this fails, either the log format changed or the quoted figure is stale.
    Both need a human, so it asserts exact values rather than a range.
    """
    log = ROOT / "reports" / "SAMPLE-006.log"
    if not log.is_file():
        pytest.skip("SAMPLE-006.log not present in this checkout")
    result = measure_swarm.measure(log)
    assert result["agents"] == 2
    assert result["children"] == 1
    assert result["coordination_calls"] == 3
    assert result["total_calls"] == 12
    assert result["coordination_share"] == 0.25
    assert result["root_calls_before_spawn"] == 1
    assert result["verdict"] == "child_expensive"
