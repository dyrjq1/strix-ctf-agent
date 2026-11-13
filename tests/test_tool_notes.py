from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_strix.tool_notes import append_note


SCAN_JSON = json.dumps(
    {
        "success": True,
        "scan_completed": True,
        "message": "Scan completed (not persisted)",
    }
)


def test_lifecycle_json_stays_parseable_and_keeps_keys() -> None:
    out = append_note(SCAN_JSON, "\n\n--- platform submission ---\nREJECTED: 1 candidate")

    parsed = json.loads(out)
    assert parsed["success"] is True
    assert parsed["scan_completed"] is True
    assert any("REJECTED" in n for n in parsed["_ctf_notes"])


def test_lifecycle_notes_accumulate() -> None:
    out = append_note(
        append_note(SCAN_JSON, "\n\n[TURN BUDGET] 19 of 25"),
        "\n\n--- platform submission ---",
    )

    assert len(json.loads(out)["_ctf_notes"]) == 2


def test_agent_finish_key_is_covered() -> None:
    payload = json.dumps({"success": True, "agent_completed": True})

    parsed = json.loads(append_note(payload, "\nhint"))

    assert parsed["agent_completed"] is True


def test_plain_text_still_appends() -> None:
    assert append_note("hello", "\n\nhi") == "hello\n\nhi"


def test_non_lifecycle_json_still_appends() -> None:
    payload = json.dumps({"status": 200, "body": "ok"})

    out = append_note(payload, "\n\n[SOFT DEADLINE]")

    assert out.startswith(payload)
    assert out.endswith("[SOFT DEADLINE]")


@pytest.mark.parametrize("value", [{"success": False}, None, 3])
def test_non_string_passthrough(value: object) -> None:
    assert append_note(value, "hint") == value


def test_empty_note_is_noop() -> None:
    assert append_note(SCAN_JSON, "") == SCAN_JSON


def test_lifecycle_output_survives_vendor_detector() -> None:
    """回归：vendor 的生命周期判据必须仍能认出这次 finish。"""
    from strix.agents.factory import _lifecycle_tool_completed

    out = append_note(SCAN_JSON, "\n\n--- platform submission ---\nREJECTED")

    assert _lifecycle_tool_completed("finish_scan", out) is True


def test_autosubmit_decorate_keeps_lifecycle_json_parseable() -> None:
    from ctf_strix.autosubmit import AutoSubmitter

    sub = AutoSubmitter.__new__(AutoSubmitter)
    verdict = {"tried": ["x"], "correct": [], "challenge_fully_solved": False}

    out = sub.decorate(SCAN_JSON, verdict)

    parsed = json.loads(out)
    assert parsed["scan_completed"] is True
    assert any("REJECTED" in n for n in parsed["_ctf_notes"])


def test_all_note_appenders_use_the_helper() -> None:
    """接线回归：任何一个守卫回到裸拼接，生命周期工具就又会失明。"""
    src = Path(__file__).resolve().parents[1] / "src" / "ctf_strix"
    names = (
        "turn_budget",
        "deadline_guard",
        "journey_guard",
        "enum_guard",
        "progress_guard",
        "sweep_guard",
        "negative_guard",
        "restart_guard",
        "autosubmit",
    )
    for name in names:
        text = (src / f"{name}.py").read_text(encoding="utf-8")
        assert 'f"{result}{hint}"' not in text, name
        assert "append_note(" in text, name
