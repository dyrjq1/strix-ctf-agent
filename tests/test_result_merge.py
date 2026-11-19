"""result.json restart-merge regression tests.

The platform restarts a run after a failed lifecycle call.  The restarted run
starts with an empty answers map, so an unmerged write silently drops flags the
previous run had already found and submitted.
"""

from __future__ import annotations

import json

from ctf_strix import agent


def _payload(answers, **overrides):
    payload = {
        "schema_version": agent.BRIEF_SCHEMA_VERSION,
        "answers": answers,
        "turns": 10,
        "input_tokens": 100,
        "output_tokens": 20,
        "stop_reason": "completed",
        "writeup": "new run",
    }
    payload.update(overrides)
    return payload


def _write(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_every_result_write_leaves_a_stop_marker(tmp_path, monkeypatch):
    """收场标记必须在**真实收口**上落盘，而不只是在 ``record_stop`` 里能跑。

    2026-11-19：三道题全部 wallclock 收场，盒子里连 stall_markers.jsonl 都
    没有——``observe()`` 只在停滞判据响时写文件，而轮次打满/墙钟一次也不响。
    每一轮的重试提示因此只剩「收场：wallclock」，路径与所选方法卡全缺。
    """
    from ctf_strix import progress_guard

    markers = tmp_path / "stall_markers.jsonl"
    monkeypatch.setenv("CTFY_STALL_MARKERS", str(markers))
    progress_guard.reset_for_tests()
    try:
        agent._write_result(
            tmp_path / "result.json", _payload({}, stop_reason="wallclock")
        )
    finally:
        progress_guard.reset_for_tests()

    line = json.loads(markers.read_text(encoding="utf-8").splitlines()[-1])
    assert line["stage"] == "stop:wallclock"
    assert line["cards_state"] in {"no_menu", "menu_no_pick", "picked", "unknown"}


def test_old_two_flags_new_empty_keeps_both(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({"foothold": "FLAG{a}", "deploy": "FLAG{b}"}, stop_reason="solved"))

    agent._write_result(result, _payload({}, stop_reason="error"))

    merged = _read(result)
    assert merged["answers"] == {"foothold": "FLAG{a}", "deploy": "FLAG{b}"}
    assert merged["stop_reason"] == "solved"
    assert merged["previous_stop_reason"] == "solved"


def test_new_flag_is_used_and_old_other_keys_survive(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({"a": "FLAG{old-a}", "b": "FLAG{old-b}"}, stop_reason="solved"))

    agent._write_result(result, _payload({"a": "FLAG{new-a}"}, stop_reason="completed"))

    merged = _read(result)
    assert merged["answers"] == {"a": "FLAG{new-a}", "b": "FLAG{old-b}"}
    assert merged["stop_reason"] == "completed"
    assert "previous_stop_reason" not in merged


def test_blank_new_value_does_not_erase_old_value(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({"flag": "FLAG{real}"}))

    agent._write_result(result, _payload({"flag": "   "}))

    assert _read(result)["answers"]["flag"] == "FLAG{real}"


def test_old_empty_new_nonempty_uses_new_values(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({}))

    agent._write_result(result, _payload({"flag": "FLAG{new}"}))

    assert _read(result)["answers"] == {"flag": "FLAG{new}"}


def test_both_empty_stays_empty(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({"flag": ""}))

    agent._write_result(result, _payload({}))

    assert _read(result)["answers"] == {"flag": ""}


def test_old_nonempty_new_nonempty_is_per_key(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({"a": "FLAG{old-a}", "b": "FLAG{old-b}"}))

    agent._write_result(result, _payload({"a": "FLAG{new-a}", "c": "FLAG{new-c}"}))

    assert _read(result)["answers"] == {
        "a": "FLAG{new-a}",
        "b": "FLAG{old-b}",
        "c": "FLAG{new-c}",
    }


def test_non_answer_fields_follow_the_new_payload(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({"flag": "FLAG{x}"}, turns=99, input_tokens=999, writeup="old"))

    agent._write_result(result, _payload({}, turns=7, input_tokens=42, writeup="new"))

    merged = _read(result)
    assert merged["turns"] == 7
    assert merged["input_tokens"] == 42
    assert merged["writeup"] == "new"


def test_corrupt_json_is_treated_as_absent(tmp_path):
    result = tmp_path / "result.json"
    result.write_text("{ this is not json", encoding="utf-8")

    agent._write_result(result, _payload({"flag": "FLAG{new}"}))

    assert _read(result)["answers"] == {"flag": "FLAG{new}"}


def test_truncated_json_is_treated_as_absent(tmp_path):
    result = tmp_path / "result.json"
    result.write_text('{"answers": {"flag": "FLAG{half"', encoding="utf-8")

    agent._write_result(result, _payload({"flag": "FLAG{new}"}))

    assert _read(result)["answers"] == {"flag": "FLAG{new}"}


def test_non_dict_json_is_treated_as_absent(tmp_path):
    result = tmp_path / "result.json"
    result.write_text('["not", "an", "object"]', encoding="utf-8")

    agent._write_result(result, _payload({"flag": "FLAG{new}"}))

    assert _read(result)["answers"] == {"flag": "FLAG{new}"}


def test_unreadable_answers_field_is_treated_as_empty(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload(["not", "a", "map"]))

    agent._write_result(result, _payload({"flag": "FLAG{new}"}))

    assert _read(result)["answers"] == {"flag": "FLAG{new}"}


def test_write_stays_atomic_and_leaves_no_tmp_file(tmp_path):
    result = tmp_path / "result.json"
    _write(result, _payload({"flag": "FLAG{old}"}))

    agent._write_result(result, _payload({}))

    assert not (tmp_path / "result.json.tmp").exists()
    assert _read(result)["answers"] == {"flag": "FLAG{old}"}
