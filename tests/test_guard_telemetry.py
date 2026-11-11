"""Guard counters must survive a wall-clock SIGKILL and still be parseable.

One-line description of the change under test: guard counters are persisted
atomically after every model call, and parsers fall back to that file when the
summary line never gets printed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

import batch_eval  # noqa: E402
import run_strix_ctf  # noqa: E402
from ctf_strix.guard_state import GuardStateWriter  # noqa: E402


def _state(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "schema": 1,
        "reach": 17,
        "enum_keys": 4,
        "journey": {
            "wall": 2,
            "authed": True,
            "created": False,
            "payloads": 6,
            "prompts": 1,
        },
        "finish": {"refused": 2, "allowed": 5},
        "mechanisms": {"injection": 3},
        "mount_verified": True,
    }
    body.update(overrides)
    return body


def _write(tmp_path: Path, body: dict[str, object]) -> Path:
    path = tmp_path / "guard_state.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_killed_run_reads_counters_from_the_state_file(tmp_path: Path) -> None:
    """A run killed at the wall clock has no summary line, only the sidecar."""
    killed_log = "[sandbox] private_tmp=on\n\n[WALLCLOCK TIMEOUT after 900s]\n"
    state = _write(tmp_path, _state())

    parsed = batch_eval._parse_guard(killed_log, state)

    assert parsed["reach"] == 17
    assert parsed["enum_keys"] == 4
    assert parsed["journey_wall"] == 2
    assert parsed["journey_authed"] is True
    assert parsed["journey_created"] is False
    assert parsed["journey_payloads"] == 6
    assert parsed["journey_prompts"] == 1
    assert parsed["finish_refused"] == 2
    assert parsed["mount_broken"] is False


def test_missing_state_file_keeps_the_untrusted_default(tmp_path: Path) -> None:
    """No summary line and no file: the old "cannot trust reach=0" rule stays."""
    parsed = batch_eval._parse_guard("nothing here\n", tmp_path / "absent.json")

    assert parsed["reach"] == 0
    assert parsed["mount_broken"] is True


def test_state_file_with_unverified_mount_is_still_broken(tmp_path: Path) -> None:
    """The mount flag, not the counter value, decides brokenness."""
    state = _write(tmp_path, _state(reach=0, mount_verified=False))

    parsed = batch_eval._parse_guard("", state)

    assert parsed["mount_broken"] is True


def test_summary_line_still_wins_when_present(tmp_path: Path) -> None:
    """A printed line is authoritative; the sidecar is only a fallback."""
    guard = SimpleNamespace(
        counts={"k": 1}, mechanism_counts=lambda: {"injection": 1}, observe_calls=11
    )
    journey = SimpleNamespace(
        wall_hit=1, authed=True, created=False, payloads=2, prompts=3, observe_calls=0
    )
    finisher = SimpleNamespace(refusals=1, allowed=1)
    line = run_strix_ctf._guard_summary(guard, journey, finisher, reached=11)
    state = _write(tmp_path, _state(reach=99, mount_verified=False))

    parsed = batch_eval._parse_guard(line, state)

    assert parsed["reach"] == 11
    assert parsed["journey_prompts"] == 3
    # Line-present behaviour is unchanged: reach != 0 means the mount worked.
    assert parsed["mount_broken"] is False


def test_summary_line_with_zero_reach_stays_broken(tmp_path: Path) -> None:
    """The line path keeps its old rule even when the sidecar disagrees."""
    guard = SimpleNamespace(
        counts={}, mechanism_counts=lambda: {}, observe_calls=0
    )
    journey = SimpleNamespace(
        wall_hit=0, authed=False, created=False, payloads=0, prompts=0, observe_calls=0
    )
    finisher = SimpleNamespace(refusals=0, allowed=0)
    line = run_strix_ctf._guard_summary(guard, journey, finisher, reached=0)

    parsed = batch_eval._parse_guard(line, _write(tmp_path, _state(mount_verified=True)))

    assert parsed["reach"] == 0
    assert parsed["mount_broken"] is True


def test_writer_persists_a_valid_file_and_leaves_no_partial_json(tmp_path: Path) -> None:
    """Each persist is a complete JSON document; no half-written temp survives."""
    counters = {"reach": 1}
    target = tmp_path / "nested" / "guard_state.json"
    writer = GuardStateWriter(target, lambda: {"reach": counters["reach"]})

    assert writer.persist() is True
    assert json.loads(target.read_text(encoding="utf-8")) == {
        "reach": 1,
        "schema": 1,
    }

    counters["reach"] = 9
    assert writer.persist() is True
    assert json.loads(target.read_text(encoding="utf-8"))["reach"] == 9

    leftovers = [p.name for p in target.parent.iterdir() if p.name.startswith(".")]
    assert leftovers == []


def test_payload_round_trips_through_the_fallback_parser(tmp_path: Path) -> None:
    """The sidecar payload and the summary line carry the same numbers."""
    from ctf_strix.enum_guard import EnumerationGuard

    guard = EnumerationGuard()
    guard.observe_calls = 7
    guard.counts["p"] = 2
    guard.counts["q"] = 1
    guard.mechanisms["injection"] = 1
    journey = SimpleNamespace(
        wall_hit=3, authed=True, created=False, payloads=4, prompts=2, observe_calls=5
    )
    finisher = SimpleNamespace(refusals=2, allowed=6)

    payload = run_strix_ctf._guard_state_payload(guard, journey, finisher, True)
    state = _write(tmp_path, payload)
    parsed = batch_eval._parse_guard("", state)

    line = run_strix_ctf._guard_summary(guard, journey, finisher, reached=12)
    from_line = batch_eval._parse_guard(line)

    for key in (
        "reach",
        "enum_keys",
        "journey_wall",
        "journey_authed",
        "journey_created",
        "journey_payloads",
        "journey_prompts",
        "finish_refused",
    ):
        assert parsed[key] == from_line[key], key
    assert parsed["mount_broken"] is False
