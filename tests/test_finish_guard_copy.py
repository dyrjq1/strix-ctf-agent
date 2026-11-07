"""The "no flag" refusal must point at target data, not at the local filesystem.

Hunting the agent's own filesystem for a flag-looking filename is a ritual: in
the challenge container the flag is not at a findable local path, and the hunt
burns turns. The refusal should send the model back to data it already reached
on the target.
"""

from __future__ import annotations

from ctf_strix import finish_guard


def _refusal() -> str:
    return finish_guard._REFUSAL["error"]


def test_refusal_does_not_hunt_the_local_filesystem() -> None:
    text = _refusal().lower()
    assert "find /" not in text
    assert "locate" not in text


def test_refusal_points_at_target_data() -> None:
    text = _refusal()
    assert "SELECT * FROM" in text
    assert "data you already reached" in text.lower()
