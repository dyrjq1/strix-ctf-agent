# -*- coding: utf-8 -*-
"""Tags must reach the child process, or the tag-keyed card block never renders.

Measured 2026-11-15 over every recorded run (402 session databases): not one
injected message contained the card header, because ``run_strix_ctf.py`` was
never given ``--tags``. The card table, and the A/B that adopted it, were both
inert. These tests pin the wiring so it cannot silently come apart again.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402

BE_SRC = (ROOT / "scripts" / "batch_eval.py").read_text(encoding="utf-8")


def test_tags_arg_builds_the_flag() -> None:
    assert batch_eval._tags_arg(["ssrf", "idor"]) == ["--tags", "ssrf", "idor"]


def test_tags_arg_is_empty_without_usable_tags() -> None:
    assert batch_eval._tags_arg(None) == []
    assert batch_eval._tags_arg([]) == []
    assert batch_eval._tags_arg(["", "   "]) == []


def test_tags_arg_drops_anything_flag_shaped() -> None:
    """A tag is an identifier; a leading dash would be parsed as a CLI flag."""
    assert batch_eval._tags_arg(["--instance", "-x", "ok_tag"]) == ["--tags", "ok_tag"]
    assert batch_eval._tags_arg(["a b"]) == []  # space is not an identifier


def test_tags_arg_strips_and_dedupes_but_keeps_case() -> None:
    assert batch_eval._tags_arg([" ssrf ", "ssrf"]) == ["--tags", "ssrf"]
    # Case is preserved: tag matching lowercases on its own, and rewriting the
    # value here would be a second, divergent normalisation rule.
    assert batch_eval._tags_arg(["SSRF"]) == ["--tags", "SSRF"]


def test_run_agent_puts_tags_on_the_child_command() -> None:
    assert "tags: list[str] | None = None" in BE_SRC
    assert "cmd += _tags_arg(tags)" in BE_SRC


def test_cards_off_switch_reaches_the_child_and_the_row() -> None:
    """The card A/B arms share one working tree, so arm A only exists if the
    switch is forwarded to the child env -- and only checkable if each row
    records which arm it belongs to (the 11-14 P0-4 ablation ran both arms
    identical precisely because the switch was not forwarded)."""
    assert '"CTF_CARDS_OFF": os.environ.get("CTF_CARDS_OFF", "")' in BE_SRC
    assert 'rec["cards_off"] = os.environ.get("CTF_CARDS_OFF", "")' in BE_SRC


def test_both_run_agent_call_sites_pass_tags() -> None:
    """Instance path and QA path: a challenge answered without a target still
    carries the tags its challenge was published with."""
    assert BE_SRC.count("_tags_arg(tags)") == 1
    assert "challenge_detail.get(\"tags\")" in BE_SRC
    assert "(detail.get(\"tags\") or [])" in BE_SRC