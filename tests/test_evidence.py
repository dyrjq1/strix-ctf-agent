"""Regression: a flag only counts if this run actually read it.

Both cases below are real runs from 2026-10-31 and are replayed from the
recorded transcripts (see docs/11 section 4.15).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.evidence import EvidenceLedger  # noqa: E402

#: CTFARENA-082, the genuine solve: the operator row came back from the target.
REAL_OUTPUT = (
    "4 200 {\"ok\":true,\"member\":{\"id\":4,\"username\":\"operator\","
    "\"role\":\"operator\",\"recoverySlip\":\"FLAG{2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b}\"}}"
)
REAL_FLAG = "FLAG{2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b}"

#: CTFARENA-078 attempt 2: written by the model, present in no tool output.
FABRICATED_FLAG = "FLAG{3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f}"

#: CTFARENA-018 attempt 2: real flag, but read from a stale /tmp file.
STALE_FILE_OUTPUT = (
    "{\"id\":1,\"title\":\"Vault Master Key\","
    "\"content\":\"FLAG{9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c}\"}"
)


def test_flag_seen_in_output_is_supported():
    ledger = EvidenceLedger()
    ledger.observe_output(REAL_OUTPUT)
    assert ledger.supports(REAL_FLAG)
    assert ledger.summary()["flags_observed"] == 1


def test_fabricated_flag_is_not_supported():
    """078: nothing in the run ever produced this string."""
    ledger = EvidenceLedger()
    ledger.observe_output(REAL_OUTPUT)
    assert not ledger.supports(FABRICATED_FLAG)
    ledger.reject(FABRICATED_FLAG)
    assert ledger.summary()["unsupported_claims"] == [FABRICATED_FLAG]


def test_output_without_flag_adds_no_evidence():
    ledger = EvidenceLedger()
    ledger.observe_output("HTTP 404 Not Found")
    assert not ledger.supports(REAL_FLAG)
    assert ledger.observed == {}


def test_empty_and_none_outputs_are_safe():
    ledger = EvidenceLedger()
    ledger.observe_output("")
    ledger.observe_output(None)  # type: ignore[arg-type]
    assert ledger.observed == {}


def test_counts_repeats_of_the_same_flag():
    ledger = EvidenceLedger()
    ledger.observe_output(REAL_OUTPUT)
    ledger.observe_output(REAL_OUTPUT)
    assert ledger.observed[REAL_FLAG] == 2


def test_stale_local_read_is_still_supported_by_design():
    """018 is NOT fixed by this gate -- and that is deliberate.

    The flag really was printed by a tool output during the run; the defect is
    that host ``/tmp`` is shared between runs.  Rejecting it here would need
    string heuristics that also reject genuine solves which write a probe
    script to ``/tmp`` and print the answer from it (CTFARENA-009 did that).

    This test documents the boundary, so nobody "fixes" it with a heuristic.
    """
    ledger = EvidenceLedger()
    ledger.observe_output(STALE_FILE_OUTPUT)
    assert ledger.supports("FLAG{9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c}")


def test_placeholder_never_counts_as_evidence():
    """2026-11-06 v6 冒烟：agent 读自己的源码，注释里的 ``FLAG{xxxx}`` 被当证据。

    抽取层过滤只能挡住「按 proximity 挑一个」的那条路；finish_scan 参数、
    并行 race-win 等路径直接问 ``ledger.supports()``，所以证据层也必须挡。
    """
    ledger = EvidenceLedger()
    ledger.observe_output("cat /app/src/ctf_strix/finish_guard.py -> FLAG{xxxx}")
    assert ledger.supports("FLAG{xxxx}") is False
    assert "FLAG{xxxx}" not in ledger.observed
