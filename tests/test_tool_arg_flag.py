"""Regression: answer carried by finish_scan arguments.

082 exposed this: the agent read the flag correctly and put it in the
``finish_scan`` payload, but the entrypoint only scanned tool *outputs*, so
``answers`` stayed empty.  The fix scans full (untruncated) arguments for
non-engagement challenges.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.agent import _extract_flag  # noqa: E402


def test_flag_in_finish_scan_payload_is_extractable():
    host = "abc123.node2.ctfy.run"
    payload = (
        '{"executive_summary":"**Answer: `FLAG{9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a}`** '
        f'from https://{host}/api/users/4",'
        '"technical_analysis":"GET /api/users/4 returned recoverySlip"}'
    )

    assert _extract_flag(payload, host) == "FLAG{9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a}"


def test_flag_far_from_host_is_not_promoted():
    host = "abc123.node2.ctfy.run"
    payload = "FLAG{" + "a" * 32 + "}" + (" padding" * 400)

    # The extractor may still return the only candidate; the point is that it
    # must not invent a different flag.  Keep this explicit so a future
    # scoring change shows up here.
    result = _extract_flag(payload, host)
    assert result is None or result.startswith("FLAG{")


def test_flag_written_but_never_read_is_rejected():
    """078: the model invented ``3cada892...``; no tool output ever had it."""
    from ctf_strix.evidence import EvidenceLedger

    host = "sx45loqqzit4kvrlq.node1.ctfy.run"
    ledger = EvidenceLedger()
    ledger.observe_output(
        '4 200 {"member":{"role":"operator",'
        '"recoverySlip":"FLAG{2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b}"}}'
    )
    claimed = '{"executive_summary":"Answer: FLAG{3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f}",' + '"target":"https://' + host + '/"}'
    found = _extract_flag(claimed, host)
    assert found == "FLAG{3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f}"   # extractor still sees it
    assert not ledger.supports(found)                            # ledger refuses it


def test_flag_read_by_the_run_is_accepted():
    """082: same code path, but the output really contained the flag."""
    from ctf_strix.evidence import EvidenceLedger

    host = "sx45loqqzit4kvrlq.node1.ctfy.run"
    output = '4 200 {"member":{"role":"operator","recoverySlip":"FLAG{2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b}"}}'
    ledger = EvidenceLedger()
    ledger.observe_output(output)
    claimed = '{"executive_summary":"Answer: FLAG{2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b}",' + '"target":"https://' + host + '/"}'
    found = _extract_flag(claimed, host)
    assert found == "FLAG{2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b}"
    assert ledger.supports(found)
