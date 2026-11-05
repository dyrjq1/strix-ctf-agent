"""Self-echo provenance: a guess replayed by a tool is not a retrieval.

External review Q6: the model can write its own guess into a command, a
script argument, or a submission payload.  The tool then prints it back and
the old ledger counted that output as proof.  The rule implemented here uses
only data the run already has -- the call's own arguments -- so it does not
need the string heuristics this module deliberately avoids.  CTFARENA-009's
``/tmp`` probe script (flag only in the *output*) must keep counting.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.evidence import EvidenceLedger  # noqa: E402
from ctf_strix.finish_guard import FinishGuard  # noqa: E402
from ctf_strix.success_stop import SuccessLedger  # noqa: E402

FLAG = "FLAG{e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0}"
OTHER = "FLAG{a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1}"


def _echo_command(flag: str) -> str:
    return f'{{"command": "echo {flag}"}}'


def test_a_genuine_output_without_the_literal_in_args_is_retrieved():
    """CTFARENA-009: the probe script's source has no flag; its output does."""
    ledger = EvidenceLedger()
    ledger.observe_output(
        f"$ python3 /tmp/probe.py\n{FLAG}",
        arguments='{"command": "python3 /tmp/probe.py"}',
    )
    assert ledger.supports(FLAG)
    assert ledger.summary()["retrieved_flags"] == [FLAG]


def test_b_echoing_the_guess_back_is_not_retrieved():
    ledger = EvidenceLedger()
    ledger.observe_output(
        f"$ echo {FLAG}\n{FLAG}",
        arguments=_echo_command(FLAG),
    )
    assert not ledger.supports(FLAG)
    assert ledger.echoed_only(FLAG)


def test_c_server_replaying_a_wrong_submission_is_not_retrieved():
    ledger = EvidenceLedger()
    ledger.observe_output(
        f"HTTP/1.1 200 OK\nwrong: {FLAG}",
        arguments=json.dumps({"method": "POST", "data": f"answer={FLAG}"}),
    )
    assert not ledger.supports(FLAG)
    assert ledger.summary()["echoed_only_flags"] == [FLAG]


def test_d_a_later_clean_output_restores_support():
    ledger = EvidenceLedger()
    ledger.observe_output(f"$ echo {FLAG}\n{FLAG}", arguments=_echo_command(FLAG))
    assert not ledger.supports(FLAG)

    # Different call, arguments do not contain the literal -> real retrieval.
    ledger.observe_output(
        f"$ cat /flag\n{FLAG}",
        arguments='{"command": "cat /flag"}',
    )
    assert ledger.supports(FLAG)
    assert ledger.observed[FLAG] == 1
    assert ledger.echoed[FLAG] == 1
    # No longer echo-only: the diagnostic moves it to the retrieved side.
    assert ledger.summary()["echoed_only_flags"] == []
    assert ledger.summary()["retrieved_flags"] == [FLAG]


def test_e_finish_guard_refuses_echo_only_evidence_with_an_echo_hint():
    ledger = EvidenceLedger()
    ledger.observe_output(f"$ echo {FLAG}\n{FLAG}", arguments=_echo_command(FLAG))
    success = SuccessLedger()
    guard = FinishGuard(success=success, evidence=ledger)

    refusal = guard.check(json.dumps({"summary": f"answer {FLAG}"}))
    assert refusal is not None and refusal["success"] is False
    message = refusal["error"].lower()
    assert "self-echo" in message
    assert "not retrieval" in message
    assert not success.solved


def test_e_finish_guard_still_allows_a_genuine_retrieval():
    ledger = EvidenceLedger()
    ledger.observe_output(
        f"$ cat /flag\n{FLAG}",
        arguments='{"command": "cat /flag"}',
    )
    success = SuccessLedger()
    guard = FinishGuard(success=success, evidence=ledger)

    assert guard.check(json.dumps({"summary": f"answer {FLAG}"})) is None
    assert success.solved
    assert success.answer == FLAG


def test_f_summary_separates_retrieved_from_echoed():
    ledger = EvidenceLedger()
    ledger.observe_output(
        f"$ cat /flag\n{OTHER}",
        arguments='{"command": "cat /flag"}',
    )
    ledger.observe_output(f"$ echo {FLAG}\n{FLAG}", arguments=_echo_command(FLAG))

    summary = ledger.summary()
    assert summary["flags_observed"] == 1
    assert summary["outputs_with_flag"] == 1
    assert summary["flags_echoed"] == 1
    assert summary["echoed_observations"] == 1
    assert summary["retrieved_flags"] == [OTHER]
    assert summary["echoed_only_flags"] == [FLAG]


def test_g_arg_claims_path_cannot_fire_on_a_pure_self_echo():
    """agent.py promotes a claim only when ``ledger.supports`` is true.

    The literal is extracted from the call arguments (so ``arg_claims`` does
    hold it), but the echo observation leaves support false.  That is the
    intended narrowing of the "flag captured from tool args" path.
    """
    from ctf_strix.agent import _extract_args_flags

    ledger = EvidenceLedger()
    args = json.dumps({"summary": f"the answer is {FLAG}"})
    claims = _extract_args_flags(args)
    assert claims == [FLAG]

    ledger.observe_output(f"tool echoed: {args}", arguments=args)
    assert not ledger.supports(claims[0])
    assert ledger.echoed_only(claims[0])


def test_g_arg_claims_path_still_confirms_an_earlier_retrieval():
    from ctf_strix.agent import _extract_args_flags

    ledger = EvidenceLedger()
    ledger.observe_output(
        f"$ cat /flag\n{FLAG}",
        arguments='{"command": "cat /flag"}',
    )
    claims = _extract_args_flags(json.dumps({"summary": f"answer {FLAG}"}))
    assert claims == [FLAG]
    assert ledger.supports(claims[0])


def test_tcp_payload_echo_is_not_retrieved():
    payload = f"GET /?probe={FLAG} HTTP/1.0\r\n\r\n"
    args = json.dumps({"target": "10.0.0.5", "port": 80, "payload": payload})
    ledger = EvidenceLedger()
    ledger.observe_output(f"HTTP/1.0 200 OK\r\n\r\n{FLAG}", arguments=args)
    assert not ledger.supports(FLAG)


def test_tcp_response_without_the_literal_in_the_payload_is_retrieved():
    args = json.dumps(
        {"target": "10.0.0.5", "port": 80, "payload": "GET /flag HTTP/1.0\r\n\r\n"}
    )
    ledger = EvidenceLedger()
    ledger.observe_output(f"HTTP/1.0 200 OK\r\n\r\n{FLAG}", arguments=args)
    assert ledger.supports(FLAG)


def test_parallel_finish_does_not_stop_children_on_echoed_evidence():
    """parallel.py consumes the same ``supports`` predicate; no extra code."""
    from ctf_strix import parallel

    ledger = EvidenceLedger()
    ledger.observe_output(f"$ echo {FLAG}\n{FLAG}", arguments=_echo_command(FLAG))
    parallel.configure(evidence=ledger)
    try:
        raw = json.dumps({"summary": f"answer {FLAG}"})
        assert parallel._should_stop_children(raw) is False

        ledger.observe_output(
            f"$ cat /flag\n{FLAG}",
            arguments='{"command": "cat /flag"}',
        )
        assert parallel._should_stop_children(raw) is True
    finally:
        parallel.reset_run()
