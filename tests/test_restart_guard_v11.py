"""restart_guard v1.1: shell URLs into T3, negative evidence, truncation pointer.

Each test docstring is the one-sentence description used by the naming check:
no ticket number, IP, path, or flag literal appears in any of them.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402
import run_strix_ctf  # noqa: E402
from ctf_strix import command_tokens  # noqa: E402
from ctf_strix import negative_guard as ng  # noqa: E402
from ctf_strix import restart_guard as rg  # noqa: E402
from ctf_strix.traffic import Exchange  # noqa: E402


def _guard(window: int = 20) -> rg.RestartGuard:
    return rg.RestartGuard(
        elapsed=lambda: 0.0,
        wall=lambda: 1800.0,
        ledger_items=lambda: [],
        window=window,
    )


def _args(command: str) -> str:
    return json.dumps({"command": command})


# ---------------------------------------------------------------------------
# G1: shell HTTP reaches the T3 endpoint window, de-duplicated
# ---------------------------------------------------------------------------


def test_curl_urls_enter_the_endpoint_window_once_per_distinct_url() -> None:
    """Repeating one command URL five times leaves one window entry, not five."""
    guard = _guard()
    args = _args("curl -sS http://h:8080/item?id=1")

    for _ in range(5):
        guard.observe("exec_command", args, "same body")

    sources = guard.endpoint_sources()
    assert sources["window_size"] == 1
    assert sources["window_exec"] == 1
    assert sources["distinct_exec"] == 1


def test_python_string_that_mentions_curl_does_not_enter_the_window() -> None:
    """A curl word inside a Python one-liner is text, not a request."""
    guard = _guard()
    args = _args('python -c \'print("curl http://h/p")\'')

    guard.observe("exec_command", args, "printed")

    assert guard.endpoint_sources()["window_size"] == 0


def test_option_values_are_not_mistaken_for_urls() -> None:
    """Cookie/header/output option values never become endpoint entries; the URL does."""
    guard = _guard()
    args = _args('curl -H "Cookie: a=b" -o out.html -b jar.txt http://h/p')

    guard.observe("exec_command", args, "ok")

    sources = guard.endpoint_sources()
    assert sources["distinct_exec"] == 1
    assert sources["window_size"] == 1


def test_wget_url_is_extracted_after_cookie_switches() -> None:
    """wget cookie switches consume their files; the following URL is recorded."""
    guard = _guard()
    args = _args("wget --load-cookies cj.txt -O out.html http://h:9000/a")

    guard.observe("exec_command", args, "ok")

    assert guard.endpoint_sources()["distinct_exec"] == 1


def test_probe_ledger_and_shell_urls_share_one_window() -> None:
    """Ledger-recorded probes and shell-issued URLs coexist in the same T3 window."""
    ledger = [
        Exchange(
            id="r1",
            ts=0.0,
            method="GET",
            url="http://h/a",
            status=200,
            resp_body="a",
            size=1,
        )
    ]
    guard = rg.RestartGuard(
        elapsed=lambda: 0.0,
        wall=lambda: 1800.0,
        ledger_items=lambda: ledger,
        window=20,
    )
    guard.sync_ledger()

    guard.observe("exec_command", _args("curl http://h/b"), "b")

    sources = guard.endpoint_sources()
    assert sources["distinct_probe"] == 1
    assert sources["distinct_exec"] == 1
    assert sources["window_size"] == 2
    assert sources["window_probe"] == 1
    assert sources["window_exec"] == 1


def test_url_normalization_drops_default_port_and_caps_path_query() -> None:
    """Default ports collapse and path+query is capped at 48 characters."""
    assert command_tokens.normalize_url("HTTP://H:80/x") == ("http://h", "/x")
    assert command_tokens.normalize_url("https://h/a?b=1") == ("https://h", "/a?b=1")

    origin, suffix = command_tokens.normalize_url(
        "http://h/" + "a" * 60 + "?q=" + "b" * 20
    )
    assert origin == "http://h"
    assert len(suffix) == 48


# ---------------------------------------------------------------------------
# G4: repeated negative evidence earns exactly one direction change
# ---------------------------------------------------------------------------


def test_repeated_identical_output_is_hinted_on_the_third_round_only() -> None:
    """Round two is silent, round three injects once, round four stays silent."""
    guard = ng.NegativeEvidenceGuard()
    args = _args("curl -s http://h/p")

    assert guard.observe("exec_command", args, "same") is None
    assert guard.observe("exec_command", args, "same") is None
    hint = guard.observe("exec_command", args, "same")

    assert hint is not None
    assert "[NEGATIVE EVIDENCE GUARD]" in hint
    assert "read-back path" in hint
    assert guard.observe("exec_command", args, "same") is None
    assert guard.stats()["injections"] == 1


def test_one_changed_character_starts_a_new_group() -> None:
    """A different command is a different group even with the same output."""
    guard = ng.NegativeEvidenceGuard()
    first = _args("curl -s http://h/p")
    second = _args("curl -s http://h/q")

    for _ in range(2):
        assert guard.observe("exec_command", first, "same") is None
        assert guard.observe("exec_command", second, "same") is None
    hint = guard.observe("exec_command", first, "same")

    assert hint is not None and "[NEGATIVE EVIDENCE GUARD]" in hint
    assert guard.stats()["groups"] == 2


def test_changed_output_starts_a_new_group() -> None:
    """A response that changed is new information and resets the streak."""
    guard = ng.NegativeEvidenceGuard()
    args = _args("curl -s http://h/p")

    assert guard.observe("exec_command", args, "same") is None
    assert guard.observe("exec_command", args, "same") is None
    assert guard.observe("exec_command", args, "changed") is None
    assert guard.observe("exec_command", args, "changed") is None
    hint = guard.observe("exec_command", args, "changed")

    assert hint is not None and "[NEGATIVE EVIDENCE GUARD]" in hint
    assert guard.stats()["groups"] == 2


def test_injection_ceiling_counts_but_stops_nagging() -> None:
    """After two per-run injections a third group is counted but not hinted."""
    guard = ng.NegativeEvidenceGuard()

    for name in ("a", "b", "c"):
        args = _args(f"curl -s http://h/{name}")
        assert guard.observe("exec_command", args, "same") is None
        assert guard.observe("exec_command", args, "same") is None
        guard.observe("exec_command", args, "same")

    stats = guard.stats()
    assert stats["injections"] == 2 == ng.LIMITS[ng.L4]
    assert stats["groups"] == 3


def test_non_shell_tool_is_never_counted() -> None:
    """Only exec_command results feed the negative-evidence counter."""
    guard = ng.NegativeEvidenceGuard()
    args = _args("curl http://h/p")

    for _ in range(4):
        assert guard.observe("http_probe", args, "same") is None

    assert guard.stats() == {
        "groups": 0,
        "injections": 0,
        "limit": 2,
        "truncation_pointers": 0,
    }


def test_threshold_and_limit_are_frozen_constants() -> None:
    """K and the per-run injection ceiling are literal constants, not tunables."""
    assert ng.K == 3
    assert ng.LIMITS == {"L4": 2}


# ---------------------------------------------------------------------------
# G5: truncation gets a read-back pointer
# ---------------------------------------------------------------------------


def _truncate(text: str, *, max_lines: int = 20, max_bytes: int = 400) -> str:
    from strix.tools.output_store import bound_text

    return bound_text(text, max_lines=max_lines, max_bytes=max_bytes)


def test_truncated_output_carries_a_read_back_pointer() -> None:
    """The vendor truncation notice triggers exactly one retrieval pointer."""
    big = "\n".join(f"line {index}" for index in range(400))
    truncated = _truncate(big)

    assert "truncated" in truncated
    pointer = ng.truncation_pointer(truncated)

    assert pointer is not None
    assert "[TOOL OUTPUT TRUNCATED]" in pointer
    assert "dropped range" in pointer


def test_untruncated_output_has_no_pointer() -> None:
    """A result that fits needs no read-back advice."""
    assert ng.truncation_pointer("short output") is None


def test_spill_notice_points_at_the_saved_file() -> None:
    """When the vendor spilled the full output, the pointer names that path."""
    notice = (
        "[... 5 lines (100 bytes) truncated \u2014 full output saved to "
        "/workspace/.tool-output/abc.txt in the sandbox; read it with "
        "exec_command (e.g. `sed -n`, `grep`, `cat`) ...]"
    )

    pointer = ng.truncation_pointer(notice)

    assert pointer is not None
    assert "/workspace/.tool-output/abc.txt" in pointer


def test_direction_change_precedes_the_truncation_pointer() -> None:
    """When both fire on one result, the strategy hint comes first, then the pointer."""
    guard = ng.NegativeEvidenceGuard()
    big = "\n".join(f"line {index}" for index in range(400))
    truncated = _truncate(big)
    args = _args("curl -s http://h/p")

    early = guard.observe("exec_command", args, truncated)
    assert early is not None and "[NEGATIVE EVIDENCE GUARD]" not in early
    assert guard.observe("exec_command", args, truncated) is not None
    hint = guard.observe("exec_command", args, truncated)

    assert hint is not None
    strategy = hint.index("[NEGATIVE EVIDENCE GUARD]")
    pointer = hint.index("[TOOL OUTPUT TRUNCATED]")
    assert strategy < pointer


# ---------------------------------------------------------------------------
# sidecar round trip + naming
# ---------------------------------------------------------------------------


def test_v11_counters_round_trip_through_the_state_file(
    tmp_path: Path, monkeypatch
) -> None:
    """The new counters survive JSON persistence and are read by the parser."""
    monkeypatch.setattr(
        run_strix_ctf,
        "_endpoint_sources",
        lambda: {
            "distinct_probe": 4,
            "distinct_exec": 2,
            "window_size": 6,
            "window_probe": 4,
            "window_exec": 2,
        },
    )
    guard = SimpleNamespace(
        counts={},
        observe_calls=0,
        mechanism_counts=lambda: {},
    )
    journey = SimpleNamespace(
        wall_hit=0, authed=False, created=False, payloads=0, prompts=0, observe_calls=0
    )
    finisher = SimpleNamespace(refusals=0, allowed=0)
    negative = ng.NegativeEvidenceGuard()
    args = _args("curl http://h/p")
    for _ in range(3):
        negative.observe("exec_command", args, "same")

    payload = run_strix_ctf._guard_state_payload(guard, journey, finisher, True, negative)
    path = tmp_path / "guard_state.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = batch_eval._parse_guard("", path)

    assert parsed["endpoint_probe"] == 4
    assert parsed["endpoint_exec"] == 2
    assert parsed["endpoint_window"] == 6
    assert parsed["negative_groups"] == 1
    assert parsed["negative_injections"] == 1
    assert parsed["negative_limit"] == 2


def test_naming_statements_have_no_ticket_ip_path_or_flag() -> None:
    """Each change's one-line description stays capability-level and generic."""
    for text in (
        command_tokens.CHANGE_SUMMARY,
        ng.CHANGE_SUMMARY_G4,
        ng.CHANGE_SUMMARY_G5,
    ):
        assert text.count(". ") <= 0
        assert not re.search(r"\b(?:CTF|S|r)\d{2,4}\b", text, re.I)
        assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        assert "/" not in text and "\\" not in text
        assert "flag" not in text.lower()