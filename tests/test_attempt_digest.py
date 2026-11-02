"""P16: the retry digest must be useful, small, and secret-free."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.attempt_digest import build_digest  # noqa: E402


def test_keeps_actionable_errors_and_methods():
    calls = [
        ("http_probe", '{"method":"GET","url":"http://t/api/plugins"}'),
        ("http_probe", '{"method":"POST","url":"http://t/api/plugins/preview"}'),
    ]
    outputs = [
        "HTTP 200 OK\n{\"plugins\":[]}",
        "HTTP 400 Bad Request\n{\"error\":\"code_b64 required\"}",
    ]

    digest = build_digest(calls, outputs)

    assert "GET t/api/plugins" in digest
    assert "POST t/api/plugins/preview" in digest
    assert "400" in digest
    assert "code_b64 required" in digest
    assert "PUT, PATCH, DELETE, OPTIONS" in digest


def test_redacts_flags_and_credentials():
    calls = [
        ("http_probe", '{"method":"GET","url":"http://t/login?token=abc123456"}'),
    ]
    outputs = [
        "HTTP 200 OK\nflag=FLAG{this_must_not_leak}\npassword: hunter2secret",
    ]

    digest = build_digest(calls, outputs)

    assert "this_must_not_leak" not in digest
    assert "hunter2secret" not in digest
    assert "[REDACTED_FLAG]" in digest


def test_dedupes_repeated_pairs_but_keeps_new_signal():
    calls = [
        ("http_probe", '{"method":"GET","url":"http://t/a"}'),
        ("http_probe", '{"method":"GET","url":"http://t/a"}'),
        ("http_probe", '{"method":"GET","url":"http://t/a"}'),
    ]
    outputs = [
        "HTTP 404 Not Found",
        "HTTP 404 Not Found",
        "HTTP 200 OK",
    ]

    digest = build_digest(calls, outputs)

    assert digest.count("GET t/a") == 2
    assert "200 OK" in digest


def test_shell_commands_are_kept_as_cmd_rows():
    calls = [("exec_command", '{"command":"curl -s http://t/x | head"}')]
    outputs = ["HTTP/1.1 500 Internal Server Error"]

    digest = build_digest(calls, outputs)

    assert "CMD t/x" in digest
    assert "500" in digest


def test_empty_input_returns_empty_string():
    assert build_digest([], []) == ""


def test_meta_tools_do_not_create_fake_probes():
    calls = [
        ("finish_scan", '{"summary":"I probed http://t/a and found nothing"}'),
        ("http_probe", '{"method":"GET","url":"http://t/real"}'),
    ]
    outputs = [
        'REFUSED: summary contains no flag',
        "HTTP 200 OK",
    ]

    digest = build_digest(calls, outputs)

    assert "t/a" not in digest
    assert "GET t/real" in digest


def test_hard_cap_is_respected():
    calls = [
        ("http_probe", f'{{"method":"GET","url":"http://t/path{i}"}}')
        for i in range(40)
    ]
    outputs = ["HTTP 404 Not Found"] * 40

    digest = build_digest(calls, outputs, max_chars=400)

    assert len(digest) <= 400
    assert digest.endswith("[digest truncated]")

def test_path_variants_urls_string_is_parsed_not_treated_as_shell():
    """path_variants takes a newline-separated `urls` string, not a list.

    Before this test the digest classified it as CMD and kept the whole
    multi-line arg string as the "target", which produced a 120-char blob of
    `base_url=... kinds=...` text that told a retrying model nothing.
    """
    calls = [
        (
            "path_variants",
            '{"urls":"/internal/banner\\n/internal/status",'
            '"base_url":"https://t","kinds":"upper"}',
        ),
    ]
    outputs = ["[path_variants] 2 paths x 1 kinds x 1 method = 4 requests"]

    digest = build_digest(calls, outputs)

    assert "path_variants" in digest or "GET" in digest
    assert "/internal/banner" in digest
    assert "CMD" not in digest
