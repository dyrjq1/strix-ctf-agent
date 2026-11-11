"""Journey guard must recognise session workflows carried in exec arguments.

One-line description of the change under test: the journey guard treats curl
and wget cookie-jar flags, and explicit Cookie request headers, as proof that a
session is in use, without matching unrelated commands.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.journey_guard import JourneyGuard, _AUTH_OK_RE, _args_session_signal  # noqa: E402


@pytest.mark.parametrize(
    "args",
    [
        'curl -b jar.txt http://target/profile',
        'curl -c jar.txt -d "user=a&pass=b" http://target/login',
        'curl --cookie jar.txt http://target/profile',
        'curl --cookie-jar=jar.txt http://target/login',
        'wget --load-cookies jar.txt http://target/profile',
        'wget --save-cookies jar.txt --keep-session-cookies http://target/login',
        'curl http://target/profile -H "Cookie: sid=abc123"',
        'curl http://target/profile -H \'Cookie: sid=abc123\'',
        'curl http://target/profile --header "Cookie: a=b; c=d"',
        'curl.exe -b jar.txt http://target/profile',
        '/usr/bin/curl -b jar.txt http://target/profile',
        json.dumps({"command": "curl -b jar.txt http://target/profile"}),
        json.dumps({"command": 'curl http://target/profile -H "Cookie: sid=abc"'}),
    ],
)
def test_cookie_workflow_in_arguments_counts_as_authenticated(args: str) -> None:
    """Every mechanism-level cookie signal flips the guard to authenticated."""
    guard = JourneyGuard()

    assert _args_session_signal(args) is True
    assert guard.observe("exec_command", args, "200 OK") is None
    assert guard.state.authed is True


@pytest.mark.parametrize(
    "args",
    [
        "python -c 'print(1)'",
        "python -c 'import pycurl'",
        "python -c 'print(\"curl -b jar\")'",
        "cat /tmp/notes.txt",
        "curl http://target/index.html",
        "wget http://target/index.html",
        "ls -c -b",
        json.dumps({"command": "python -c 'print(1)'"}),
        json.dumps({"command": 'python -c \'print("curl -b jar")\''}),
    ],
)
def test_unrelated_commands_do_not_count_as_authenticated(args: str) -> None:
    """Token-level gating: no curl/wget command means no cookie-flag signal."""
    guard = JourneyGuard()

    assert _args_session_signal(args) is False
    guard.observe("exec_command", args, "200 OK")
    assert guard.state.authed is False


@pytest.mark.parametrize(
    "args",
    [
        "wget -c http://target/big.bin",
        "curl -s http://target/ ; grep -c 404 access.log",
        "curl -s http://target/ | sort -b",
        "curl -s http://target/ ; awk -b '{print}'",
        "echo 'curl -H \"Cookie: sid=1\" http://target/'",
        "printf '%s\\n' 'curl -H \"Cookie: sid=1\"' > notes.txt",
        "cat > notes.sh <<'EOF'\ncurl -H 'Cookie: a=b' http://target/\nEOF",
        "bash <<EOF\ncurl -b jar.txt http://target/\nEOF",
    ],
)
def test_short_flags_and_printed_text_are_not_session_signals(args: str) -> None:
    """Cookie flags count only inside the curl/wget segment that owns them."""
    assert _args_session_signal(args) is False


@pytest.mark.parametrize(
    "args",
    [
        "curl -b cj.txt http://target/profile",
        "curl -H 'Cookie: a=b' http://target/profile",
        "wget --save-cookies cj.txt http://target/login",
    ],
)
def test_cookie_flags_inside_client_segments_still_count(args: str) -> None:
    """The narrowed gate must not lose the genuine session workflows."""
    assert _args_session_signal(args) is True


@pytest.mark.parametrize(
    "output",
    [
        "HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; path=/",
        '{"access_token": "abcdef"}',
        '{"token": "abcdef"}',
        "session=abcdef",
        "Authorization: Bearer abcdefghijklmnop",
    ],
)
def test_output_side_auth_signals_are_unchanged(output: str) -> None:
    """The five original output patterns keep releasing the guard."""
    guard = JourneyGuard()

    guard.observe("exec_command", "curl http://target/login", output)

    assert _AUTH_OK_RE.search(output) is not None
    assert guard.state.authed is True


def test_plain_request_without_cookie_never_releases_the_guard() -> None:
    """A bare GET must not be mistaken for a hold on a session."""
    guard = JourneyGuard()
    guard.observe("exec_command", "curl http://target/login", "403 Forbidden")

    assert guard.state.authed is False
    assert guard.state.wall_hit == 1
