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
    "args",
    [
        "cat > notes.sh <<'EOF'\n  EOF\ncurl -H 'Cookie: a=b' http://target/\nEOF",
        "bash <<EOF\n\tEOF\ncurl -H 'Cookie: a=b' http://target/\nEOF",
    ],
)
def test_indented_terminator_does_not_end_a_plain_heredoc(args: str) -> None:
    """A space- or tab-indented ``EOF`` is body text for plain ``<<``.

    Ending the body there would expose the following ``curl -H 'Cookie: ...'``
    line as a command and re-open the authentication false positive.
    """
    assert _args_session_signal(args) is False


@pytest.mark.parametrize(
    "args",
    [
        "bash <<-EOF\n\tbody\n\tEOF\ncurl -H 'Cookie: a=b' http://target/",
        "bash <<-'EOF'\n\tbody\n\tEOF\ncurl -H 'Cookie: a=b' http://target/",
    ],
)
def test_tab_indented_terminator_ends_a_dash_heredoc(args: str) -> None:
    """``<<-`` strips leading tabs, so its tab-indented terminator is real."""
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


# ---------------------------------------------------------------------------
# WEB-3: the header line has two renderings, and both carry a session
# ---------------------------------------------------------------------------

def _probe_output(
    status: int,
    *,
    path: str,
    headers: str = "content-type=application/json",
    body: str = "",
    hint: str = "",
) -> str:
    """One ``http_probe`` result, exactly as ``http_probe`` joins its lines."""
    lines = [
        f"[HTTP {status}] GET https://target.test{path} | 0.11s | 27B | "
        f"application/json | id=r3",
        f"hdr: {headers}",
    ]
    if body:
        lines.append(f"body: {body}")
    if hint:
        lines.append(f"next: {hint}")
    return "\n".join(lines)


def test_http_probe_rendered_set_cookie_releases_the_guard() -> None:
    """WEB-3: ``http_probe`` prints ``set-cookie=...``, not ``Set-Cookie: ...``.

    ``_format_headers`` joins picked headers as ``name=value``.  The guard only
    accepted the ``Set-Cookie:`` colon form (``curl -i`` output), so a login
    completed through ``http_probe`` never released it -- six later payloads
    hit the hard stop on a session that was already authenticated.
    """
    output = _probe_output(
        200,
        path="/api/login",
        headers="content-type=application/json | set-cookie=sid=abc123; Path=/; HttpOnly",
        body='{"ok":true}',
    )

    guard = JourneyGuard()
    guard.observe("http_probe", "https://target.test/api/login", output)

    assert _AUTH_OK_RE.search(output) is not None
    assert guard.state.authed is True


def test_probe_without_a_session_header_leaves_the_guard_armed() -> None:
    """Reverse control: the widened separator must not accept a plain 200."""
    output = _probe_output(200, path="/api/items", body="[]")

    guard = JourneyGuard()
    guard.observe("http_probe", "https://target.test/api/items", output)

    assert _AUTH_OK_RE.search(output) is None
    assert guard.state.authed is False


def test_probe_login_releases_a_guard_already_counting_payloads() -> None:
    """End to end: six payloads hard-stop, then a probe login silences it."""
    guard = JourneyGuard()
    payload = "curl -s 'https://target.test/api/items?id=1 OR 1=1'"

    guard.observe("http_probe", "https://target.test/api/login", _probe_output(
        401, path="/api/login", body='{"error":"unauthorized"}',
        hint="鉴权被拒：先走注册/登录拿会话，别继续盲试参数。",
    ))
    hints = [guard.observe("exec_command", payload, "500 oops") for _ in range(6)]

    assert any("HARD STOP" in (hint or "") for hint in hints), hints
    assert guard.state.payloads == 6

    guard.observe("http_probe", "https://target.test/api/login", _probe_output(
        200, path="/api/login",
        headers="content-type=application/json | set-cookie=sid=abc123; Path=/",
        body='{"ok":true}',
    ))

    assert guard.state.authed is True
    assert guard.observe("exec_command", payload, "200 []") is None
    assert guard.state.payloads == 6, "a released guard must not keep counting"
