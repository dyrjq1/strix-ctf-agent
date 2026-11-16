"""Headless browser primitive: read a page the way a browser renders it.

Why this module exists
----------------------
``http_probe`` returns the bytes the server sent.  A growing share of web
challenges send an empty shell and build the page in JavaScript, so that bytes
say nothing about what the browser shows: the flag sits in a script-built DOM,
in a cookie a script sets, or behind a client-side route.  The image shipped
no browser (docs/30), so the only move left was guessing at bundles by hand.

The primitive is deliberately driver-free: it shells out to the distro
``chromium`` binary that ``docker/check_toolchain.sh`` boots once per build.
No Playwright/Selenium dependency, so there is no driver-version pairing that
can break silently between the lock file and the browser build.

Two modes, both one call:

* ``dom`` -- run the page with scripts for ``wait_ms`` of virtual time, then
  return the serialised DOM.  This is what a browser-only page looks like once
  it has finished building itself.
* ``shot`` -- the same, but save a PNG and return its path, for pages whose
  content is canvas/image rather than text.

Scope limit worth knowing: requests the browser makes are not in the run's
traffic ledger (``traffic_list`` only sees this package's own exchanges), and
the tool cannot set cookies or click.  When a step needs those, drive the page
from ``exec_command`` -- the binary is on PATH.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Final

#: Browser binary, in probe order.  ``CTF_CHROMIUM`` overrides the search (the
#: tests use it; an operator can point it at another Chromium build).
BINARY_ENV: Final = "CTF_CHROMIUM"
BINARIES: Final = ("chromium", "chromium-browser", "google-chrome", "chrome")

#: Ablation switch, same shape as ``CTF_VIABILITY``: only ``0/false/no`` turns
#: it off.  There is no positive override -- a second default would be a second
#: thing to measure.
FLAG_ENV: Final = "CTF_BROWSER"

#: Rendered DOM returned per call.  A script-built page can be megabytes of
#: framework noise; the caller can raise this only by reading the file itself.
MAX_DOM: Final = 8000
#: Hard process ceiling.  A page whose load stalls must not eat the turn.
MAX_SECONDS: Final = 90.0


def wants_browser() -> tuple[bool, str]:
    """Whether ``browser_render`` should be installed.

    Returns:
        ``(installed, reason)``; ``reason`` is for diagnostics only.
    """
    raw = os.environ.get(FLAG_ENV, "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False, f"{FLAG_ENV}={raw}"
    return True, "default on"


def _override_words(override: str) -> list[str]:
    """Split ``CTF_CHROMIUM`` into a command line without eating backslashes.

    A bare path is the common case and must survive Windows separators, so it
    is tried before any splitting.  The multi-word form (``python3 fake.py``)
    exists for tests; ``posix=False`` on Windows keeps ``C:\\...`` intact, and
    surrounding quotes are stripped by hand.
    """
    candidate = Path(override)
    if candidate.is_file():
        return [str(candidate)]
    found = shutil.which(override)
    if found:
        return [found]
    try:
        words = shlex.split(override, posix=(os.name != "nt"))
    except ValueError:
        return []
    out: list[str] = []
    for word in words:
        if len(word) > 1 and word[0] == word[-1] and word[0] in "\"'":
            word = word[1:-1]
        if word:
            out.append(word)
    return out


def find_binary() -> list[str] | None:
    """Locate the browser command; ``None`` when the image has none.

    Resolution order: ``CTF_CHROMIUM`` (a path, or a command line such as
    ``python3 /tmp/fake.py`` -- the tests use that form), then the usual distro
    names on PATH.  Returning ``None`` rather than raising lets the tool answer
    with one honest line instead of a traceback the model would spend turns
    interpreting.
    """
    override = os.environ.get(BINARY_ENV, "").strip()
    if override:
        words = _override_words(override)
        if words:
            head = words[0]
            found = shutil.which(head) or (head if Path(head).is_file() else None)
            if found:
                return [found, *words[1:]]
    for name in BINARIES:
        found = shutil.which(name)
        if found:
            return [found]
    return None


def _budget_seconds(wait_ms: int) -> float:
    """Ceiling for the whole browser process, derived from the virtual budget.

    Separated so the timeout path has a test that does not spend 20 seconds:
    the tests patch this to 0.5 and use a binary that sleeps.
    """
    return min(MAX_SECONDS, max(20.0, wait_ms / 1000.0 * 2.0 + 20.0))


def _check_url(url: str) -> str:
    """Only ``http(s)`` targets: this tool is for the challenge, not the disk."""
    text = (url or "").strip()
    lowered = text.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    return text


def build_argv(
    binary: list[str],
    url: str,
    *,
    wait_ms: int,
    width: int,
    height: int,
    user_agent: str,
    profile: Path,
    screenshot: Path | None,
) -> list[str]:
    """The exact Chromium command line, as a list (unit-testable, no shell).

    ``--no-sandbox`` is not a convenience: the challenge container runs as an
    unprivileged user where Chromium's namespace sandbox cannot start, and a
    browser that refuses to boot is worse than one without its own sandbox --
    the container is already the boundary, and the page is untrusted *content*,
    not code we execute on the host.
    """
    argv = [
        *binary,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-extensions",
        "--disable-background-networking",
        "--no-first-run",
        "--no-default-browser-check",
        "--hide-scrollbars",
        f"--user-data-dir={profile}",
        f"--window-size={width},{height}",
        f"--virtual-time-budget={wait_ms}",
    ]
    if user_agent:
        argv.append(f"--user-agent={user_agent}")
    if screenshot is not None:
        argv.append(f"--screenshot={screenshot}")
    else:
        argv.append("--dump-dom")
    argv.append(url)
    return argv


def _title_of(dom: str) -> str:
    """First ``<title>`` in the DOM, trimmed; empty when there is none."""
    lowered = dom.lower()
    start = lowered.find("<title")
    if start < 0:
        return ""
    open_end = lowered.find(">", start)
    close = lowered.find("</title>", open_end + 1)
    if open_end < 0 or close < 0:
        return ""
    return " ".join(dom[open_end + 1 : close].split())[:200]


def browser_render(
    url: str,
    mode: str = "dom",
    wait_ms: int = 4000,
    width: int = 1280,
    height: int = 900,
    user_agent: str = "",
) -> str:
    """Render one page in headless Chromium and return what a browser sees.

    Use it when ``http_probe`` shows a shell rather than content: an empty
    root div, a single bundle script, a meta-refresh, or a body whose text is
    "You need JavaScript".  One call replaces "download the bundle and guess
    what it builds".

    Args:
        url: absolute ``http(s)`` URL, same target you already reached.
        mode: ``dom`` (default) returns the serialised DOM after scripts ran;
            ``shot`` saves a PNG and returns its path plus size, for canvas or
            image content that has no text form.
        wait_ms: how much virtual time scripts get before the snapshot.  Raise
            it when the page fetches data after load; 3000-8000 covers most.
        width: viewport width in CSS pixels (``shot`` mode matters most).
        height: viewport height in CSS pixels.
        user_agent: optional UA override, for pages that gate on mobile or bot
            signatures.

    Returns:
        One header line (mode, title, elapsed, size) followed by the DOM text
        or the screenshot path.  Failures are a single ``[browser] error:``
        line naming the phase, never a traceback.
    """
    started = time.monotonic()
    try:
        target = _check_url(url)
    except ValueError as exc:
        return f"[browser] error: {exc}"
    if mode not in {"dom", "shot"}:
        return "[browser] error: mode must be `dom` or `shot`"
    wait_ms = max(0, min(int(wait_ms), 60_000))
    width = max(200, min(int(width), 4000))
    height = max(200, min(int(height), 4000))

    binary = find_binary()
    if binary is None:
        return (
            "[browser] error: no chromium binary in this image; "
            "use http_probe/curl and read the bundles by hand"
        )

    shot_path: Path | None = None
    if mode == "shot":
        out_dir = Path(os.environ.get("CTF_BROWSER_DIR") or Path.cwd()) / "browser_shots"
        out_dir.mkdir(parents=True, exist_ok=True)
        shot_path = out_dir / f"shot-{int(time.time() * 1000)}.png"

    profile = Path(tempfile.mkdtemp(prefix="ctf-browser-"))
    budget = _budget_seconds(wait_ms)
    argv = build_argv(
        binary,
        target,
        wait_ms=wait_ms,
        width=width,
        height=height,
        user_agent=user_agent.strip(),
        profile=profile,
        screenshot=shot_path,
    )
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=budget,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        return (
            f"[browser] error: timeout after {elapsed:.1f}s "
            f"(page still loading? lower wait_ms or probe it with http_probe)"
        )
    except OSError as exc:
        return f"[browser] error: cannot start {Path(binary[0]).name}: {exc}"
    finally:
        shutil.rmtree(profile, ignore_errors=True)

    elapsed = time.monotonic() - started
    stderr_tail = " ".join((proc.stderr or "").split())[-300:]
    if mode == "shot":
        if shot_path is None or not shot_path.exists():
            return (
                f"[browser] error: no screenshot written (exit={proc.returncode}) "
                f"{stderr_tail}"
            )
        size = shot_path.stat().st_size
        return (
            f"[browser] mode=shot exit={proc.returncode} elapsed={elapsed:.1f}s "
            f"bytes={size} path={shot_path}"
        )

    dom = proc.stdout or ""
    if not dom.strip():
        return (
            f"[browser] error: empty DOM (exit={proc.returncode}) {stderr_tail}"
        )
    title = _title_of(dom)
    body = dom
    truncated = ""
    if len(body) > MAX_DOM:
        body = body[:MAX_DOM]
        truncated = f" truncated=1 (kept {MAX_DOM}/{len(dom)} chars)"
    header = (
        f"[browser] mode=dom exit={proc.returncode} elapsed={elapsed:.1f}s "
        f"chars={len(dom)} title={title or '-'}{truncated}"
    )
    return f"{header}\n{body}"


TOOLS: Final = (browser_render,)


def _as_async(func):
    """Run the blocking browser call off the agent event loop.

    ``function_tool(timeout=...)`` raises at registration for a sync handler;
    ``functools.wraps`` keeps the signature visible so the SDK still derives
    the JSON schema from it.
    """
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner


def register(register_fn=None) -> list[str]:
    """Register ``browser_render`` on every scan agent built afterwards."""
    from agents import function_tool

    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()
    wrapped = [function_tool(timeout=150)(_as_async(fn)) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]