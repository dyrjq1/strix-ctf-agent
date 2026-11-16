"""``browser_render``: one external binary, two modes, no driver stack.

The tests never need Chromium: ``CTF_CHROMIUM`` accepts a command line, so a
small Python stand-in plays the browser and the argv written by
``build_argv`` is asserted directly.  What is *not* faked is the binary being
missing -- that is the failure the image shipped with for months, and it has to
answer in one line instead of a traceback.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ctf_strix import browser

DOM = (
    "<html><head><title>Sign in</title></head>"
    "<body><div id='app'>FLAG rendered by script</div></body></html>"
)

FAKE_SOURCE = '''\
import os
import sys
import time

args = sys.argv[1:]
mode = os.environ.get("FAKE_BROWSER_MODE", "dom")
if mode == "sleep":
    time.sleep(30)
shot = next((a.split("=", 1)[1] for a in args if a.startswith("--screenshot=")), None)
if shot:
    with open(shot, "wb") as fh:
        fh.write(b"\\x89PNG\\r\\n\\x1a\\n" + b"0" * 32)
elif mode == "empty":
    pass
elif mode == "big":
    sys.stdout.write("<title>big</title>" + "x" * 20000)
else:
    sys.stdout.write(os.environ.get("FAKE_BROWSER_DOM", "<html><title>t</title></html>"))
'''


@pytest.fixture
def fake_browser(monkeypatch, tmp_path):
    """Point ``CTF_CHROMIUM`` at a Python script that impersonates the binary."""
    script = tmp_path / "fake_chromium.py"
    script.write_text(FAKE_SOURCE, encoding="utf-8")
    monkeypatch.setenv(browser.BINARY_ENV, f"{sys.executable} {script}")
    monkeypatch.delenv(browser.FLAG_ENV, raising=False)
    return script


def test_dom_mode_returns_the_rendered_document(fake_browser, monkeypatch):
    monkeypatch.setenv("FAKE_BROWSER_DOM", DOM)
    text = browser.browser_render("http://target.local/", wait_ms=1000)

    assert text.startswith("[browser] mode=dom")
    assert "title=Sign in" in text, "the <title> is extracted into the header"
    assert "FLAG rendered by script" in text, "script output must reach the model"


def test_shot_mode_writes_a_png_and_names_it(fake_browser, tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BROWSER_DIR", str(tmp_path / "shots"))
    text = browser.browser_render("https://target.local/", mode="shot", wait_ms=500)

    assert text.startswith("[browser] mode=shot")
    assert "bytes=40" in text
    path = Path(text.rsplit("path=", 1)[1].strip())
    assert path.exists() and path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_dom_is_capped_and_says_so(fake_browser, monkeypatch):
    monkeypatch.setenv("FAKE_BROWSER_MODE", "big")
    text = browser.browser_render("http://target.local/", wait_ms=100)

    assert "truncated=1" in text
    assert len(text) < browser.MAX_DOM + 400
    full = len("<title>big</title>") + 20000
    assert f"chars={full}" in text
    assert f"kept {browser.MAX_DOM}/{full}" in text


def test_missing_binary_is_one_honest_line(monkeypatch):
    """The shipped-for-months state: package installed, no browser binary."""
    monkeypatch.setattr(browser, "find_binary", lambda: None)
    text = browser.browser_render("http://target.local/")

    assert text.startswith("[browser] error:")
    assert "no chromium binary" in text
    assert "http_probe" in text, "the model needs the fallback it still has"


def test_non_http_targets_are_refused_before_any_process(monkeypatch):
    monkeypatch.setattr(
        browser, "find_binary", lambda: pytest.fail("must not launch a browser")
    )
    for bad in ("file:///etc/passwd", "ftp://target/x", "", "javascript:alert(1)"):
        text = browser.browser_render(bad)
        assert text.startswith("[browser] error:"), bad
        assert "http://" in text


def test_unknown_mode_is_refused(fake_browser):
    text = browser.browser_render("http://target.local/", mode="pdf")
    assert text.startswith("[browser] error:")
    assert "dom" in text and "shot" in text


def test_empty_dom_reports_exit_instead_of_pretending(fake_browser, monkeypatch):
    monkeypatch.setenv("FAKE_BROWSER_MODE", "empty")
    text = browser.browser_render("http://target.local/", wait_ms=100)
    assert text.startswith("[browser] error: empty DOM")


def test_timeout_is_bounded(fake_browser, monkeypatch):
    monkeypatch.setattr(browser, "_budget_seconds", lambda _wait: 0.5)
    monkeypatch.setenv("FAKE_BROWSER_MODE", "sleep")
    text = browser.browser_render("http://target.local/", wait_ms=100)
    assert text.startswith("[browser] error: timeout")


def test_argv_has_the_flags_that_make_headless_work():
    argv = browser.build_argv(
        ["chromium"],
        "http://target.local/",
        wait_ms=2500,
        width=1024,
        height=768,
        user_agent="Mozilla/5.0 test",
        profile=Path("/tmp/profile"),
        screenshot=None,
    )
    assert argv[0] == "chromium"
    assert "--headless=new" in argv
    assert "--no-sandbox" in argv, "the container cannot start a namespace sandbox"
    assert "--virtual-time-budget=2500" in argv
    assert "--window-size=1024,768" in argv
    assert "--user-agent=Mozilla/5.0 test" in argv
    assert "--dump-dom" in argv
    assert argv[-1] == "http://target.local/", "url comes last, nothing after it"


def test_shot_mode_swaps_dump_dom_for_a_screenshot_path(tmp_path):
    shot = tmp_path / "out.png"
    argv = browser.build_argv(
        ["chromium"],
        "http://target.local/",
        wait_ms=1000,
        width=800,
        height=600,
        user_agent="",
        profile=Path("/tmp/profile"),
        screenshot=shot,
    )
    assert "--dump-dom" not in argv
    assert f"--screenshot={shot}" in argv
    assert not any(a.startswith("--user-agent=") for a in argv)


def test_profile_directory_is_removed_after_the_run(fake_browser, tmp_path, monkeypatch):
    """A leftover profile is state leaking between attempts on one machine."""
    seen: list[Path] = []
    real_mkdtemp = browser.tempfile.mkdtemp

    def spy(*args, **kwargs):
        path = Path(real_mkdtemp(*args, **kwargs))
        seen.append(path)
        return str(path)

    monkeypatch.setattr(browser.tempfile, "mkdtemp", spy)
    monkeypatch.setenv("FAKE_BROWSER_DOM", DOM)
    browser.browser_render("http://target.local/", wait_ms=100)
    assert seen and not seen[0].exists()


def test_ablation_switch_only_accepts_off_values(monkeypatch):
    for value in ("0", "false", "no", "off", "OFF", " 0 "):
        monkeypatch.setenv(browser.FLAG_ENV, value)
        assert browser.wants_browser()[0] is False, value
    for value in ("", "1", "yes", "on"):
        monkeypatch.setenv(browser.FLAG_ENV, value)
        assert browser.wants_browser()[0] is True, value


def test_override_env_survives_windows_separators(tmp_path, monkeypatch):
    """``C:\\...\\python.exe C:\\...\\fake.py`` must not lose backslashes."""
    script = tmp_path / "fake_chromium.py"
    script.write_text("print('x')\n", encoding="utf-8")
    monkeypatch.setenv(browser.BINARY_ENV, f'"{sys.executable}" "{script}"')
    found = browser.find_binary()
    assert found is not None
    assert found[0] == sys.executable
    assert found[-1] == str(script)


def test_tool_is_registered_under_the_catalogue_name():
    """The row and the function must not drift; the prompt reads the row."""
    from ctf_strix import catalogue

    names = [info.name for info in catalogue.CATALOGUE]
    assert "browser_render" in names
    assert browser.TOOLS[0].__name__ == "browser_render"
    info = next(i for i in catalogue.CATALOGUE if i.name == "browser_render")
    assert "web" in info.kinds and "file" not in info.kinds