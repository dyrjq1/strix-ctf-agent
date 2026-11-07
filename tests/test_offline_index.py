"""The web indexes must describe an offline image, not an installable toolchain.

Every command an index prints confidently is paid for by the model: it runs it,
gets "command not found" or a network error, and loses a turn. These three
indexes may *name* a missing tool in the offline-facts line, but must not
present one as a runnable prerequisite, and must not point at an outbound
callback service.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src" / "ctf_strix" / "skills_strix" / "ctf-web"
INDEXES = ["ctf-web.md", "sql-injection.md", "server-side-exec.md"]

# Anywhere in the file this is a recipe the image cannot follow.
BANNED = (
    "apt install",
    "apt-get install",
    "brew install",
    "go install",
    "git clone",
    "webhook.site",
    "pip install",
)

# Naming a missing tool is fine; printing an invocation of it is not.
BANNED_COMMANDS = ("ffuf -", "sqlmap -", "nuclei -", "flask-unsign --", "hashcat -")


def _read(name: str) -> str:
    return (WEB / name).read_text(encoding="utf-8")


def _numbered_steps(section: str) -> list[str]:
    return [line for line in section.splitlines() if re.match(r"^\d+\. ", line)]


@pytest.mark.parametrize("name", INDEXES)
def test_no_install_or_outbound_recipe(name: str) -> None:
    low = _read(name).lower()
    hits = [token for token in BANNED if token in low]
    hits += [token for token in BANNED_COMMANDS if token in low]
    assert not hits, f"{name} still tells the agent to run: {hits}"


def test_sqli_ladder_is_six_ordered_steps() -> None:
    body = _read("sql-injection.md")
    assert "order by" in body.lower()
    head = body.split("## Table of Contents", 1)[0]
    assert "## 阶梯" in head, "SQLi ladder must sit before the ToC"
    steps = _numbered_steps(head.split("## 阶梯", 1)[1])
    assert len(steps) == 6, steps
    order = ["闭合", "order by", "union select", "取库", "盲注", "waf"]
    positions = []
    for token in order:
        idx = next((i for i, s in enumerate(steps) if token in s.lower()), None)
        assert idx is not None, f"ladder lost step: {token}"
        positions.append(idx)
    assert positions == sorted(positions), positions


def test_upload_ladder_is_four_ordered_steps() -> None:
    body = _read("server-side-exec.md")
    _, after = body.split("## File Upload to RCE Techniques", 1)
    section = after.split("### ", 1)[0]
    steps = _numbered_steps(section)
    assert len(steps) == 4, steps
    order = ["extension blacklist", "content-type", "parser config", "path traversal"]
    positions = []
    for token in order:
        idx = next((i for i, s in enumerate(steps) if token in s.lower()), None)
        assert idx is not None, f"ladder lost step: {token}"
        positions.append(idx)
    assert positions == sorted(positions), positions
