"""The direction indexes must describe an offline image, not an installable toolchain.

Every command an index prints confidently is paid for by the model: it runs it,
gets "command not found" or a network error, and loses a turn. An index may
*name* a missing tool in its offline-facts line, but must not present one as a
runnable prerequisite, and must not point at an outbound callback service.

``INDEXES`` mirrors what ``ctf_strix.skillpack.index_skills`` actually
registers; ``test_indexes_cover_every_registered_index`` keeps the two in sync
so a new category cannot slip past the assertions below.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "src" / "ctf_strix" / "skills_strix"
WEB = SKILLS / "ctf-web"

#: Every direction index, as ``<category>/<category>.md``.
INDEXES = [
    "ctf-agentic-ai/ctf-agentic-ai.md",
    "ctf-ai-infra/ctf-ai-infra.md",
    "ctf-ai-ml/ctf-ai-ml.md",
    "ctf-crypto/ctf-crypto.md",
    "ctf-forensics/ctf-forensics.md",
    "ctf-malware/ctf-malware.md",
    "ctf-misc/ctf-misc.md",
    "ctf-osint/ctf-osint.md",
    "ctf-pwn/ctf-pwn.md",
    "ctf-reverse/ctf-reverse.md",
    "ctf-supply-chain/ctf-supply-chain.md",
    "ctf-triage/ctf-triage.md",
    "ctf-web/ctf-web.md",
]

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
    """Read a file in ``ctf-web/`` (kept for the ladder tests)."""
    return (WEB / name).read_text(encoding="utf-8")


def _read_index(rel: str) -> str:
    return (SKILLS / rel).read_text(encoding="utf-8")


def _numbered_steps(section: str) -> list[str]:
    return [line for line in section.splitlines() if re.match(r"^\d+\. ", line)]


def test_indexes_cover_every_registered_index() -> None:
    from ctf_strix.skillpack import index_skills

    registered = {f"{category}/{path.name}" for category, _, path in index_skills(SKILLS)}
    assert set(INDEXES) == registered


@pytest.mark.parametrize("name", INDEXES)
def test_no_install_or_outbound_recipe(name: str) -> None:
    low = _read_index(name).lower()
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


def test_sqli_ladder_has_exit_criteria() -> None:
    body = _read("sql-injection.md")
    head = body.split("## Table of Contents", 1)[0]
    steps = _numbered_steps(head.split("## 阶梯", 1)[1])
    missing = [s for s in steps if "出口" not in s]
    assert not missing, f"steps without an exit criterion: {missing}"


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


def test_upload_ladder_has_exit_criteria() -> None:
    body = _read("server-side-exec.md")
    _, after = body.split("## File Upload to RCE Techniques", 1)
    steps = _numbered_steps(after.split("### ", 1)[0])
    missing = [s for s in steps if "出口" not in s]
    assert not missing, f"steps without an exit criterion: {missing}"


def test_subfile_banned_census() -> None:
    """Report-only: how many BANNED recipes survive in the subfiles.

    This is a census, not an assertion -- subfiles are out of scope for the
    index sweep, and the numbers are recorded in the ledger so the next round
    can decide whether to spend on them.
    """
    indexed = set(INDEXES)
    rows: list[tuple[str, int, list[str]]] = []
    for path in sorted(SKILLS.glob("*/*.md")):
        rel = f"{path.parent.name}/{path.name}"
        if rel in indexed:
            continue
        low = path.read_text(encoding="utf-8").lower()
        tokens = [t for t in BANNED + BANNED_COMMANDS if t in low]
        count = sum(low.count(t) for t in tokens)
        if count:
            rows.append((rel, count, tokens))
    rows.sort(key=lambda row: (-row[1], row[0]))
    total = sum(row[1] for row in rows)
    print(f"\n[subfile BANNED census] {total} hits across {len(rows)} subfiles")
    for rel, count, tokens in rows:
        print(f"  {count:3d}  {rel}  {tokens}")
