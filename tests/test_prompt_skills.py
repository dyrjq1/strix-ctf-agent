"""The skill index is a *router*, not a catalogue.

Two regressions are guarded here, both found by reading the real prompt:

1. ``_CORE`` hard-coded twelve skill names next to a dynamically generated
   list.  The two drifted immediately: the hard-coded copy omitted
   ``ctf-agentic-ai`` and ``ctf-supply-chain`` -- exactly the AI-security
   directions this project is strongest in.  A list with two sources is a list
   that will be wrong.
2. The dynamic list published *every* registered skill, including the 65
   upstream strix ones (``vulnerabilities/*``, ``frameworks/*``,
   ``tooling/nuclei`` ...).  Those articles assume a tool chain that does not
   exist in this image, so loading them sends the model at absent binaries.
   ``ctf-similar-search`` is worse: it is built entirely on the Tavily API.

The fix is that the index lists only what this container can actually do, and
each line carries the "use when" condition taken from the skill's own
frontmatter -- so the model can *choose*, not just enumerate.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture(scope="module")
def block():
    from ctf_strix import prompt, skillpack

    skillpack.register()
    text = prompt.build({})
    if "## Skill indexes" not in text:
        pytest.skip("skill pack not staged in this environment")
    return text[text.index("## Skill indexes"):]


def test_index_lists_every_usable_ctf_direction(block):
    """Missing a direction is the worst failure: the model cannot load it."""
    for name in (
        "ctf-agentic-ai",
        "ctf-ai-infra",
        "ctf-ai-ml",
        "ctf-web",
        "ctf-pwn",
        "ctf-reverse",
        "ctf-crypto",
        "ctf-forensics",
        "ctf-malware",
        "ctf-misc",
        "ctf-osint",
        "ctf-supply-chain",
        "ctf-triage",
    ):
        assert f"`{name}/{name}`" in block, f"{name} missing from the index"


def test_index_excludes_upstream_skills_whose_toolchain_is_absent(block):
    for name in ("vulnerabilities/", "frameworks/", "tooling/", "technologies/",
                 "protocols/", "reconnaissance/", "cloud/", "custom/"):
        assert name not in block


def test_index_excludes_directions_that_cannot_work_offline(block):
    """``ctf-similar-search`` needs pip + api.tavily.com; both are denied."""
    assert "ctf-similar-search" not in block


def test_index_carries_a_when_to_use_hint(block):
    """A bare name list makes the model guess; a condition lets it route."""
    lines = [ln for ln in block.splitlines() if ln.startswith("- `")]
    assert lines
    with_hint = [ln for ln in lines if "\u2014" in ln]
    assert len(with_hint) >= len(lines) - 1
    for line in lines:
        assert len(line) < 260, f"hint too long to scan: {line[:80]}"


def test_prompt_does_not_duplicate_the_skill_list():
    """``_CORE`` must not name directions; it points at the index instead."""
    from ctf_strix import prompt

    core = prompt._CORE
    for name in ("ctf-web", "ctf-ai-ml", "ctf-triage"):
        assert name not in core, f"_CORE still hard-codes {name}"
    assert "load_skill" in core


def test_prompt_stays_small(block):
    """System prompt is paid on every request; keep it in the measured band."""
    from ctf_strix import prompt

    size = len(prompt.build({}))
    assert size < 6000, f"system prompt grew to {size} chars"
