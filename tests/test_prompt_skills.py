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
    """No hard-coded direction list anywhere in the rendered prompt.

    ``_CORE`` is a template now (Tools and turns are filled per kind), so the
    assertion has to run on rendered output: a hard-coded list added to the
    template would still be a second source of truth.
    """
    from ctf_strix import prompt

    text = prompt.build({})
    # Everything from "## Skill indexes" on is the generated index; nothing
    # before it may name a direction, and nothing after it may name one twice.
    head, _, index = text.partition("## Skill indexes")
    for name in ("ctf-web", "ctf-ai-ml", "ctf-triage"):
        assert name not in head, f"{name} is hard-coded above the index"
        # Each index line is ``- `ctf-x/ctf-x` -- when to use it``, so the
        # category name legitimately appears twice *on that one line*.
        entries = [ln for ln in index.splitlines() if ln.startswith("- `")]
        assert sum(name in ln for ln in entries) <= 1, f"{name} is listed twice"
    assert "load_skill" in text


def test_prompt_stays_small(block):
    """System prompt is paid on every request; keep it in the measured band."""
    from ctf_strix import prompt

    size = len(prompt.build({}))
    # 5,186 before hypothesis discipline; 6,216 after (+1,030 exactly).
    # Headroom from the old threshold is preserved, so a one-line edit fits but
    # an unmeasured section does not.
    assert size < 7030, f"system prompt grew to {size} chars"


_KINDS = ("web", "file", "tcp")


def _build_by_kind() -> dict[str, str]:
    """Render one prompt per challenge kind, then restore module state."""
    from ctf_strix import prompt

    before = prompt.active()
    texts: dict[str, str] = {}
    try:
        for kind in _KINDS:
            prompt.activate(kind, ("base", kind))
            texts[kind] = prompt.build({})
    finally:
        prompt.activate(*before)
    return texts


def test_hypothesis_block_requires_falsification_in_every_kind() -> None:
    """Every kind must ask for at least one action that could disprove the bet."""
    texts = _build_by_kind()
    for kind, text in texts.items():
        assert "Try to falsify it" in text, f"{kind} prompt lacks falsification"


def test_hypothesis_block_requires_explicit_closure_in_every_kind() -> None:
    """Repeated same-shape failure must close the hypothesis, not extend it."""
    texts = _build_by_kind()
    for kind, text in texts.items():
        assert "Close it explicitly" in text, f"{kind} prompt lacks closure"


def test_hypothesis_block_requires_a_mechanism_switch_in_every_kind() -> None:
    """After closure the next step must move to a different mechanism."""
    texts = _build_by_kind()
    for kind, text in texts.items():
        assert "Change mechanism" in text, f"{kind} prompt lacks a switch"


def test_hypothesis_block_is_within_its_character_budget() -> None:
    """The shared block is paid on every request; 600-1,500 chars is the deal."""
    from ctf_strix import prompt

    size = len(prompt._HYPOTHESIS)
    assert 600 <= size <= 1500, f"hypothesis block is {size} chars"


def test_file_turn_plan_runs_the_triage_table_before_loading_a_skill() -> None:
    """The file branch must point at the tool's own table, not at a skill.

    The decision table ships inside ``unpack_archive``'s return value; telling the
    model to load a discipline index first adds a round trip that carries no
    information about the file it is already holding.
    """
    from ctf_strix import prompt

    text = prompt._TURNS_FILE
    assert "`next:`" in text
    assert "1 then 2 then 3" in text
    assert "last resort" in " ".join(text.split())
    assert "load_skill" not in text


def test_skill_index_teaches_registered_read_channels_only() -> None:
    """The index must not name a tool the registry never installs.

    ``read_file`` was never registered: Shell exposes ``exec_command`` and
    Filesystem exposes ``view_image``/``apply_patch``.  A model that follows
    the index toward ``read_file`` spends a turn on a tool that does not exist.
    """
    from ctf_strix import prompt

    text = prompt._skills_block()
    if not text:
        pytest.skip("skill pack not staged in this environment")
    assert "read_file" not in text
    assert "exec_command" in text
    assert "view_image" in text
    assert "`cat`" in text or "cat" in text


def test_skill_index_sends_images_to_view_image_not_the_shell() -> None:
    """Pixels go through ``view_image``; ``cat`` would print bytes, not a picture."""
    from ctf_strix import prompt

    text = prompt._skills_block()
    if not text:
        pytest.skip("skill pack not staged in this environment")
    sentence = " ".join(text.split("\n\n", 2)[1].split())
    assert "subfiles: `exec_command`" in sentence
    assert "images `view_image`" in sentence
    assert "images `exec_command`" not in sentence


def test_skill_index_names_both_read_channels_in_one_sentence() -> None:
    """A text-only sentence leaves the image case to guesswork.

    The index is the only place the model learns how to open a subfile, so the
    two registered channels must be in the same instruction: text via
    ``exec_command`` (``cat``/``sed -n``), images via ``view_image``.
    """
    from ctf_strix import prompt

    text = prompt._skills_block()
    if not text:
        pytest.skip("skill pack not staged in this environment")
    sentence = " ".join(text.split("\n\n", 2)[1].split())
    assert "exec_command" in sentence
    assert "view_image" in sentence
    assert "load_skill" in sentence
