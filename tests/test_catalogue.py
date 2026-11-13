"""The catalogue is the single source for registration *and* the prompt.

Three regressions are guarded here, all of them found by reading the code
rather than the docs (docs/27 C2/C3/C4):

1. A ``file`` or ``tcp`` challenge registered the four HTTP primitives anyway.
   3,829 chars of schema -- about 843 tokens -- on every call, for tools whose
   target does not exist, and in a ``file`` challenge that was 37.5% of the
   whole tool surface.
2. When a file challenge *did* get its six primitives, the prompt never named
   them: the Tools section was written by hand and listed only the web four.
   The capability existed and the model could not see it.
3. AI-security tools were registered whenever their rule data was on disk,
   while the eval harness defaulted them off -- so the measured tool surface was
   never the delivered one.

The fix is one table (``ctf_strix.catalogue``) read by both sides.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture(autouse=True)
def reset_prompt_state():
    """``prompt.activate`` is module state; tests must not leak it into others."""
    from ctf_strix import prompt

    before = prompt.active()
    yield
    prompt.activate(*before)


def test_catalogue_names_are_unique():
    from ctf_strix import catalogue

    names = [info.name for info in catalogue.CATALOGUE]
    assert len(names) == len(set(names))


def test_every_row_has_a_usable_prompt_line():
    from ctf_strix import catalogue

    for info in catalogue.CATALOGUE:
        assert info.summary, f"{info.name} has no prompt line"
        assert info.summary[0].islower(), f"{info.name} starts a new sentence"
        assert not info.summary.endswith("."), f"{info.name} has a trailing stop"
        assert len(info.summary) <= 180, f"{info.name} line is too long"


def test_file_and_tcp_do_not_get_web_tools():
    from ctf_strix import catalogue

    for kind in ("file", "tcp"):
        names = catalogue.registered_names(kind)
        for web_tool in ("http_probe", "route_map", "method_sweep", "path_variants"):
            assert web_tool not in names, f"{kind} challenge would pay for {web_tool}"


def test_file_and_tcp_are_told_about_their_own_primitives():
    """The gap that mattered: the tools existed and the prompt never named them."""
    from ctf_strix import catalogue

    file_names = catalogue.registered_names("file")
    for tool in ("file_triage", "decode_blob", "unpack_archive", "hexpeek", "elfpeek", "elffind"):
        assert tool in file_names, f"file challenge is not told about {tool}"

    tcp_names = catalogue.registered_names("tcp")
    assert {"tcp", "tcp_batch"} <= tcp_names


def test_prompt_block_lists_exactly_the_rows_for_that_kind():
    from ctf_strix import catalogue

    block = catalogue.prompt_block("file")
    for info in catalogue.for_kind("file"):
        assert f"`{info.name}`" in block
    for info in catalogue.CATALOGUE:
        if info not in catalogue.for_kind("file"):
            assert f"`{info.name}`" not in block


def test_groups_limit_the_block_to_what_actually_registered():
    """A failed installer must not leave a promise in the prompt."""
    from ctf_strix import catalogue

    block = catalogue.prompt_block("file", groups=("base",))
    assert "`exec_command`" in block
    assert "`file_triage`" not in block


def test_prompt_renders_the_block_for_the_active_kind():
    from ctf_strix import prompt

    prompt.activate("file", ("base", "file"))
    text = prompt.build({})
    assert "`decode_blob`" in text
    assert "`route_map`" not in text

    prompt.activate("web", ("base", "web"))
    text = prompt.build({})
    assert "`route_map`" in text
    assert "`decode_blob`" not in text


def test_turn_plan_follows_the_kind():
    """A file challenge must not be told to probe a root page or register."""
    from ctf_strix import prompt

    prompt.activate("file", ("base", "file"))
    file_text = prompt.build({})
    assert "`file_triage` the attachment once" in file_text
    assert "register and log in" not in file_text

    prompt.activate("web", ("base", "web"))
    web_text = prompt.build({})
    assert "register and log in" in web_text


def test_prompt_stays_inside_the_web_budget():
    """The delivered web prompt must not grow: it is the measured configuration.

    Measured with the skill index present, because that is what the container
    sends.  The index is process-global state, so it is registered explicitly
    here rather than inherited from whichever test ran first -- otherwise the
    same code measures 3.5k or 5.5k depending on collection order, and the
    guard silently stops guarding.
    """
    from ctf_strix import prompt, skillpack

    skillpack.register()
    prompt.activate("web", ("base", "web", "aisec"))
    size = len(prompt.build({}))
    # 5,005 before traffic memory (two tool lines, ~500 chars of prompt text);
    # 5,505 after; 6,558 after the shared hypothesis block (+1,030).  Headroom
    # is 72 chars so an unrelated one-line addition does not need a threshold
    # edit, but a tool section cannot slip in unnoticed.
    # L3b: 6,605 -> 6,680 (+75) for the stage-2 CLI names in the Environment
    # bullet and ctf-web Prerequisites (impacket/flask-unsign/RsaCtfTool).
    # 2026-11-13: one ceiling, two growth sources.  Measured split of the
    # delivered prompt: prose (core + tool sections + hypothesis) 4,984, skill
    # index 1,978, total 6,962.  The 2026-11-07 prompt.py, run in-process
    # against today's index, already measures 6,690 -- 10 chars of headroom --
    # so the overflow is the index, not B0's 13 chars of new prose.
    # ``_skills_block()`` has no cache, so this split is the same number the
    # test above measures, not an estimate.
    index = len(prompt._skills_block())
    prose = size - index
    # 2026-11-13 B-14（台账 §4.165）：收工序言教 ANSWER[<qid>]=<value>
    # 契约行（非 flag 题的唯一交付通道），prose 实测 4,984 -> 5151。阈值
    # 与实测的距离保持 ~100（一次单行改动的余量），工具段仍插不进来。
    assert prose < 5251, f"web prompt prose grew to {prose} chars (index {index})"
    assert index < 2050, f"skill index grew to {index} chars (prose {prose})"


def test_activate_defaults_to_web_so_unit_tests_keep_working():
    from ctf_strix import prompt

    prompt.activate("")
    assert prompt.active()[0] == "web"

def test_name_filter_never_drops_vendor_base_tools():
    """``exec_command`` is a vendor base tool, not an extra one.

    Filtering the Tools section by "names measured in ``_EXTRA_TOOLS``" dropped
    the shell from the prompt during this change's own smoke test: base tools
    are registered in a different list.  A prompt without ``exec_command`` is
    worse than one with an extra line.
    """
    from ctf_strix import catalogue

    measured = {"http_probe", "route_map", "method_sweep", "path_variants"}
    names = catalogue.registered_names("web", None, measured)
    assert {"exec_command", "load_skill", "think"} <= names
    assert "http_probe" in names

    empty = catalogue.registered_names("web", None, frozenset())
    assert {"exec_command", "load_skill", "think"} <= empty
    assert "http_probe" not in empty


def test_load_skill_line_points_at_registered_readers():
    """The Tools section is the other place a model learns how to open a subfile.

    ``read_file`` is not in the vendor registry; ``exec_command`` and
    ``view_image`` are.  Naming the ghost tool here is the same contract bug as
    naming it in the skill index.
    """
    from ctf_strix import catalogue

    line = catalogue.describe("load_skill")
    assert "read_file" not in line
    assert "exec_command" in line
    assert "view_image" in line


def test_tcp_gets_the_offline_cve_lookup_but_not_the_ai_probes():
    """A banner names the component; only the lookup can use it (AI-5).

    ``ai_fingerprint``/``ai_quick_scan`` probe an HTTP target and stay
    web-only.  ``ai_cve_lookup`` reads a bundled rule base and needs neither
    a target nor the network, so a tcp challenge can use it and a file
    challenge still cannot.
    """
    from ctf_strix import catalogue

    tcp_names = {info.name for info in catalogue.for_kind("tcp")}
    assert "ai_cve_lookup" in tcp_names
    assert "ai_fingerprint" not in tcp_names
    assert "ai_quick_scan" not in tcp_names

    file_names = {info.name for info in catalogue.for_kind("file")}
    assert "ai_cve_lookup" not in file_names
