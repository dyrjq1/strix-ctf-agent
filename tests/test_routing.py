"""The routing block is the only place that maps a signal to a skill.

These tests guard three failure modes that are invisible in a run log:

1. a route pointing at a skill that is not installed (the model calls
   ``load_skill`` and gets an error instead of an index);
2. the block growing past its budget (paid on every LLM call);
3. the four disciplines silently disappearing in a later edit.
"""

from __future__ import annotations

from ctf_strix import routing, skillpack


def test_every_route_target_is_a_real_category() -> None:
    categories = {c for c, _n, _p in skillpack.index_skills()}
    missing = {skill for _s, skill, _k, _f in routing.ROUTES if skill not in categories}
    assert missing == set(), f"routes point at missing skills: {sorted(missing)}"


def test_render_only_lists_registered_directions() -> None:
    text = routing.render(["ctf-web/ctf-web", "ctf-pwn/ctf-pwn"], "/skills")
    assert "`ctf-web/ctf-web`" in text
    assert "`ctf-pwn/ctf-pwn`" in text
    assert "`ctf-crypto/ctf-crypto`" not in text


def test_render_is_empty_without_names() -> None:
    assert routing.render([], "/skills") == ""


def test_render_fits_the_character_budget() -> None:
    """Both ref lengths the contract runs under must fit the 3000-char budget.

    ``/var/ctf/jail/skills`` is the 20-char jail path; ``ref_root()`` is the
    57-char local debug path. Only checking the short one hid a 33-char overrun.
    """
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    for ref in ("/var/ctf/jail/skills", skillpack.ref_root()):
        text = routing.render(names, ref)
        assert len(text) <= routing.MAX_CHARS, (
            f"{len(ref)}-char ref renders {len(text)} chars"
        )


def test_render_keeps_the_four_disciplines() -> None:
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    text = routing.render(names, "/skills")
    assert "Liveness gate" in text
    assert "falsifier" in text
    assert "40% and 70%" in text
    assert "do NOT `load_skill`" in text


def test_load_first_is_qualified_by_the_triage_escape_hatch() -> None:
    """L-2: "load it first" must not contradict prompt.py's skip-the-load exit.

    ``_TURNS_FILE`` says a triage output that already fixed the route skips the
    ``load_skill``. An unqualified imperative here would read as "always load",
    so the qualifier is part of the contract, not decoration.
    """
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    text = " ".join(routing.render(names, "/skills").split())
    assert "load it first unless the triage output already fixed the route" in text


def test_triage_line_dropped_when_not_registered() -> None:
    text = routing.render(["ctf-web/ctf-web"], "/skills")
    assert "ctf-triage/ctf-triage" not in text
    assert "exactly one" in text


def test_kind_filter_drops_directions_the_run_cannot_execute() -> None:
    """A web run has no file/tcp tools; offering pwn or forensics is a dead route."""
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    web = routing.render(names, "/skills", kind="web")
    assert "`ctf-web/ctf-web`" in web
    assert "`ctf-pwn/ctf-pwn`" not in web
    assert "`ctf-forensics/ctf-forensics`" not in web
    tcp = routing.render(names, "/skills", kind="tcp")
    assert "`ctf-pwn/ctf-pwn`" in tcp
    assert "`ctf-forensics/ctf-forensics`" not in tcp
    assert "`ctf-web/ctf-web`" not in tcp


def test_every_kind_keeps_at_least_three_directions() -> None:
    """A filter that leaves one row is not a router; it is a single forced route."""
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    for kind in ("web", "file", "tcp"):
        rows = [
            ln for ln in routing.render(names, "/skills", kind=kind).splitlines()
            if ln.startswith("- ")
        ]
        assert len(rows) >= 3, f"{kind} keeps only {len(rows)} rows"


def test_kind_none_keeps_the_full_table() -> None:
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    full = routing.render(names, "/skills")
    assert sum(1 for ln in full.splitlines() if ln.startswith("- ")) == len(routing.ROUTES)


def test_each_kind_stays_under_the_paid_budget() -> None:
    """A real run always knows its kind; this is the size it actually pays."""
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    for kind in ("web", "file", "tcp"):
        text = routing.render(names, skillpack.ref_root(), kind=kind)
        assert len(text) <= routing.KIND_MAX_CHARS, f"{kind} block is {len(text)} chars"


def test_bare_skill_names_are_not_rendered() -> None:
    """A bare category is ambiguous to strix's loader, so it must not be offered."""
    text = routing.render(["ctf-web"], "/skills")
    assert "-> `ctf-web`" not in text


def test_no_direction_registered_does_not_ask_for_a_direction_load() -> None:
    text = routing.render(["ctf-triage/ctf-triage"], "/skills")
    assert "No direction index is registered" in text
    assert "load one index" not in text


def test_full_table_covers_every_route_in_documented_order() -> None:
    """Rows follow ROUTES order, which the module documents as priority."""
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    rows = [
        ln for ln in routing.render(names, "/skills").splitlines() if ln.startswith("- ")
    ]
    assert len(rows) == len(routing.ROUTES)
    got = [r.split("-> `")[1].split("/")[0] for r in rows]
    assert got == [skill for _sig, skill, _k, _f in routing.ROUTES]


def test_unknown_kind_falls_back_to_the_full_table() -> None:
    """A misclassified run must still get directions, not an empty router."""
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    text = routing.render(names, "/skills", kind="unknown-kind")
    assert "`ctf-web/ctf-web`" in text
    assert "`ctf-pwn/ctf-pwn`" in text
