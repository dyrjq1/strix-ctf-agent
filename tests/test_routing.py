"""The routing block is the only place that maps a signal to a skill.

These tests guard three failure modes that are invisible in a run log:

1. a route pointing at a skill that is not installed (the model calls
   ``load_skill`` and gets an error instead of an index);
2. the block growing past its paid budget (the numbers live *here*, not in
   ``routing``: ``render`` never truncates, on purpose -- a silently dropped
   route is a dead direction, and the budget is the test's assertion, not a
   runtime cap).  The runtime defense for the joined ``user_instructions``
   block lives one layer up: ``skillpack.prompt_hint`` caps its exit at
   ``HINT_MAX_CHARS`` (line boundary + visible mark) -- the same budget,
   guarded dev-time here and at runtime there;
3. the four disciplines silently disappearing in a later edit.
"""

from __future__ import annotations

from ctf_strix import routing, skillpack

#: Paid size ceilings, asserted here rather than enforced in ``render``.
#:
#: These used to be ``routing.MAX_CHARS`` / ``routing.KIND_MAX_CHARS``, which
#: nothing in the runtime ever read -- a constant that looks like a cap but
#: trims nothing is worse than no constant: it invites someone to "rely" on it.
#: Truncation stays off deliberately; the assertion fails instead of the route
#: silently disappearing from the prompt.
_MAX_CHARS = 3000
_KIND_MAX_CHARS = 2400


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
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    text = routing.render(names, "/var/ctf/jail/skills")
    assert len(text) <= _MAX_CHARS, f"routing block is {len(text)} chars"


def test_render_keeps_the_four_disciplines() -> None:
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    text = routing.render(names, "/skills")
    assert "Liveness gate" in text
    assert "falsifier" in text
    assert "40% and 70%" in text
    assert "do NOT `load_skill`" in text


def test_render_pushes_the_best_hit_to_exploitation() -> None:
    """Depth needs an entry: one enumeration pass, then exploit the best hit.

    The old step 3 stopped on "two identical responses", a condition a breadth
    scan never meets; the class count replaces it.
    """
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    text = routing.render(names, "/skills")
    assert "a second sweep is not progress" in text
    assert "add no new attack class" in text
    assert "Two identical responses" not in text


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
        assert len(text) <= _KIND_MAX_CHARS, f"{kind} block is {len(text)} chars"


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
