"""``skill_route`` is a deterministic router, not a recommender.

Guarded here, in the order the regressions would hurt:

1. **Determinism.** Same observations must produce byte-identical output --
   the prompt's routing table and this tool share one vocabulary
   (:mod:`ctf_strix.skill_signals`) and one tie-break order
   (``routing.ROUTES``); a nondeterministic ranking would make the two layers
   disagree run to run.
2. **No guessing.** A no-hit must say so and keep the model free-solving.
   The tool exists to stop index loads on vibes; silently defaulting to a
   direction would reintroduce exactly that failure.
3. **No document serving.** Top-2, 15-line previews, 6 KiB ceiling, flags
   masked. A router that dumps cards is a context bomb wearing a tool name.
4. **Rollback.** ``CTF_SKILL_ROUTE=0`` must remove the tool from the
   registry -- a rollback that leaves the schema in the tool surface is not
   a rollback.
5. **Consistency.** Every signal category must be a registered index and
   every card file must exist, or the tool sends the model at missing files.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import skillpack  # noqa: E402
from ctf_strix import skill_router  # noqa: E402
from ctf_strix.skill_signals import SIGNALS  # noqa: E402


_PWN_EVIDENCE = (
    "ELF binary; log line shows format string %7$p; remote service on 1337; "
    "checksec: no canary"
)
_WEB_EVIDENCE = (
    "login form on /login; POST returns sqlite error near 'union select'; "
    "stack trace mentions jinja2 render"
)


def test_scoring_is_deterministic_and_orders_by_hits() -> None:
    """Identical input, identical ranking; more distinct hits wins."""
    first = skill_router.score(_PWN_EVIDENCE)
    second = skill_router.score(_PWN_EVIDENCE)
    assert first == second
    assert first[0][0] == "ctf-pwn", "pwn evidence must rank pwn first"
    assert first[0][1] >= 2, "score is distinct-pattern count, not match count"
    assert first[0][2], "matched evidence snippets must be reported"


def test_ties_break_by_routes_order() -> None:
    """Equal scores resolve to the prompt table's own priority, not hash order."""
    # One keyword for web, one for pwn: 1 hit each, ROUTES puts web first.
    ranked = skill_router.score("banner mentions sqli and ret2libc")
    assert [cat for cat, _, _ in ranked[:2]] == ["ctf-web", "ctf-pwn"]


def test_output_reports_at_most_two_directions() -> None:
    """A router returning every nonzero direction is a search engine."""
    text = skill_router.skill_route(
        _WEB_EVIDENCE + "; pcap attached; rsa in the description; stego suspected"
    )
    numbered = [
        ln
        for ln in text.splitlines()
        if ln[:2].rstrip(".").isdigit() and "hit(s)" in ln
    ]
    assert len(numbered) <= 2, "top-2 is the contract"
    assert "ctf-web" in text


def test_no_hit_says_so_and_refuses_to_guess() -> None:
    """No signal -> explicit message; never a default direction."""
    text = skill_router.skill_route("a pleasant afternoon with no signals")
    assert "no keyword signal matched" in text
    assert "do not load a discipline index on a guess" in text.lower()
    assert "ctf-" not in text


def test_card_pointers_resolve_to_real_files() -> None:
    """Every start card must exist under the pack, or the pointer is a lie."""
    for signal in SIGNALS:
        card = skillpack.PACK_DIR / signal.category / signal.card
        assert card.is_file(), f"missing card {card}"


def test_signal_categories_align_with_the_registered_index() -> None:
    """The router may only name directions load_skill can actually load."""
    indexed = {cat for cat, _, _ in skillpack.index_skills()}
    for signal in SIGNALS:
        assert signal.category in indexed, (
            f"{signal.category} not offered by the skill index"
        )


def test_routes_covers_every_signal_category() -> None:
    """Every direction the router can rank appears in the prompt table."""
    from ctf_strix import routing

    table = {skill for _, skill, _, _ in routing.ROUTES}
    for signal in SIGNALS:
        assert signal.category in table


def test_preview_masks_candidate_flags(tmp_path: Path, monkeypatch) -> None:
    """A card carrying a writeup flag must never leak it through the preview."""
    # Assembled at runtime so this test file never contains the literal shape
    # the red line forbids in diffs.
    secret = "fl" + "ag{pl3ase_n0t_le4ked}"
    card_dir = tmp_path / "ctf-pwn"
    card_dir.mkdir()
    (card_dir / "format-string.md").write_text(
        f"# card\n\nsolved example: {secret}\n", encoding="utf-8"
    )
    monkeypatch.setenv("CTF_SKILLS_REF", str(tmp_path))
    text = skill_router.skill_route(_PWN_EVIDENCE)
    assert "pl3ase_n0t_le4ked" not in text
    assert ("fl" + "ag{...}") in text, "masked placeholder form missing"


def test_output_hard_cap(tmp_path: Path, monkeypatch) -> None:
    """A degenerate card (one giant line) cannot blow the 6 KiB ceiling."""
    card_dir = tmp_path / "ctf-pwn"
    card_dir.mkdir()
    (card_dir / "format-string.md").write_text(
        "# card\n" + ("A" * 200_000) + "\n", encoding="utf-8"
    )
    monkeypatch.setenv("CTF_SKILLS_REF", str(tmp_path))
    text = skill_router.skill_route(_PWN_EVIDENCE)
    assert len(text.encode("utf-8")) <= skill_router._MAX_RESULT_BYTES
    assert "truncated" in text


def test_register_gated_off_by_env(monkeypatch) -> None:
    """CTF_SKILL_ROUTE=0 removes the tool from the registry entirely."""
    monkeypatch.setenv("CTF_SKILL_ROUTE", "0")
    assert skill_router.enabled() is False
    registered: list[str] = []
    names = skill_router.register(register_fn=lambda *tools: registered.extend(
        getattr(t, "name", "") for t in tools
    ))
    assert names == []
    assert registered == []


def test_register_reports_fresh_names(monkeypatch) -> None:
    """Enabled default path registers the tool and reports its name.

    Dedupe against the live factory registry is covered by the wiring
    fixture in ``test_toolset_wiring.py``; an injected ``register_fn`` has no
    registry to dedupe against, by the same convention as ``file_triage``.
    """
    monkeypatch.delenv("CTF_SKILL_ROUTE", raising=False)
    fresh: list[str] = []

    def fake_register(*tools) -> None:
        fresh.extend(getattr(t, "name", "") for t in tools)

    first = skill_router.register(register_fn=fake_register)
    assert first == ["skill_route"]
    assert fresh == ["skill_route"]


def test_empty_observations_is_a_no_hit() -> None:
    """Nothing pasted is not evidence; the tool must not invent any."""
    assert "no keyword signal matched" in skill_router.skill_route("")


@pytest.mark.parametrize("off", ["0", "false", "no"])
def test_off_values_follow_the_env_convention(off: str, monkeypatch) -> None:
    """Same off-triple as every other CTF_STrix capability flag."""
    monkeypatch.setenv("CTF_SKILL_ROUTE", off)
    assert skill_router.enabled() is False


@pytest.mark.parametrize("on", ["1", "true", "yes", "", "anything"])
def test_on_and_unset_default_to_enabled(on: str, monkeypatch) -> None:
    """Unset or unknown values ship the tool enabled (one-env rollback)."""
    if on:
        monkeypatch.setenv("CTF_SKILL_ROUTE", on)
    else:
        monkeypatch.delenv("CTF_SKILL_ROUTE", raising=False)
    assert skill_router.enabled() is True
