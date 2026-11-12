"""Method cards: fixed table, set-intersection matching, zero injection surface.

What breaks silently without these tests: a card naming a tool we do not ship
(the model calls it and gets nothing), a table that outgrows its per-call
budget, and a ``render`` that echoes platform tags back into the prompt.
"""

from __future__ import annotations

import re

import pytest

from ctf_strix import catalogue, method_cards


def test_matching_card_is_returned() -> None:
    cards = method_cards.select(["sqli"], "web")
    assert cards and any("注入" in card.text for card in cards)


def test_priority_follows_table_order() -> None:
    tags = ["sqli", "java", "agentic_ai"]
    got = [card.text for card in method_cards.select(tags, "web")]
    order = [card.text for card in method_cards.CARDS]
    assert got == sorted(got, key=order.index)
    assert "Agent 题" in got[0], "AI cards must outrank web cards"


def test_max_cards_truncates() -> None:
    every = [key for card in method_cards.CARDS for key in card.keys]
    assert len(method_cards.select(every, "web")) == method_cards.MAX_CARDS


def test_no_match_renders_empty() -> None:
    assert method_cards.render(["no_such_tag"], "web") == ""
    assert method_cards.render([], "web") == ""
    assert method_cards.render(None, "web") == ""


@pytest.mark.parametrize("kind", ["file", "tcp", "checker", "engagement", None])
def test_non_web_kind_renders_nothing(kind: str | None) -> None:
    assert method_cards.render(["sqli", "agentic_ai"], kind) == ""


def test_same_card_matched_by_many_keys_appears_once() -> None:
    cards = method_cards.select(["sqli", "injection", "nosql_injection"], "web")
    assert len(cards) == 1
    assert {"sqli", "injection", "nosql_injection"} <= cards[0].keys


def test_rendered_text_never_echoes_tags() -> None:
    sentinel = "zzsentinel_tag_9f3"
    text = method_cards.render(["sqli", sentinel], "web")
    assert text
    assert sentinel not in text.lower()


def test_every_backticked_name_is_a_registered_tool() -> None:
    registered = {info.name for info in catalogue.CATALOGUE}
    bad: set[str] = set()
    for blob in [card.text for card in method_cards.CARDS] + [method_cards.PLAYBOOK]:
        bad |= {name for name in re.findall(r"`([^`]+)`", blob) if name not in registered}
    assert bad == set(), f"cards name tools that are not registered: {sorted(bad)}"


def test_every_card_names_at_least_one_tool() -> None:
    registered = {info.name for info in catalogue.CATALOGUE}
    for index, card in enumerate(method_cards.CARDS, start=1):
        named = {n for n in re.findall(r"`([a-z0-9_]+)`", card.text) if n in registered}
        assert named, f"card #{index} names no tool: {card.text}"


def test_playbook_has_five_stages_and_fits() -> None:
    text = method_cards.PLAYBOOK
    assert len(text) <= method_cards.PLAYBOOK_MAX_CHARS
    for stage in "01234":
        assert re.search(rf"^{stage} ", text, re.M), f"stage {stage} missing"


def test_worst_and_typical_render_stay_under_budget() -> None:
    every = [key for card in method_cards.CARDS for key in card.keys]
    assert len(method_cards.render(every, "web")) <= method_cards.MAX_CHARS
    typical = method_cards.render(["sqli", "php"], "web")
    assert 0 < len(typical) <= method_cards.MAX_CHARS


def test_prompt_hint_carries_cards_for_web_only() -> None:
    from ctf_strix import skillpack

    assert "[Method cards]" in skillpack.prompt_hint([], kind="web", tags=["sqli"])
    assert skillpack.prompt_hint([], kind="file", tags=["sqli"]) == ""


def test_tags_of_ignores_name_and_description() -> None:
    task = {
        "challenge": {"name": "ZZNAME", "description": "ZZDESC", "tags": ["SQLi"]},
        "tags": ["Weak_Password"],
    }
    assert method_cards.tags_of(task) == ["SQLi", "Weak_Password"]
    assert method_cards.tags_of(None) == []

def test_every_playbook_stage_has_two_to_four_lines() -> None:
    lines = method_cards.PLAYBOOK.splitlines()
    for stage in "01234":
        start = next(i for i, line in enumerate(lines) if line.startswith(stage + " "))
        count = 1
        for line in lines[start + 1 :]:
            if not line.startswith("  "):
                break
            count += 1
        assert 2 <= count <= 4, f"stage {stage} has {count} lines"


def test_render_contains_no_ip_or_flag_shape() -> None:
    from ctf_strix.flag_extract import CANDIDATE_RE

    every = [key for card in method_cards.CARDS for key in card.keys]
    text = method_cards.render(every, "web")
    assert text
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    assert CANDIDATE_RE.findall(text) == []


def test_all_keys_are_lowercase_observed_identifiers() -> None:
    for card in method_cards.CARDS:
        for key in card.keys:
            assert re.fullmatch(r"[a-z0-9_-]+", key), key
