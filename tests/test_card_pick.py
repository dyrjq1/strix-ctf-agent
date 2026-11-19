"""Round-5 self-selection: the menu, the picker, and its per-attempt reset.

What breaks silently without these tests: the picker registered under the
wrong tool name (or with an empty schema, so the model cannot pass ``ids``), a
menu that fires on every call, a pick that ignores the size cap, and rotation
that never marks a used card because the state file path was wrong.
"""

from __future__ import annotations

import json

import pytest

from ctf_strix import card_pick, card_menu, method_cards


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CTF_CARDS_STATE", raising=False)
    card_pick.set_pool([])
    yield
    card_pick.set_pool([])


def _web_cards() -> list:
    return method_cards.pool("web", "", ["sqli"])


def test_menu_is_empty_without_a_pool() -> None:
    assert card_pick.menu() == ""
    assert card_pick.install(register_fn=lambda *a: pytest.fail("registered")) == []


def test_menu_lists_every_candidate_and_how_to_pick() -> None:
    pool = _web_cards()
    card_pick.set_pool(pool)
    text = card_pick.menu()
    assert "method_cards_pick" in text
    for card in pool:
        assert card.cid in text
    assert card_pick.pool_size() == len(pool)


def test_pick_returns_the_bodies_and_ignores_unknown_ids() -> None:
    pool = _web_cards()[:2]
    card_pick.set_pool(pool)
    text = card_pick._pick([pool[0].cid, "no_such_card"])
    assert pool[0].text in text
    assert "no_such_card" in text, "an unknown id must be reported, not silently eaten"
    assert card_pick.chosen() == [pool[0].cid]


def test_pick_is_capped_at_three_cards() -> None:
    pool = method_cards.pool("web", "", ["linux"])[:5]
    assert len(pool) >= 4
    card_pick.set_pool(pool)
    text = card_pick._pick([card.cid for card in pool])
    injected = [card for card in pool if card.text in text]
    assert len(injected) == card_pick.MAX_PICK
    assert len(card_pick.chosen()) == card_pick.MAX_PICK


def test_an_empty_pick_means_keep_the_start_cards() -> None:
    card_pick.set_pool(_web_cards())
    text = card_pick._pick([])
    assert "未选卡" in text
    assert card_pick.chosen() == []


def test_used_cards_are_remembered_across_attempts(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CTF_CARDS_STATE", str(tmp_path))
    pool = _web_cards()
    card_pick.set_pool(pool, "DEMO-001")
    card_pick._pick([pool[0].cid])
    assert json.loads((tmp_path / "DEMO-001.json").read_text(encoding="utf-8")) == {
        "used": [pool[0].cid]
    }

    # A new attempt: nothing chosen yet, but the menu still knows what was used.
    card_pick.reset_attempt()
    card_pick.set_pool(pool, "DEMO-001")
    assert card_pick.chosen() == []
    assert f"- {pool[0].cid} *" in card_pick.menu()


def test_reset_attempt_clears_the_choice_but_not_the_pool() -> None:
    card_pick.set_pool(_web_cards())
    card_pick._pick([_web_cards()[0].cid])
    card_pick.reset_attempt()
    assert card_pick.chosen() == []
    assert card_pick.pool_size() > 0


def test_the_registered_tool_is_named_and_typed_for_the_menu() -> None:
    """The menu tells the model to call ``method_cards_pick`` by name."""
    captured: list = []
    card_pick.set_pool(_web_cards())
    names = card_pick.install(register_fn=lambda *tools: captured.extend(tools))
    assert names == ["method_cards_pick"]
    assert captured[0].name == "method_cards_pick"
    schema = getattr(captured[0], "params_json_schema", None) or {}
    assert "ids" in (schema.get("properties") or {}), "the tool cannot take ids"


def test_the_menu_guard_fires_once_after_the_fifth_call() -> None:
    card_pick.set_pool(_web_cards())
    guard = card_menu.CardMenuGuard(after=5)
    hints = [guard.observe() for _ in range(4)]
    assert hints == [None, None, None, None]
    fired = guard.observe()
    assert fired and "method_cards_pick" in fired
    assert guard.observe() is None, "the menu must not repeat on every call"


def test_the_guard_stays_quiet_when_a_card_was_already_picked() -> None:
    pool = _web_cards()
    card_pick.set_pool(pool)
    card_pick._pick([pool[0].cid])
    guard = card_menu.CardMenuGuard(after=1)
    assert guard.observe() is None


def test_the_guard_stays_quiet_without_a_pool() -> None:
    guard = card_menu.CardMenuGuard(after=1)
    assert guard.observe() is None


def test_install_can_be_switched_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTF_CARD_MENU", "0")
    monkeypatch.setattr(card_menu, "_GUARD", None)
    assert card_menu.install() is None