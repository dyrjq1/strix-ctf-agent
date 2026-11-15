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


def test_playbook_has_a_depth_exit_not_a_breadth_quota() -> None:
    """Breadth used to be the only quota; nothing asked to push one hit through.

    The "same response twice" stop is also gone: RT-3 showed a breadth scan
    answers every name differently, so that stop never fires. The replacement is
    the class count, which the runtime guard already maintains.
    """
    text = method_cards.PLAYBOOK
    assert "每轮最多" not in text, "breadth quota came back"
    assert "两次同响应" not in text, "same-response stop is the RT-3 failure"
    assert "3 深挖" in text
    assert "利用成功" in text, "no instruction to push a hit to exploitation"
    assert "交给 3" in text, "stage 2 must hand its best hit to stage 3"
    assert "新攻击类" in text


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


def test_tools_named_reads_only_backticked_tool_names() -> None:
    """The filter must not mistake prose or a shell flag for a tool."""
    assert method_cards.tools_named("先 `exec_command` 看头，再 `http_probe`。") == {
        "exec_command",
        "http_probe",
    }
    assert method_cards.tools_named("`Flag` 与 `--help` 都不是工具名") == frozenset()
    assert method_cards.tools_named("没有反引号") == frozenset()


def test_select_drops_a_card_whose_tool_is_not_installed() -> None:
    """A card naming a tool this run did not install costs a turn, not a hint.

    The first card tells the model to start with ``ai_quick_scan``; on a run
    where the AI gate was off that name does not resolve.
    """
    every = [key for card in method_cards.CARDS for key in card.keys]
    installed = set(method_cards.tools_named(method_cards.render(every, "web")))
    assert "ai_quick_scan" in installed  # sanity: the table does name it

    cards = method_cards.select(["agentic_ai"], "web", available=installed)
    assert cards
    without = method_cards.select(
        ["agentic_ai"], "web", available=installed - {"ai_quick_scan"}
    )
    assert all("ai_quick_scan" not in card.text for card in without)


def test_select_with_available_none_keeps_the_whole_table() -> None:
    """Callers that cannot see the registry get exactly the old behaviour."""
    every = [key for card in method_cards.CARDS for key in card.keys]
    baseline = method_cards.select(every, "web")
    assert method_cards.select(every, "web", available=None) == baseline
    assert len(baseline) == method_cards.MAX_CARDS


def test_cve_tag_shape_selects_the_adaptation_card() -> None:
    """Platform tags arrive as ``cve_2021_3129``; matching by shape, not by list,
    is what keeps the card alive for CVE challenges tagged later."""
    for tags in (["historical_cve"], ["cve_2099_12345"], ["cve_2017_9805"]):
        cards = method_cards.select(tags, "web")
        assert cards and "已知 CVE" in cards[0].text, tags


def test_cve_shape_does_not_match_unrelated_tags() -> None:
    for tags in (["cve"], ["cve_2021"], ["xcve_2021_3129"], ["cve_2021_312"]):
        assert all("已知 CVE" not in card.text for card in method_cards.select(tags, "web")), tags


def test_cve_card_outranks_stack_cards() -> None:
    """The block truncates from the tail: a CVE run must keep the CVE card."""
    got = [card.text for card in method_cards.select(["cve_2018_18778", "php", "laravel"], "web")]
    assert got and "已知 CVE" in got[0]


def test_named_cve_card_suppresses_the_generic_one() -> None:
    """A card for that exact CVE already carries the variant; the generic card
    would only spend budget re-asking where the entry point is."""
    got = [card.text for card in method_cards.select(["cve_2021_44228", "log4j"], "web")]
    assert got and "Log4Shell" in got[0]
    assert all("已知 CVE" not in text for text in got)


def test_cve_adaptation_section_exists_in_the_pack() -> None:
    """The card points at "ctf-web 的 CVE 适配节"; a missing section is a dead end."""
    from ctf_strix.skillpack import PACK_DIR

    text = (PACK_DIR / "ctf-web" / "cves.md").read_text(encoding="utf-8")
    assert "Adaptation procedure" in text
    assert "controlled observation" in text


def test_auth_flow_card_fires_on_flow_tags() -> None:
    for tags in (
        ["predictable_code"],
        ["authentication_failures", "2fa_bypass"],
        ["account_merge"],
    ):
        cards = method_cards.select(tags, "web")
        assert any("认证流程" in card.text for card in cards), tags


def test_auth_flow_card_outranks_the_object_swap_card() -> None:
    """Both fire on an account-merge tag; the flow check must come first."""
    got = [card.text for card in method_cards.select(["account_merge"], "web")]
    assert len(got) >= 2
    assert "认证流程" in got[0]


def test_auth_flow_procedure_exists_in_the_pack() -> None:
    from ctf_strix.skillpack import PACK_DIR

    text = (PACK_DIR / "ctf-web" / "auth-and-access.md").read_text(encoding="utf-8")
    assert "Procedure: multi-step auth flows" in text
    assert "state machine" in text


def test_select_keeps_every_card_when_all_its_tools_are_installed() -> None:
    """The filter is a subset test: a complete registry changes nothing."""
    every = [key for card in method_cards.CARDS for key in card.keys]
    installed = set(method_cards.tools_named(method_cards.render(every, "web")))
    assert method_cards.select(every, "web", available=installed) == (
        method_cards.select(every, "web")
    )
