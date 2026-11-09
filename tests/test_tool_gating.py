"""Wiring invariants for the 2026-11-02 tool gating.

The failures these lock down all had the same shape: something was registered
for one kind, described for another, and measured under a third configuration.
Each test therefore asserts a *relationship*, not a literal list -- a list would
just be the fourth copy that drifts.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _task(description: str = "", tags: list[str] | None = None) -> dict:
    return {"challenge": {"description": description, "tags": tags or []}}


def test_aisec_off_by_default_on_a_plain_web_task(monkeypatch):
    from ctf_strix import capabilities

    monkeypatch.delenv("CTF_AISEC", raising=False)
    enabled, reason = capabilities.wants_aisec("web", _task("A vault with a login page"))
    assert enabled is False
    assert "no AI-security signal" in reason


def test_aisec_turns_on_for_agentic_metadata(monkeypatch):
    from ctf_strix import capabilities

    monkeypatch.delenv("CTF_AISEC", raising=False)
    enabled, reason = capabilities.wants_aisec("web", _task(tags=["agentic_ai", "prompt_injection"]))
    assert enabled is True
    assert "metadata" in reason


def test_aisec_is_never_offered_without_a_web_surface(monkeypatch):
    """The rules are about HTTP endpoints; a file challenge cannot use them."""
    from ctf_strix import capabilities

    monkeypatch.delenv("CTF_AISEC", raising=False)
    enabled, _ = capabilities.wants_aisec("file", _task(tags=["agentic_ai"]))
    assert enabled is False


@pytest.mark.parametrize("value,expected", [("1", True), ("true", True), ("0", False), ("no", False)])
def test_env_override_wins_over_metadata(monkeypatch, value, expected):
    from ctf_strix import capabilities

    monkeypatch.setenv("CTF_AISEC", value)
    enabled, _ = capabilities.wants_aisec("file", _task(tags=["agentic_ai"]))
    assert enabled is expected


def test_harness_and_entrypoint_share_the_gate():
    """A second copy of the rule is exactly how the three drifts happened."""
    entry = (ROOT / "src" / "ctf_strix" / "agent.py").read_text(encoding="utf-8")
    harness = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
    assert "wants_aisec(" in entry
    assert "wants_aisec(" in harness
    # Neither may hand-roll its own env check again.  Compare the *code* lines
    # only: both files explain the old drift in comments, and a comment cannot
    # re-introduce it.
    def code_lines(text: str) -> str:
        return "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        )

    for source in (entry, harness):
        assert 'os.environ.get("CTF_AISEC"' not in code_lines(source)


def test_harness_registers_web_primitives_only_for_web_kinds():
    harness = (ROOT / "scripts" / "run_strix_ctf.py").read_text(encoding="utf-8")
    index = harness.index("install_web_capabilities()")
    window = harness[max(0, index - 700):index]
    assert "target_kind" in window, "web primitives are registered unconditionally again"


def test_entrypoint_registers_web_primitives_only_for_web_kinds():
    entry = (ROOT / "src" / "ctf_strix" / "agent.py").read_text(encoding="utf-8")
    index = entry.index("install_web_capabilities()")
    window = entry[max(0, index - 700):index]
    assert 'kind in ("web", "checker", "engagement")' in window


def test_aisec_hint_requires_a_whole_token(monkeypatch, metadata, expected, why):
    """Substring matching turned three schemas on for a plain storage challenge.

    Measured on the platform catalog: ``rag`` matched ``sto-rag-e`` (C2O-ALIST),
    and ``llm`` matched the OSINT tag ``llm_reasoning`` (CTFARENA-037, a payroll
    kiosk with no model anywhere).  A hint has to stand on its own.
    """
    from ctf_strix import capabilities

    monkeypatch.delenv("CTF_AISEC", raising=False)
    enabled, _ = capabilities.wants_aisec("web", {"challenge": metadata})
    assert enabled is expected, why
