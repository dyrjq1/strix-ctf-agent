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


def test_every_registered_tool_is_described_in_the_catalogue():
    """No tool may be registered without a line the model can read.

    This is the check that would have caught the file primitives: they were
    registered (so they cost schema in every request) and absent from the Tools
    section (so the model never knew they existed).
    """
    from ctf_strix import catalogue, file_triage, nonweb
    from ctf_strix.aisec import tools as aisec_tools

    declared = {info.name for info in catalogue.CATALOGUE}
    registered: set[str] = set()
    for fn in file_triage.TOOLS:
        registered.add(fn.__name__)
    for fn in (*nonweb.FILE_TOOLS, *nonweb.TCP_TOOLS):
        registered.add(fn.__name__)
    for fn in aisec_tools.TOOLS:
        registered.add(fn.__name__)

    missing = registered - declared
    assert not missing, f"registered but never described: {sorted(missing)}"


def test_catalogue_does_not_promise_tools_nobody_registers():
    from ctf_strix import catalogue, file_triage, nonweb
    from ctf_strix.aisec import tools as aisec_tools

    from ctf_strix import discovery, http_probe, variants

    registered = {fn.__name__ for fn in file_triage.TOOLS}
    registered |= {fn.__name__ for fn in (*nonweb.FILE_TOOLS, *nonweb.TCP_TOOLS)}
    registered |= {fn.__name__ for fn in aisec_tools.TOOLS}
    # The web primitives' public names differ from their function names in one
    # case (``method_sweep`` is built by the discovery module's register()).
    registered |= {"http_probe", "route_map", "method_sweep", "path_variants"}
    # The base four are vendor tools; they are asserted separately below.
    base = {"exec_command", "load_skill", "think"}

    promised = {info.name for info in catalogue.CATALOGUE}
    assert promised - base <= registered, promised - base - registered


def test_next_commands_only_use_binaries_the_image_installs():
    """``_NEXT`` is the first thing a file challenge reads; every command counts."""
    from ctf_strix import file_triage

    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    installed = set()
    for token in dockerfile.split():
        if token.islower() and "-" not in token and len(token) > 2:
            installed.add(token)

    # Binaries the image really has, checked against the apt line.
    # ``binutils`` ships readelf/objdump/strings as one package; ``file`` and
    # ``xxd`` have their own.  Assert against the packages, not the binaries, so
    # this stays true if the image swaps one for an equivalent.
    assert "binutils" in dockerfile
    assert "xxd" in dockerfile
    assert "unzip" in dockerfile

    banned = ("checksec", "zsteg", "exiftool", "tshark", "tcpdump", "binwalk")
    for family, hint in file_triage._NEXT.items():
        for name in banned:
            assert name not in hint, f"_NEXT[{family}] still suggests missing {name}"