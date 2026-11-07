"""Environment claims in the prompt and the web index must agree.

The agent learns what the offline image can do from two places: the ``_CORE``
environment block in ``prompt.py`` and the ``Prerequisites`` facts in
``ctf-web/ctf-web.md``. If one says a tool exists and the other says it does
not, the model has to guess -- and guessing burns turns. This module parses both
sources plus the build-time toolchain probe and asserts they cannot contradict
each other.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROMPT = ROOT / "src" / "ctf_strix" / "prompt.py"
WEB_INDEX = ROOT / "src" / "ctf_strix" / "skills_strix" / "ctf-web" / "ctf-web.md"
TOOLCHAIN = ROOT / "docker" / "check_toolchain.sh"

#: Tools the dispatcher promised to add; the probe must name exactly these.
#: Lower-cased because ``_toolchain_tools`` normalises the probe keys.
ATTACK_TOOLS = frozenset(
    {"nmap", "sqlmap", "ffuf", "smbclient", "impacket", "flask-unsign", "rsactftool"}
)


def _norm(token: str) -> str:
    return token.strip().strip("`").strip().lower()


def _prompt_environment() -> str:
    text = PROMPT.read_text(encoding="utf-8")
    head, sep, tail = text.partition("## Environment (verified facts, not guesses)")
    assert sep, "prompt.py lost its verified-facts environment section"
    return tail.split("{tools}", 1)[0]


def _prompt_claims() -> tuple[set[str], set[str]]:
    env = _prompt_environment()
    no_match = re.search(r"^- No ([^;]+);", env, re.MULTILINE)
    assert no_match, "prompt.py environment must keep a 'No <tools>;' absent-list"
    unavailable = {_norm(t) for t in re.split(r"[/,\s]+", no_match.group(1)) if t}
    available: set[str] = set()
    for match in re.finditer(r"([A-Za-z0-9][A-Za-z0-9/_.-]*) are installed", env):
        available |= {_norm(t) for t in match.group(1).split("/") if t}
    return available, unavailable


def _backticked(text: str) -> set[str]:
    return {_norm(t) for t in re.findall(r"`([^`]+)`", text)}


def _web_claims() -> tuple[set[str], set[str]]:
    text = WEB_INDEX.read_text(encoding="utf-8")
    _, sep, tail = text.partition("## Prerequisites")
    assert sep, "ctf-web.md lost its Prerequisites section"
    block = tail.split("\n## ", 1)[0]
    available: set[str] = set()
    unavailable: set[str] = set()
    for match in re.finditer(r"([^;.\n]*?)\s+are installed", block):
        available |= _backticked(match.group(1))
    for match in re.finditer(r"([^;.\n]*?)\s+are\s+\*\*not available\*\*", block):
        unavailable |= _backticked(match.group(1))
    return available, unavailable


def _toolchain_tools() -> set[str]:
    text = TOOLCHAIN.read_text(encoding="utf-8")
    return {m.group(1).lower() for m in re.finditer(r'"([A-Za-z0-9_.-]+)": \(', text)}


def test_prompt_claims_are_self_consistent() -> None:
    available, unavailable = _prompt_claims()
    both = available & unavailable
    assert not both, f"prompt.py says both present and absent: {sorted(both)}"


def test_web_claims_are_self_consistent() -> None:
    available, unavailable = _web_claims()
    both = available & unavailable
    assert not both, f"ctf-web.md says both present and absent: {sorted(both)}"


def test_prompt_and_web_claims_agree() -> None:
    p_available, p_absent = _prompt_claims()
    w_available, w_absent = _web_claims()
    for tool in (p_available | p_absent) & (w_available | w_absent):
        assert (tool in p_available) == (tool in w_available), (
            f"{tool}: prompt.py available={tool in p_available} but "
            f"ctf-web.md available={tool in w_available}"
        )


def test_available_tools_are_probed_at_build_time() -> None:
    probed = _toolchain_tools()
    p_available, _ = _prompt_claims()
    w_available, _ = _web_claims()
    missing = (p_available | w_available) - probed
    assert not missing, f"claimed available but not version-probed: {sorted(missing)}"


def test_build_probes_every_attack_tool() -> None:
    probed = _toolchain_tools()
    assert ATTACK_TOOLS <= probed, sorted(ATTACK_TOOLS - probed)


def test_unavailable_tools_are_not_probed() -> None:
    probed = _toolchain_tools()
    _, p_absent = _prompt_claims()
    _, w_absent = _web_claims()
    leaked = (p_absent | w_absent) & probed
    assert not leaked, f"declared absent but probed as installed: {sorted(leaked)}"


#: Stage-2 CLI tools and the Dockerfile snippet that installs each one.
STAGE2_INSTALLS = {
    "impacket": "impacket-0.13.1-py3-none-any.whl",
    "flask-unsign": "flask-unsign==",
    "rsactftool": "/opt/RsaCtfTool",
}


def test_stage2_tools_have_install_lines() -> None:
    """A prompt claim is only true if the build actually installs the tool."""
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    available, _ = _prompt_claims()
    for tool, marker in STAGE2_INSTALLS.items():
        assert tool in available, f"{tool} is not claimed as installed in prompt.py"
        assert marker in dockerfile, f"{tool}: build install marker missing ({marker!r})"
