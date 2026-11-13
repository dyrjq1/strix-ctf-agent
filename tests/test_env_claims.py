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


def _bullets(env: str) -> list[str]:
    """Split the environment block into top-level bullets, keeping continuations."""
    blocks: list[str] = []
    for line in env.splitlines():
        if line.startswith("- "):
            blocks.append(line)
        elif line.startswith("  ") and blocks:
            blocks[-1] += "\n" + line
    return blocks


#: A comma-separated list of tool names, nothing else.  Keeping this strict is
#: the point: the previous lax ``^- No ([^;]+);`` accepted the prose line
#: ``- No internet: anything else **cannot be installed**;`` and silently turned
#: the absent-list assertion green with junk tokens.
_TOOL_LIST = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:, ?[A-Za-z0-9][A-Za-z0-9_.-]*)*"
)


def _prompt_claims() -> tuple[set[str], set[str]]:
    env = _prompt_environment()
    bullets = _bullets(env)

    cli = next((b for b in bullets if b.startswith("- CLIs:")), None)
    assert cli, "prompt.py environment must list its CLIs in a '- CLIs: `a` `b`' bullet"
    available = _backticked(cli)

    no_lines = [b for b in bullets if b.startswith("- No ")]
    assert len(no_lines) == 1, (
        "prompt.py must have exactly one '- No <tools>;' absent-list bullet "
        f"(found {len(no_lines)}); anything else starting with '- No ' is prose "
        "that would shadow it"
    )
    raw = no_lines[0][len("- No "):].split(";", 1)[0].strip()
    assert _TOOL_LIST.fullmatch(raw), (
        "the absent-list must be comma-separated tool names, not a sentence; "
        f"got {raw!r}"
    )
    unavailable = {_norm(t) for t in raw.split(",")}
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


#: Prompt names -> probe labels.  The probe key is a label, not always the CLI
#: name (radare2's binary is ``r2``), and the prompt legitimately speaks in CLI
#: names.  ``test_file_triage`` maps the other way for the same reason.
PROBE_ALIASES = {"r2": "radare2"}


def test_available_tools_are_probed_at_build_time() -> None:
    probed = _toolchain_tools()
    p_available, _ = _prompt_claims()
    w_available, _ = _web_claims()
    claimed = {PROBE_ALIASES.get(tool, tool) for tool in p_available | w_available}
    missing = claimed - probed
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


#: The tools whose presence used to be restated in the goal preamble.  The
#: preamble is prepended to the *user* goal text (``agent._read_goal``), so a
#: second copy there competes with ``## Environment`` instead of reinforcing it.
INVENTORY_TOOLS = ("nmap", "sqlmap", "ffuf", "gobuster", "r2")


def _word_hits(text: str, tool: str) -> int:
    return len(re.findall(rf"(?<![A-Za-z0-9_.-]){re.escape(tool)}(?![A-Za-z0-9_.-])", text))


def test_preamble_states_no_tool_inventory() -> None:
    """The preamble must point at ``## Environment``, not repeat its contents.

    Naming a tool here is what produced the original contradiction: the review
    snapshot said ``usually NOT installed`` while ``prompt.py`` said listed
    CLIs are installed.  Deleting the names is the fix; adding a new one
    re-opens the same failure mode one edit later.
    """
    preamble = (ROOT / "config" / "goal_preamble.txt").read_text(encoding="utf-8")
    named = [tool for tool in INVENTORY_TOOLS if _word_hits(preamble, tool)]
    assert not named, (
        "goal_preamble.txt restates the tool inventory: "
        f"{named}; keep the facts in prompt.py's '## Environment' only"
    )


def test_goal_texts_do_not_hedge_on_installed_tools() -> None:
    """No goal file may say a listed CLI 'may be' missing or 'happens to be' there."""
    goals = sorted((ROOT / "config").glob("goal_*.txt")) + [ROOT / "config" / "ctf_goal.txt",
                                                           ROOT / "config" / "ctf_goal_engagement.txt"]
    for path in goals:
        text = path.read_text(encoding="utf-8")
        assert "happens to be installed" not in text, f"{path.name} hedges on a listed CLI"
        assert "usually NOT installed" not in text, f"{path.name} contradicts ## Environment"


def test_attack_tool_names_live_only_on_the_system_side() -> None:
    """``nmap``/``sqlmap``/``ffuf`` appear once in the prompt, on the system side.

    The acceptance for this fix: no assembled user-side goal (every kind, since
    the preamble is prepended to all of them) carries any of the three, and the
    fixed system core carries each exactly once -- its CLI list.
    """
    from ctf_strix.agent import GOAL_FILES, _read_goal
    from ctf_strix.prompt import _CORE

    for kind in GOAL_FILES:
        user = _read_goal(kind)
        for tool in ("nmap", "sqlmap", "ffuf"):
            assert _word_hits(user, tool) == 0, f"{tool} leaked into the {kind} goal"
    for tool in ("nmap", "sqlmap", "ffuf"):
        assert _word_hits(_CORE, tool) == 1, f"{tool} must appear exactly once in _CORE"
