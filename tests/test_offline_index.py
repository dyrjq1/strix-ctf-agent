"""The direction indexes must describe an offline image, not an installable toolchain.

Every command an index prints confidently is paid for by the model: it runs it,
gets "command not found" or a network error, and loses a turn. An index may
*name* a missing tool in its offline-facts line, but must not present one as a
runnable prerequisite, and must not point at an outbound callback service.

``INDEXES`` mirrors what ``ctf_strix.skillpack.index_skills`` actually
registers; ``test_indexes_cover_every_registered_index`` keeps the two in sync
so a new category cannot slip past the assertions below.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "src" / "ctf_strix" / "skills_strix"
WEB = SKILLS / "ctf-web"

#: Every direction index, as ``<category>/<category>.md``.
INDEXES = [
    "ctf-agentic-ai/ctf-agentic-ai.md",
    "ctf-ai-infra/ctf-ai-infra.md",
    "ctf-ai-ml/ctf-ai-ml.md",
    "ctf-crypto/ctf-crypto.md",
    "ctf-forensics/ctf-forensics.md",
    "ctf-malware/ctf-malware.md",
    "ctf-misc/ctf-misc.md",
    "ctf-osint/ctf-osint.md",
    "ctf-pwn/ctf-pwn.md",
    "ctf-reverse/ctf-reverse.md",
    "ctf-supply-chain/ctf-supply-chain.md",
    "ctf-triage/ctf-triage.md",
    "ctf-web/ctf-web.md",
]

# Anywhere in the file this is a recipe the image cannot follow.
BANNED = (
    "apt install",
    "apt-get install",
    "brew install",
    "go install",
    "git clone",
    "webhook.site",
    "pip install",
    "gem install",
)

#: Command-shaped invocations an index may print, and the tool each one runs.
#: An index may only invoke tools the image installs (see ``docker/Dockerfile``
#: and ``docker/check_toolchain.sh``); naming a missing tool in prose stays fine.
COMMAND_FORMS = {
    "ffuf -": "ffuf",
    "sqlmap -": "sqlmap",
    "nmap -": "nmap",
    "smbclient -": "smbclient",
    "nuclei -": "nuclei",
    "flask-unsign --": "flask-unsign",
    "hashcat -": "hashcat",
    "impacket ": "impacket",
    "secretsdump.py ": "impacket",
    "wmiexec.py ": "impacket",
    "RsaCtfTool ": "RsaCtfTool",
}

#: Tools the offline image installs; pinned to the build-time probe by
#: ``test_image_tools_match_build_probe``.
IMAGE_TOOLS = frozenset(
    {"nmap", "sqlmap", "ffuf", "smbclient", "impacket", "flask-unsign", "RsaCtfTool"}
)

#: An invocation of anything outside ``IMAGE_TOOLS`` is still a wasted turn.
BANNED_COMMANDS = tuple(
    form for form, tool in COMMAND_FORMS.items() if tool not in IMAGE_TOOLS
)

#: Every registered skill pack's ``SKILL.md``. ``skillpack`` stages only the
#: direction index (``<pack>/<pack>.md``) for registration; strix serves the
#: body via ``load_skill`` (frontmatter stripped) and the ``description`` in
#: the skills listing; ``SKILL.md`` is
#: maintainer documentation, kept honest here so the two surfaces cannot
#: drift apart. Unlike a direction index, a pack body may name tools the
#: image lacks in deferred one-liners, so only ``BANNED`` (not
#: ``BANNED_COMMANDS``) governs it.
SKILL_PACKS = sorted(p.parent.name for p in SKILLS.glob("*/SKILL.md"))


def _read(name: str) -> str:
    """Read a file in ``ctf-web/`` (kept for the ladder tests)."""
    return (WEB / name).read_text(encoding="utf-8")


def _read_index(rel: str) -> str:
    return (SKILLS / rel).read_text(encoding="utf-8")


def _numbered_steps(section: str) -> list[str]:
    return [line for line in section.splitlines() if re.match(r"^\d+\. ", line)]


def test_indexes_cover_every_registered_index() -> None:
    from ctf_strix.skillpack import index_skills

    registered = {f"{category}/{path.name}" for category, _, path in index_skills(SKILLS)}
    assert set(INDEXES) == registered


@pytest.mark.parametrize("name", INDEXES)
def test_no_install_or_outbound_recipe(name: str) -> None:
    low = _read_index(name).lower()
    hits = [token for token in BANNED if token in low]
    hits += [token for token in BANNED_COMMANDS if token in low]
    assert not hits, f"{name} still tells the agent to run: {hits}"


def _read_skill_pack(pack: str) -> str:
    return (SKILLS / pack / "SKILL.md").read_text(encoding="utf-8")


def _frontmatter(text: str) -> str:
    """The frontmatter block between the leading ``---`` fences.

    A regex (not ``split("---")``) so a literal ``---`` inside a
    description cannot truncate the block early.
    """
    m = re.match(r"^---\r?\n(.*?)\r?\n---", text, re.DOTALL)
    assert m, "file has no (or malformed) frontmatter block at the top"
    return m.group(1)


@pytest.mark.parametrize("pack", SKILL_PACKS)
def test_skill_pack_has_no_install_recipe(pack: str) -> None:
    low = _read_skill_pack(pack).lower()
    hits = [token for token in BANNED if token in low]
    assert not hits, f"{pack}/SKILL.md still tells the agent to run: {hits}"


@pytest.mark.parametrize("pack", SKILL_PACKS)
def test_skill_pack_frontmatter_is_offline(pack: str) -> None:
    """The pack docs must not promise tools the offline task cannot answer.

    The router loads only the direction index, not this file; keeping
    ``SKILL.md`` honest anyway stops the two surfaces from drifting apart.
    """
    text = _read_skill_pack(pack)
    head = _frontmatter(text)
    assert "internet access" not in head.lower(), (
        f"{pack}/SKILL.md frontmatter still promises internet access"
    )
    m = re.search(r"^allowed-tools:(.*)$", head, re.MULTILINE)
    assert m, f"{pack}/SKILL.md frontmatter has no allowed-tools line"
    granted = m.group(1).lower()
    assert "webfetch" not in granted and "websearch" not in granted, (
        f"{pack}/SKILL.md still grants web tools: {m.group(1).strip()}"
    )


@pytest.mark.parametrize("name", INDEXES)
def test_index_frontmatter_is_offline(name: str) -> None:
    """The direction index is what ``skillpack.index_skills`` registers.
    Of its frontmatter, only ``description`` reaches the model (the strix
    skills listing); ``load_skill`` serves the body with frontmatter
    stripped, and ``compatibility``/``allowed-tools`` are consumed by no
    code -- kept offline-honest anyway so the docs cannot drift back
    into granting tools the runtime lacks.
    """
    head = _frontmatter(_read_index(name))
    low = head.lower()
    assert "internet access" not in low, (
        f"{name} frontmatter still promises internet access"
    )
    assert "install on demand" not in low, (
        f"{name} frontmatter still offers on-demand installs"
    )
    m = re.search(r"^allowed-tools:(.*)$", head, re.MULTILINE)
    # An index with no allowed-tools line (ctf-agentic-ai,
    # ctf-supply-chain) grants nothing, which is offline-safe, so
    # absence passes by design (unlike the SKILL.md variant above).
    if m:
        granted = m.group(1).lower()
        assert "webfetch" not in granted and "websearch" not in granted, (
            f"{name} still grants web tools: {m.group(1).strip()}"
        )


def test_skill_pack_dirs_are_registered_or_excluded() -> None:
    """A pack dir with a ``SKILL.md`` must be a registered index or the
    one known exclusion; otherwise its docs rot unseen while the corpus
    moves on.
    """
    registered = {rel.split("/")[0] for rel in INDEXES}
    assert set(SKILL_PACKS) - registered == {"ctf-similar-search"}


def test_command_forms_are_installed_in_image() -> None:
    """Positive direction: every invocation an index prints names a real tool."""
    for name in INDEXES:
        low = _read_index(name).lower()
        invoked = {tool for form, tool in COMMAND_FORMS.items() if form in low}
        unknown = invoked - IMAGE_TOOLS
        assert not unknown, (
            f"{name} invokes tools the image does not install: {sorted(unknown)}"
        )


def test_image_tools_match_build_probe() -> None:
    """``IMAGE_TOOLS`` must equal the binaries ``check_toolchain.sh`` probes."""
    script = (ROOT / "docker" / "check_toolchain.sh").read_text(encoding="utf-8")
    probed = set(re.findall(r'"([A-Za-z0-9_.-]+)": \(', script))
    assert IMAGE_TOOLS == probed, (
        f"IMAGE_TOOLS={sorted(IMAGE_TOOLS)} but build probes {sorted(probed)}"
    )


def test_sqli_ladder_is_six_ordered_steps() -> None:
    body = _read("sql-injection.md")
    assert "order by" in body.lower()
    head = body.split("## Table of Contents", 1)[0]
    assert "## 阶梯" in head, "SQLi ladder must sit before the ToC"
    steps = _numbered_steps(head.split("## 阶梯", 1)[1])
    assert len(steps) == 6, steps
    order = ["闭合", "order by", "union select", "取库", "盲注", "waf"]
    positions = []
    for token in order:
        idx = next((i for i, s in enumerate(steps) if token in s.lower()), None)
        assert idx is not None, f"ladder lost step: {token}"
        positions.append(idx)
    assert positions == sorted(positions), positions


def test_sqli_ladder_has_exit_criteria() -> None:
    body = _read("sql-injection.md")
    head = body.split("## Table of Contents", 1)[0]
    steps = _numbered_steps(head.split("## 阶梯", 1)[1])
    missing = [s for s in steps if "出口" not in s]
    assert not missing, f"steps without an exit criterion: {missing}"


def test_upload_ladder_is_four_ordered_steps() -> None:
    body = _read("server-side-exec.md")
    _, after = body.split("## File Upload to RCE Techniques", 1)
    section = after.split("### ", 1)[0]
    steps = _numbered_steps(section)
    assert len(steps) == 4, steps
    order = ["extension blacklist", "content-type", "parser config", "path traversal"]
    positions = []
    for token in order:
        idx = next((i for i, s in enumerate(steps) if token in s.lower()), None)
        assert idx is not None, f"ladder lost step: {token}"
        positions.append(idx)
    assert positions == sorted(positions), positions


def test_upload_ladder_has_exit_criteria() -> None:
    body = _read("server-side-exec.md")
    _, after = body.split("## File Upload to RCE Techniques", 1)
    steps = _numbered_steps(after.split("### ", 1)[0])
    missing = [s for s in steps if "出口" not in s]
    assert not missing, f"steps without an exit criterion: {missing}"


def test_subfile_banned_census() -> None:
    """Report-only: how many BANNED recipes survive in the subfiles.

    This is a census, not an assertion -- subfiles are out of scope for the
    index sweep, and the numbers are recorded in the ledger so the next round
    can decide whether to spend on them.
    """
    indexed = set(INDEXES)
    rows: list[tuple[str, int, list[str]]] = []
    for path in sorted(SKILLS.glob("*/*.md")):
        rel = f"{path.parent.name}/{path.name}"
        if rel in indexed:
            continue
        low = path.read_text(encoding="utf-8").lower()
        tokens = [t for t in BANNED + BANNED_COMMANDS if t in low]
        count = sum(low.count(t) for t in tokens)
        if count:
            rows.append((rel, count, tokens))
    rows.sort(key=lambda row: (-row[1], row[0]))
    total = sum(row[1] for row in rows)
    print(f"\n[subfile BANNED census] {total} hits across {len(rows)} subfiles")
    for rel, count, tokens in rows:
        print(f"  {count:3d}  {rel}  {tokens}")


def test_stage2_artifacts_are_digest_pinned() -> None:
    """Downloaded build artifacts must carry a sha256 the build verifies."""
    text = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    urls = re.findall(r'^ARG IMPACKET_WHEEL_URL="?([^"\n]+)"?$', text, re.MULTILINE)
    assert urls and urls[0].endswith(".whl"), "impacket wheel URL missing"
    digests = re.findall(r"^ARG \w+_SHA256=([0-9a-f]{64})$", text, re.MULTILINE)
    assert len(digests) >= 2, f"expected ffuf + impacket digests, got {digests}"
    assert "sha256sum -c -" in text, "downloaded wheel is not integrity-checked"
