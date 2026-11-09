# Skill routing: map what the target DOES to exactly one direction index.
#
# Why a decision table and not a knowledge card
# ---------------------------------------------
# A 2026 skill ablation on an MCP-grounded CTF agent (arXiv, *When Skills Don't
# Help*) compared 591 / 12,865 / 17,253 / 36,001 tokens of documentation: the gap
# between no-skills and full-skills was 8.9pp, p=0.71. The authors name the missing
# variable *environment-feedback bandwidth* -- when the tool layer returns strict,
# low-latency, schema-validated observations, the environment itself supplies the
# correction signal and procedural knowledge becomes redundant overhead.
#
# For this benchmark that means the value of an index is not "more techniques".
# It is turning an observation into a decision. So this layer does three things
# only: one cheap observation decides the type, the type selects one index, and a
# falsifier is written before the first payload. Technique lists stay in the
# indexes; repeating them here is a token tax that also teaches the model that
# reading the router equals reading the method.

from __future__ import annotations

from typing import Iterable

#: (observable signal, skill, first move after classification)
#:
#: A signal must be confirmable by looking once -- "looks like" is not a signal.
#: Order is priority: when several rows match, the topmost wins.
ROUTES: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    (
        "HTTP app: forms / login / API / upload / sessions",
        "ctf-web",
        ("web", "checker", "engagement"),
        "root once + one route map; create two accounts before attacking",
    ),
    (
        "install / build / publish / deploy / package names / registry",
        "ctf-supply-chain",
        ("web", "checker"),
        "read lockfiles and registry config; answer is the dep graph",
    ),
    (
        "chat / assistant / agent / tool / plugin / moderation",
        "ctf-agentic-ai",
        ("web", "checker"),
        "find the agent's decision point, not a route",
    ),
    (
        "model weights / adversarial input / prompt injection / classifier",
        "ctf-ai-ml",
        ("web", "checker", "file"),
        "fix the model, input channel and threshold first",
    ),
    (
        "ollama / vllm / gradio / comfyui / open-webui inference service",
        "ctf-ai-infra",
        ("web", "checker", "tcp"),
        "inspect exposed models, files and control surface",
    ),
    (
        "ELF binary + remote stdin/stdout service",
        "ctf-pwn",
        ("tcp",),
        "checksec -> offset -> primitive; prove the crash first",
    ),
    (
        "stripped binary / PE / APK / wasm / pyc",
        "ctf-reverse",
        ("file", "tcp"),
        "locate the check statically, then confirm dynamically",
    ),
    (
        "pcap / disk / memory / image / audio / document",
        "ctf-forensics",
        ("file",),
        "inspect the file, then its family table; no hand-rolled strings",
    ),
    (
        "big integers / curves / keys / nonces / ciphertext",
        "ctf-crypto",
        ("file", "tcp"),
        "identify the construction (RSA? ECC? LCG?) first",
    ),
    (
        "encoding chains / pyjail / bashjail / esolang / puzzle",
        "ctf-misc",
        ("file", "tcp"),
        "inspect the encoding, then decide what to hand-write",
    ),
    (
        "sample / C2 / obfuscated script / macro document",
        "ctf-malware",
        ("file",),
        "static IOC/config first, execution last",
    ),
    (
        "person / place / social / image geolocation",
        "ctf-osint",
        ("web",),
        "metadata and public records first",
    ),
)

#: Character ceiling for the unfiltered table. It is user_instructions and is
#: paid on every call; beyond this size the text belongs in an index, not the
#: prompt. Real runs always pass ``kind`` and land well under KIND_MAX_CHARS.
MAX_CHARS = 3000

#: Ceiling for a single-kind table -- the size a run actually pays.
KIND_MAX_CHARS = 2400


def _table(usable: dict[str, str], kind: str | None = None) -> str:
    """Render registered directions, filtered by the run's challenge kind.

    ``usable`` maps a category to the exact id ``register()`` returned
    (``category/category``). Emitting the bare category would be ambiguous:
    strix's loader scans every skill directory and skips a name that resolves
    to more than one file, so the model would get "Ambiguous skill name" and
    lose the turn.

    ``kind=None`` keeps every row for callers that do not know the challenge
    kind; a filtered table only offers directions whose tools are installed.
    """
    rows = [
        f"- {signal} -> `{usable[skill]}`: {first}"
        for signal, skill, kinds, first in ROUTES
        if skill in usable and (kind is None or kind in kinds)
    ]
    return "\n".join(rows)


def render(
    names: Iterable[str],
    ref: str,
    triage: str = "ctf-triage/ctf-triage",
    kind: str | None = None,
) -> str:
    """Render the routing contract.

    Args:
        names: registered skill ids (``category/category``); bare categories are
            ignored because they cannot be resolved unambiguously.
        ref: absolute root of the skill subfiles, readable via ``exec_command``.
        triage: entry skill when the type is unknown; skipped if not registered.
        kind: challenge kind (web / file / tcp / ...); None keeps every row.

    Returns:
        Multi-line instruction, or an empty string when nothing is registered.
    """
    raw = set(names)
    if not raw:
        return ""
    usable = {n.split("/", 1)[0]: n for n in raw if "/" in n}
    table = _table(usable, kind)
    if not table and kind is not None:
        # An unknown kind must degrade to the full table, not to "no route":
        # a misclassified challenge would otherwise lose every direction.
        table = _table(usable, None)

    if not table:
        step_two = (
            f"2. **No direction index is registered for this run.** "
            f"`load_skill([\"{triage}\"])` once to classify, then work from that "
            "index and the tools; do not `load_skill` a direction.\n"
            if triage in raw
            else "2. **No direction index is registered for this run.** Work from "
            "the tools; do not `load_skill` a direction.\n"
        )
    else:
        triage_line = (
            f'2. **Choose by what the target DOES**, then load one index. If the '
            f'type is unknown, `load_skill(["{triage}"])` once to classify '
            "(triage is not a direction index), then load **exactly one** "
            "direction index.\n"
            if triage in raw
            else "2. **Choose by what the target DOES**, then load **exactly "
            "one** direction index.\n"
        )
        step_two = triage_line + table + "\n"

    return (
        "[Skill routing] You are the dispatcher of a skill library, not an expert "
        "answering from memory. The method lives in the index you load, not in "
        "your priors. Four moves:\n"
        "1. **Observe before naming.** Classify with one cheap, unfakeable "
        "observation: HTTP root status/length/fingerprint; a file goes to "
        "`file` and `binwalk`.\n"
        "   Liveness gate: same body on every path, or only a framework 404 "
        "with no app marker = dead instance. Say so and stop; do not enumerate.\n"
        + step_two
        + "2b. **Prefer the enumerator.** If `route_map`, `path_variants`, "
        "`method_sweep` or `tcp_batch` covers it, "
        "call it once instead of looping by hand.\n"
        "3. **Write the falsifier before the first payload**: \"If mechanism M holds, "
        "check C returns X; if Y, M is closed.\" Two identical responses from "
        "one family = wrong mechanism: change the attack class, not the payload.\n"
        "4. **Re-plan at 40% and 70%.** Three lines: proven / assumed / "
        "the one fact that unlocks the flag.\n"
        "Non-skill subfiles: text via `exec_command` (cat/sed -n), images via "
        f"`view_image`; {ref}/<category>/x.md; do NOT `load_skill` them."
    )
