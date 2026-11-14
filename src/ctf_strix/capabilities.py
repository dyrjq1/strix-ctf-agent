"""Capability installation shared by the eval harness and the official entrypoint.

Why this module exists
----------------------
The v2 work added three primitives (``http_probe``, ``route_map``,
``method_sweep``) and validated them through ``scripts/run_strix_ctf.py``.
The official CTFY entrypoint (``ctf_strix.agent``) never installed them, so
the submitted container ran with the pre-v2 tool surface while the eval
numbers described the v2 one.  That is a measurement/implementation split,
not a model-quality difference.

Both entrypoints now call the same helper.  Registration failures are
collected instead of swallowed: a capability that fails to register must be
visible in the run log, otherwise it is indistinguishable from "not needed
this challenge".
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable


RegisterFn = Callable[[], list[str]]


def _install(
    name: str,
    register: RegisterFn,
    installed: dict[str, list[str]],
    errors: list[str],
) -> None:
    """Run one registration and record either its tool names or its error."""
    try:
        installed[name] = list(register())
    except Exception as exc:  # noqa: BLE001 - one capability must not kill the run
        installed[name] = []
        errors.append(f"{name}: {type(exc).__name__}: {exc}")


#: Kinds where the HTTP primitives are worth their schema.  A ``file`` or
#: ``tcp`` challenge has no route table to probe: buying ``route_map`` there is
#: dead weight in every request's prompt, and it also invites the model to look
#: for a web surface that does not exist.
WEB_KINDS: tuple[str, ...] = ("web", "checker", "engagement")

#: Tokens in the task's own metadata that mark a challenge as AI-facing.  This
#: is used only to *offer* the AI-security tools; a hit is not a claim that the
#: challenge is one.  Kept deliberately narrow: every token here has been seen
#: on a real CTFY challenge page.
_AISEC_HINTS: tuple[str, ...] = (
    "agentic_ai",
    "ai_security",
    "ai-security",
    "llm",
    "prompt_injection",
    "prompt-injection",
    "prompt_injection_indirect",
    "prompt_injection_bypass",
    "agent_defense",
    "agent_task",
    "rag",
    "mcp",
    "asi01",
    "asi02",
    "asi03",
    "asi04",
    "asi05",
    "asi06",
    "asi07",
    "asi08",
    "asi09",
    "asi10",
)

#: Tags that begin with an AI-security hint but mean something else.  Subtracted
#: before the hint is tested, so ``llm_reasoning`` does not turn on ``llm``.
_AISEC_LOOKALIKES: tuple[str, ...] = ("llm_reasoning",)


def wants_aisec(kind: str, task: dict | None = None) -> tuple[bool, str]:
    """Decide whether to register the three AI-security tools.

    Args:
        kind: challenge kind from ``agent._challenge_kind``.
        task: the parsed ``task.json``; ``None`` means "no metadata available".

    Returns:
        ``(enabled, reason)``.  The reason is printed once at start-up, so a run
        where the tools were off is distinguishable from a run where they were
        on and not needed -- the two look identical in a transcript otherwise.

    Notes:
        ``CTF_AISEC=1`` forces them on and ``CTF_AISEC=0`` forces them off for
        both entrypoints.  Without either, they follow the challenge metadata:
        an AI-facing target gets them, everything else does not.
    """
    forced = os.environ.get("CTF_AISEC", "").strip().lower()
    if forced in ("0", "false", "no"):
        return False, "CTF_AISEC=0"
    if forced in ("1", "true", "yes"):
        return True, "CTF_AISEC=1"
    if kind not in WEB_KINDS:
        return False, f"kind={kind} has no web surface"
    return _aisec_signal(task)


def _hint_matches(hint: str, blob: str) -> bool:
    """Return whether ``hint`` occurs in ``blob`` as a whole token.

    Substring matching is wrong here, and the failure was measured on the
    platform's own catalog: ``rag`` matched ``storage``, so a plain storage
    administration challenge was handed the three AI
    security tools plus their schema on every request.  Underscores and
    hyphens are part of a token, so ``ai_security`` and ``ai-security`` still
    match themselves but ``aisecurity`` does not accidentally match either.

    Args:
        hint: one entry from :data:`_AISEC_HINTS`.
        blob: lower-cased challenge metadata.

    Returns:
        ``True`` only when the hint stands on its own.
    """

    pattern = r"(?<![a-z0-9])" + re.escape(hint) + r"(?![a-z0-9])"
    if re.search(pattern, blob) is None:
        return False
    # A hint can stand alone as a token and still belong to a longer tag that
    # means something else.  ``llm_reasoning`` is the practice suite's OSINT
    # reasoning tag (measured on one payroll-kiosk challenge, no model anywhere);
    # matching the bare ``llm`` inside it bought three useless schemas on
    # every request.  Subtract known look-alikes, then test the hint again.
    for lookalike in _AISEC_LOOKALIKES:
        if lookalike.startswith(hint + "_") or lookalike.startswith(hint + "-"):
            blob = blob.replace(lookalike, " ")
    return re.search(pattern, blob) is not None


def _metadata_tokens(task: dict) -> list[str]:
    """Flatten the task's tags/labels/name/description into searchable tokens."""
    tokens: list[str] = []
    challenge = task.get("challenge") or {}
    if isinstance(challenge, dict):
        tokens.append(str(challenge.get("name") or ""))
        tokens.append(str(challenge.get("description") or ""))
        tokens.extend(str(t) for t in (challenge.get("tags") or []))
    tokens.extend(str(t) for t in (task.get("tags") or []))
    tokens.extend(str(t) for t in (task.get("labels") or []))
    return [t for t in tokens if t]


def install_web_capabilities(
    http_register: RegisterFn | None = None,
    discovery_register: RegisterFn | None = None,
    variants_register: RegisterFn | None = None,
    traffic_register: RegisterFn | None = None,
    web_cve_register: RegisterFn | None = None,
    viability_register: RegisterFn | None = None,
) -> tuple[dict[str, list[str]], list[str]]:
    """Install the structured HTTP and route-discovery primitives.

    Args:
        http_register: Test seam; defaults to ``ctf_strix.http_probe.register``.
        discovery_register: Test seam; defaults to ``ctf_strix.discovery.register``.
        variants_register: Test seam; defaults to ``ctf_strix.variants.register``.
        traffic_register: Test seam; defaults to ``ctf_strix.traffic.register``.
        web_cve_register: Test seam; defaults to
            ``ctf_strix.aisec.tools.register_web_cve``.
        viability_register: Test seam; defaults to
            ``ctf_strix.viability.register``.

    Returns:
        ``(installed, errors)``.  ``installed`` maps capability name to the
        tool names newly registered (empty when already present).  ``errors``
        is a list of human-readable failures, empty on full success.
    """
    if http_register is None:
        from ctf_strix.http_probe import register as http_register
    if discovery_register is None:
        from ctf_strix.discovery import register as discovery_register
    if variants_register is None:
        from ctf_strix.variants import register as variants_register
    if traffic_register is None:
        from ctf_strix.traffic import register as traffic_register
    if web_cve_register is None:
        from ctf_strix.aisec.tools import register_web_cve as web_cve_register
    if viability_register is None:
        from ctf_strix.viability import register as viability_register

    installed: dict[str, list[str]] = {}
    errors: list[str] = []
    _install("http_probe", http_register, installed, errors)
    _install("discovery", discovery_register, installed, errors)
    _install("variants", variants_register, installed, errors)
    # Traffic memory is read-only and depends on http_probe having recorded
    # something, but it is registered separately: a failure to install the
    # ledger must not take the probe down with it.
    _install("traffic", traffic_register, installed, errors)
    # The offline CVE index is data, not an AI-security feature: a plain
    # Apache/WordPress box gets it too.  It is installed separately so a
    # missing snapshot cannot take the HTTP primitives down with it.
    _install("web_cve", web_cve_register, installed, errors)
    # 可行性探针（三条 ladder 一次调用出三态裁决）。它是本能力自带的预算，
    # 不是可以单独调的参数：CTF_VIABILITY=0 只做消融/回滚，不关别的工具。
    viability_on, _reason = wants_viability()
    if viability_on:
        _install("viability", viability_register, installed, errors)
    return installed, errors


def wants_viability() -> tuple[bool, str]:
    """Decide whether the ``viability_probe`` ladder tool is installed.

    The tool ships on with the web surface.  ``CTF_VIABILITY=0`` is the
    ablation and the rollback path; there is no positive override because a
    value other than ``0/false/no`` would be a second, unmeasured default.

    Returns:
        ``(enabled, reason)``, phrased like :func:`wants_aisec` so the run log
        can tell "off on purpose" from "never offered".
    """
    forced = os.environ.get("CTF_VIABILITY", "").strip().lower()
    if forced in ("0", "false", "no"):
        return False, "CTF_VIABILITY=0"
    return True, "default on"


def install_soft_deadline(soft_seconds: float, turns: int):
    """Install the soft-deadline guard when a positive budget is configured.

    Args:
        soft_seconds: Seconds after which tool results start telling the agent
            to converge.  Non-positive disables the guard.
        turns: Turn budget, used only to phrase the hint.

    Returns:
        The installed guard, or ``None`` when disabled.
    """
    if soft_seconds <= 0:
        return None
    from ctf_strix.deadline_guard import DeadlineGuard
    from ctf_strix.deadline_guard import install as install_deadline_guard

    return install_deadline_guard(
        DeadlineGuard(wall=soft_seconds * 2, soft=soft_seconds, turns=turns)
    )

def _aisec_signal(task: dict | None) -> tuple[bool, str]:
    """Answer the metadata half of :func:`wants_aisec`.

    Args:
        task: the parsed ``task.json``; ``None`` means "no metadata available".

    Returns:
        ``(enabled, reason)``; ``True`` only when a hint matches the task's own
        metadata.  Kept separate so the offline gate below applies the same
        evidence instead of growing a second, subtly different hint list.
    """
    if not task:
        return False, "no task metadata"
    blob = " ".join(_metadata_tokens(task)).lower()
    hits = [hint for hint in _AISEC_HINTS if _hint_matches(hint, blob)]
    if hits:
        return True, "task metadata mentions " + ", ".join(sorted(set(hits))[:3])
    return False, "task metadata has no AI-security signal"


#: Kinds with no HTTP surface of their own where the offline CVE lookup still
#: pays.  A tcp challenge is a remote service whose banner names a component and
#: version; ``ai_cve_lookup`` reads a bundled rule base, needs no target and no
#: network, and is the only CVE source in the offline image.
_AISEC_OFFLINE_KINDS: tuple[str, ...] = ("tcp",)


def aisec_offline(kind: str, task: dict | None = None) -> tuple[bool, str]:
    """Decide whether the offline CVE lookup alone should be registered.

    :func:`wants_aisec` answers "does this target have an AI surface", and "no"
    is the right answer for a tcp challenge -- there is no page to fingerprint.
    The lookup is a different tool: it needs no target, so it is not withheld
    from a kind that can still use it.  The full three-tool set stays behind
    :func:`wants_aisec`.

    Args:
        kind: challenge kind from ``agent._challenge_kind``.
        task: the parsed ``task.json``; the evidence is the same metadata
            :func:`wants_aisec` reads.

    Returns:
        ``(enabled, reason)``, printed once at start-up like the other gates.
        ``CTF_AISEC=0`` vetoes it and ``CTF_AISEC=1`` arms it, the same as the
        wider gate; otherwise the challenge metadata decides.
    """
    forced = os.environ.get("CTF_AISEC", "").strip().lower()
    if forced in ("0", "false", "no"):
        return False, "CTF_AISEC=0"
    if kind not in _AISEC_OFFLINE_KINDS:
        return False, f"kind={kind} has no offline AI surface"
    if forced in ("1", "true", "yes"):
        return True, "CTF_AISEC=1"
    return _aisec_signal(task)


#: Tools strix assembles from the sandbox toolset instead of adding them to
#: ``factory._BASE_TOOLS``; a method card that names one is still valid.
_SHELL_TOOL_NAMES: frozenset[str] = frozenset({"exec_command", "write_stdin"})


def _tool_name(obj: Any) -> str:
    """Name of a tool object or bare function (``""`` when it has neither)."""
    return str(getattr(obj, "name", "") or getattr(obj, "__name__", "") or "")


def live_tool_names() -> frozenset[str]:
    """Every tool name registered in this process, for method-card filtering.

    ``factory.registered_agent_tools()`` returns :class:`FunctionTool` objects
    (``.name``); ``_BASE_TOOLS`` holds bare functions (``__name__``) and is what
    ``tool_trim`` edits, so both are read.

    Returns:
        The union of the shell toolset, the registered extension tools and the
        vendor base tools.  An **empty** set means the probe failed -- callers
        must treat it as "unknown", not as "nothing is registered", which is why
        both entrypoints pass ``live_tool_names() or None``.
    """
    names = set(_SHELL_TOOL_NAMES)
    try:
        from strix.agents import factory
    except Exception:  # noqa: BLE001 -- no strix runtime (unit tests, tooling)
        return frozenset()
    try:
        names.update(_tool_name(tool) for tool in factory.registered_agent_tools())
        names.update(_tool_name(tool) for tool in getattr(factory, "_BASE_TOOLS", ()))
    except Exception:  # noqa: BLE001 -- older runtime without the query API
        return frozenset()
    names.discard("")
    return frozenset(names)
