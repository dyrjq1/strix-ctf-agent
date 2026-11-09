"""``skill_route``: turn pasted observations into ranked discipline cards.

The prompt already carries a routing *table* (``routing.ROUTES``) the model
applies by judgement. This tool is its deterministic complement: the model
pastes what it has seen (tool output, file type, banner, error text) and gets
the top directions ranked by distinct keyword hits, each with a start card to
read via ``exec_command``. Same evidence vocabulary as the table
(:mod:`ctf_strix.skill_signals`), same tie-break order (``ROUTES``), so the
two layers cannot disagree.

Deliberately *not* a replacement for judgement:
- no hit -> says so explicitly; free-solving continues, no index is loaded on
  a guess (the anti-pattern the whole L1/L2 design exists to prevent);
- output is capped at 6 KiB and card previews at 15 lines, flags masked --
  this is a router, not a document server.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Final

from ctf_strix import skillpack
from ctf_strix.skill_signals import SIGNALS, Signal

#: Rollback switch. Off values match the ``capabilities`` env convention;
#: unset (or any other value) means on, so the tool ships enabled and one
#: variable removes it from the registry and the prompt.
ENV_FLAG: Final = "CTF_SKILL_ROUTE"
_OFF_VALUES: Final = ("0", "false", "no")

#: Hard output ceiling. A route answer above this means the preview logic
#: regressed into dumping the card; truncate with a marker instead.
_MAX_RESULT_BYTES: Final = 6144

#: Card preview lines. Enough to recognise the method, not to read it.
_PREVIEW_LINES: Final = 15

#: Directions reported. Two is the whole point: a router that returns every
#: direction with a nonzero score is a search engine, not a router.
_TOP: Final = 2


def enabled() -> bool:
    """Return whether ``skill_route`` should register for this process."""
    return os.environ.get(ENV_FLAG, "").strip().lower() not in _OFF_VALUES


def _category_rank() -> dict[str, int]:
    """Stable tie-break: order of first appearance in ``routing.ROUTES``."""
    from ctf_strix import routing

    rank: dict[str, int] = {}
    for _, skill, _, _ in routing.ROUTES:
        rank.setdefault(skill, len(rank))
    for signal in SIGNALS:  # a signal category absent from ROUTES ranks last
        rank.setdefault(signal.category, len(rank) + 100)
    return rank


def score(observations: str) -> list[tuple[str, int, list[str]]]:
    """Rank directions by distinct pattern hits, deterministic on ties.

    One pattern counts once per category even if it matches twice, and
    duplicate patterns across a category's signals are unioned -- the score
    must measure breadth of evidence, not repetition.
    """
    text = observations or ""
    hits: dict[str, dict[str, str]] = {}
    evidence: dict[str, list[str]] = {}
    for signal in SIGNALS:
        for pattern in signal.patterns:
            match = pattern.search(text)
            if match is None:
                continue
            cat = signal.category
            hits.setdefault(cat, {})
            if pattern.pattern in hits[cat]:
                continue
            hits[cat][pattern.pattern] = match.group(0)
            evidence.setdefault(cat, []).append(match.group(0))
    rank = _category_rank()
    ranked = sorted(
        hits,
        key=lambda cat: (-len(hits[cat]), rank.get(cat, 10_000)),
    )
    return [
        (cat, len(hits[cat]), [ev.strip()[:40] for ev in evidence[cat][:4]])
        for cat in ranked
    ]


def _preview(path: Path) -> str:
    """First lines of a start card, flag-masked; empty when unreadable."""
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = body.splitlines()[:_PREVIEW_LINES]
    masked = [skillpack.mask_flags(line) for line in lines]
    return "\n".join(masked)


def _render(observations: str, ref: str) -> str:
    ranked = score(observations)
    if not ranked:
        return (
            "[skill_route] no keyword signal matched these observations.\n"
            "Do not load a discipline index on a guess: keep free-solving, "
            "gather one more cheap observation (file type, banner, error text, "
            "tool output) and call skill_route again with it."
        )
    blocks: list[str] = [
        "[skill_route] top directions by deterministic keyword match "
        "(evidence first, then where to read):"
    ]
    for place, (cat, points, evidence) in enumerate(ranked[:_TOP], start=1):
        signal = _first_signal(cat, evidence)
        card = Path(ref) / cat / signal.card
        lines = [f"{place}. {cat} — {points} hit(s): {', '.join(evidence)}"]
        lines.append(f"   start card: {card}")
        preview = _preview(card)
        if preview:
            lines.append(f"   preview (first {_PREVIEW_LINES} lines, flags masked):")
            lines.append(preview)
        blocks.append("\n".join(lines))
    blocks.append(
        "Verify against the observations before committing: the card is a "
        'starting point, not a verdict. Full method: `load_skill(["'
        + ranked[0][0]
        + '/'
        + ranked[0][0]
        + '"])` for the direction index, then read subfiles via exec_command.'
    )
    return "\n".join(blocks)


def _first_signal(category: str, evidence: list[str]) -> Signal:
    """Pick the signal whose card best represents the matched evidence.

    The signal with the most of this category's evidence snippets wins; ties
    resolve to declaration order, so the choice is deterministic.
    """
    lowered = [ev.lower() for ev in evidence]
    best: Signal | None = None
    best_count = -1
    for signal in SIGNALS:
        if signal.category != category:
            continue
        count = sum(
            1
            for pattern in signal.patterns
            for ev in lowered
            if pattern.search(ev) is not None
        )
        if count > best_count:
            best, best_count = signal, count
    if best is None:  # unreachable while the consistency test passes
        raise ValueError(f"no signal declared for category {category!r}")
    return best


def skill_route(observations: str) -> str:
    """Rank CTF directions for pasted observations; point at the best card.

    Args:
        observations: Raw evidence text -- tool output, file(1) lines, banners,
            error messages, challenge description. Paste what was actually
            seen, not a summary of guesses.

    Returns:
        Top directions with hit counts and matched keywords, the start card
        path for each, a short masked preview, or an explicit no-hit message
        (never a guess). Capped at 6 KiB.
    """
    result = _render(observations, skillpack.ref_root())
    if len(result.encode("utf-8")) > _MAX_RESULT_BYTES:
        marker = (
            f"\n... [skill_route output truncated at {_MAX_RESULT_BYTES} bytes]"
        )
        budget = _MAX_RESULT_BYTES - len(marker.encode("utf-8"))
        keep = result.encode("utf-8")[:budget].decode("utf-8", errors="ignore")
        result = keep.rstrip() + marker
    return result


def _as_async(func):
    """Run a blocking helper off the event loop, keeping its signature.

    Same reason as ``file_triage._as_async``: ``function_tool(timeout=...)``
    rejects sync handlers, and the rejection surfaces only as one printed
    line inside the entrypoint's try/except -- the tool would silently never
    register. Per-module copy per house convention.
    """
    import asyncio
    import functools

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):  # noqa: ANN002, ANN003
        return await asyncio.to_thread(func, *args, **kwargs)

    return wrapper


TOOLS: Final = (skill_route,)


def register(register_fn: Any | None = None) -> list[str]:
    """Register ``skill_route`` unless ``CTF_SKILL_ROUTE`` disables it.

    Args:
        register_fn: injection point for tests; defaults to the factory's
            ``register_agent_tools``.

    Returns:
        Freshly registered tool names (empty when gated off or duplicate).
    """
    if not enabled():
        return []
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001 - registration must survive a probe failure
            existing = set()
    else:
        existing = set()
    from agents import function_tool

    wrapped = [function_tool(timeout=120)(_as_async(fn)) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]
