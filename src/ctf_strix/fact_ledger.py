"""Append-only ledger of confirmed facts, and the block that injects them.

What counts as a fact
---------------------
Only strings a deterministic extractor can point at in a tool output: a flag
shape, a JWT shape, or a credential-like key/value.  The extractor reuses the
exact patterns :mod:`ctf_strix.context` already trusts (``_FLAG_RE`` /
``_EVIDENCE_KV_RE`` / ``_EVIDENCE_JWT_RE``); there is no model judgement and
no sample value in any pattern.  A fact carries the content hash, the 1-based
line range, and the observation id it came from, so the model can re-read the
source instead of trusting the ledger line.

Immutability
------------
Facts are appended with ``F#n`` ids and never edited.  A later output that
contradicts an earlier one produces new facts (and may be marked as
superseding in a future revision); it does not rewrite history.  This is the
Intentest constraint we can actually enforce with plain code: the model may
cite an id, not invent one.

Why the block sits after its anchor
-----------------------------------
The block is re-inserted after the output item that produced it, every
request.  Request N+1 is therefore request N's bytes plus the new items --
a strict prefix -- so the provider prefix cache keeps hitting.  A system-tail
block or a request-tail decoration would move the same bytes in N+1 and
invalidate the whole prefix (the measured 95.7% -> 57.8% regression).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Final

#: Block cap from the dispatch: at most this many facts per synthetic item.
MAX_FACTS_PER_BLOCK: Final = 8
#: Per-fact value cap inside the block (the ledger keeps the full value).
MAX_VALUE_CHARS: Final = 120
#: Marker that lets a replay recognise an already-inserted block.
VIRTUAL_MARK: Final = "[ctf-fact-ledger]"


@dataclass(frozen=True)
class Fact:
    """One immutable fact node."""

    id: str
    rule: str
    value: str
    content_hash: str
    start_line: int
    end_line: int
    obs_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule,
            "value": self.value,
            "content_hash": self.content_hash,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "obs_id": self.obs_id,
        }


_lock = threading.Lock()
_facts: list[Fact] = []
_by_hash: dict[str, list[Fact]] = {}
_seq = 0


def reset() -> None:
    """Test seam: forget every fact (a real run never calls this)."""
    global _seq
    with _lock:
        _facts.clear()
        _by_hash.clear()
        _seq = 0


def count() -> int:
    with _lock:
        return len(_facts)


def facts_for(content_hash: str) -> list[Fact]:
    with _lock:
        return list(_by_hash.get(content_hash, []))


def _candidates(text: str) -> list[tuple[int, str, str]]:
    """``(line, rule, value)`` in line then column order; no dedupe yet."""
    from ctf_strix import context as ctf_context

    found: list[tuple[int, int, str, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in ctf_context._FLAG_RE.finditer(line):
            found.append((number, match.start(), "flag", match.group(0)))
        for match in ctf_context._EVIDENCE_JWT_RE.finditer(line):
            found.append((number, match.start(), "jwt", match.group(0)))
        for match in ctf_context._EVIDENCE_KV_RE.finditer(line):
            found.append((number, match.start(2), "credential", match.group(2)))
    found.sort(key=lambda row: (row[0], row[1]))
    out: list[tuple[int, str, str]] = []
    seen: set[tuple[int, str, str]] = set()
    for number, _column, rule, value in found:
        key = (number, rule, value)
        if key in seen:
            continue
        seen.add(key)
        out.append((number, rule, value))
    return out


def scan(text: str) -> list[tuple[int, str, str]]:
    """Preview ``(line, rule, value)`` without appending anything."""
    return _candidates(text)


def observe(text: str, content_hash: str, obs_id: str = "") -> list[Fact]:
    """Return the facts of this output, appending them once per content hash.

    Idempotence is keyed on ``content_hash``: replaying the same history (the
    normal case on every request) never creates a second ``F#n`` or changes
    the block bytes of the anchor it belongs to.
    """
    global _seq
    if not content_hash:
        return []
    with _lock:
        existing = _by_hash.get(content_hash)
        if existing is not None:
            return list(existing)
        created: list[Fact] = []
        for number, rule, value in _candidates(text):
            _seq += 1
            created.append(
                Fact(
                    id=f"F{_seq}",
                    rule=rule,
                    value=value,
                    content_hash=content_hash,
                    start_line=number,
                    end_line=number,
                    obs_id=obs_id,
                )
            )
        _by_hash[content_hash] = created
        _facts.extend(created)
        return list(created)


def block_text(facts: list[Fact]) -> str:
    """The immutable synthetic block for one anchor (first 8 facts)."""
    shown = facts[:MAX_FACTS_PER_BLOCK]
    lines = [VIRTUAL_MARK]
    for fact in shown:
        value = " ".join(fact.value.split())[:MAX_VALUE_CHARS]
        lines.append(f"{fact.id} {fact.rule}: {value}")
    lines.append(
        'evidence: each F#n maps to an obs entry and a 1-based line range; '
        'read the source with obs_view(obs_id="<obs id from obs_list>", sel="hits").'
    )
    if len(facts) > len(shown):
        lines.append(f"(+{len(facts) - len(shown)} more from this output; re-read it with obs_view)")
    return "\n".join(lines)


def virtual_item(facts: list[Fact]) -> dict[str, Any]:
    """Synthetic message item inserted immediately after the anchor."""
    return {
        "type": "message",
        "role": "user",
        "content": [{"type": "input_text", "text": block_text(facts)}],
    }


def is_virtual(item: Any) -> bool:
    """Whether an input item is one of our injected fact blocks."""
    if not isinstance(item, dict) or item.get("type") not in (None, "message"):
        return False
    content = item.get("content")
    if isinstance(content, str):
        return content.startswith(VIRTUAL_MARK)
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                if block["text"].startswith(VIRTUAL_MARK):
                    return True
    return False
