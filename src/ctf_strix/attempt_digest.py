"""Deterministic failure digest for a second solving attempt.

The digest is built only from the agent's own tool calls and tool outputs.
No model is called to summarize, and flag-like strings are removed, so a
retry cannot be steered by an answer the first attempt guessed correctly but
failed to submit.

This is the single-agent version of Veria's ``bump(insights)``: the next
attempt starts in a fresh container, but not from zero knowledge.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable, Sequence
from urllib.parse import urlsplit


_FLAG_RE = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[^}\s]{2,}\}")
_SECRET_RE = re.compile(
    r"(?i)\b(token|api[_-]?key|secret|password|passwd|session|authorization)"
    r"(\s*[=:]\s*)(?:bearer\s+)?[A-Za-z0-9._\-+/=]{6,}"
)
_HTTP_STATUS_RE = re.compile(r"(?:HTTP(?:/\d(?:\.\d)?)?\s+|status\"?\s*[:=]\s*)(\d{3})", re.I)
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_METHOD_RE = re.compile(r"(?:-X|--request)\s+([A-Z]+)|\bmethod\"?\s*[:=]\s*\"?([A-Z]+)", re.I)
_ERROR_HINT_RE = re.compile(
    r"error|required|invalid|denied|forbidden|not found|refused|timeout|"
    r"exception|traceback|unauthorized|missing|expect",
    re.I,
)
_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")

#: Meta tools describe the run, not the target.  ``finish_scan`` arguments
#: contain the agent's own summary (and often the target URL), which would
#: otherwise become a fake "CMD <url>" row and bury the real probes.
_META_TOOLS = frozenset(
    {
        "finish_scan",
        "agent_finish",
        "create_agent",
        "send_message_to_agent",
        "wait_for_agents",
        "stop_agent",
        "view_agent_graph",
        "think",
        "load_skill",
        "list_skills",
        "search_skills",
    }
)


@dataclass(frozen=True)
class Call:
    """One probe call reduced to the fields a retry can act on."""

    method: str
    target: str
    note: str


def _redact(text: str) -> str:
    """Remove flags and credential values while keeping field names."""
    text = _FLAG_RE.sub("[REDACTED_FLAG]", text)
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)


def _args_dict(raw: str) -> dict:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _method_of(tool_name: str, args: dict, raw: str) -> str:
    method = str(args.get("method") or "").strip().upper()
    if method in _METHODS:
        return method
    match = _METHOD_RE.search(raw)
    if match:
        return (match.group(1) or match.group(2) or "").upper()
    if tool_name in ("http_probe", "method_sweep", "path_variants"):
        return "GET"
    return "CMD"


def _target_of(args: dict, raw: str) -> str:
    value = args.get("url")
    if isinstance(value, str) and value:
        return value
    # A path list (`paths` / `urls`) is more informative than the bare host in
    # `base_url`: the whole point of the digest is to show which paths were
    # already probed, so prefer the path and only fall back to the host.
    for key in ("paths", "urls"):
        item = args.get(key)
        if isinstance(item, list) and item:
            return str(item[0])
        if isinstance(item, str) and item.strip():
            first = item.strip().splitlines()[0].split(",")[0].strip()
            if first:
                return first
    for key in ("base_url", "target"):
        item = args.get(key)
        if isinstance(item, str) and item:
            return item
    command = args.get("command")
    text = command if isinstance(command, str) and command else raw
    match = _URL_RE.search(text)
    if match:
        return match.group(0)
    return text.strip().splitlines()[0][:120] if text.strip() else ""


def _compact_target(target: str) -> str:
    """Keep host and path, drop query values and fragments."""
    if target.startswith("http://") or target.startswith("https://"):
        parts = urlsplit(target)
        path = parts.path or "/"
        return f"{parts.netloc}{path}"
    return target[:100]


def _note_of(output: str) -> str:
    """Extract the most actionable line: status first, then an error line."""
    if not output:
        return ""
    status = _HTTP_STATUS_RE.search(output)
    prefix = f"{status.group(1)} " if status else ""
    for line in output.splitlines():
        clean = line.strip()
        if 3 <= len(clean) <= 160 and _ERROR_HINT_RE.search(clean):
            return prefix + _redact(clean)
    for line in output.splitlines():
        clean = line.strip()
        if 3 <= len(clean) <= 160 and _FLAG_RE.search(clean):
            return prefix + _redact(clean)
    first = output.strip().splitlines()[0] if output.strip() else ""
    return prefix + _redact(first[:120])


def _calls(calls: Sequence[tuple[str, str]], outputs: Sequence[str]) -> list[Call]:
    result: list[Call] = []
    for index, (tool_name, raw) in enumerate(calls):
        if tool_name in _META_TOOLS:
            continue
        args = _args_dict(raw)
        method = _method_of(tool_name, args, raw)
        target = _compact_target(_target_of(args, raw))
        if not target:
            continue
        output = outputs[index] if index < len(outputs) else ""
        result.append(Call(method=method, target=target, note=_note_of(output)))
    return result


def _dedupe(calls: Iterable[Call]) -> list[Call]:
    seen: set[tuple[str, str]] = set()
    unique: list[Call] = []
    for call in calls:
        # A path hit by two methods is two facts; the note can differ.
        key = (call.method, call.target, call.note)
        if key in seen:
            continue
        seen.add(key)
        unique.append(call)
    return unique


def _untried(calls: Sequence[Call]) -> list[str]:
    """For the busiest paths, list HTTP methods not attempted yet."""
    by_target: dict[str, set[str]] = {}
    for call in calls:
        if call.method == "CMD":
            continue
        by_target.setdefault(call.target, set()).add(call.method)
    rows: list[str] = []
    for target, used in sorted(by_target.items(), key=lambda kv: -len(kv[1]))[:5]:
        missing = [method for method in _METHODS if method not in used]
        if missing:
            rows.append(f"{target}: {', '.join(missing)}")
    return rows


def build_digest(
    calls: Sequence[tuple[str, str]],
    outputs: Sequence[str],
    *,
    max_calls: int = 12,
    max_errors: int = 6,
    max_chars: int = 1800,
) -> str:
    """Build a compact, redacted account of one failed attempt.

    Args:
        calls: ``(tool_name, raw_arguments)`` in call order.
        outputs: Tool outputs in the same order (shorter is allowed).
        max_calls: Distinct method+target rows to keep.
        max_errors: Distinct error lines to keep.
        max_chars: Hard cap on the returned text.

    Returns:
        A prompt-ready digest, or an empty string when there is nothing to say.
    """
    parsed = _calls(calls, outputs)
    if not parsed:
        return ""

    unique = _dedupe(parsed)
    rows = unique[:max_calls]
    lines = [
        f"[ATTEMPT DIGEST] {len(calls)} probe calls, "
        f"{len({(c.method, c.target) for c in unique})} distinct method+target pairs."
    ]
    lines.append("Tried (method target -> first signal):")
    for call in rows:
        note = f" -> {call.note}" if call.note else ""
        lines.append(f"- {call.method} {call.target}{note}")
    if len(unique) > len(rows):
        lines.append(f"- ... and {len(unique) - len(rows)} more pairs")

    notes: list[str] = []
    for call in unique:
        if call.note and call.note not in notes:
            notes.append(call.note)
    if notes:
        lines.append("Signals worth acting on (verbatim, deduped):")
        lines.extend(f"- {note}" for note in notes[:max_errors])

    untried = _untried(parsed)
    if untried:
        lines.append("Methods not tried on busy paths:")
        lines.extend(f"- {row}" for row in untried)

    text = "\n".join(lines)
    if len(text) > max_chars:
        suffix = "\n...[digest truncated]"
        text = text[: max(0, max_chars - len(suffix))] + suffix
    return text
