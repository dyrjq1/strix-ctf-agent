"""Observation store: a lossless, queryable copy of degraded tool output.

Why this exists
---------------
A cap that only keeps head/tail/marked evidence is lossy: the middle is gone
for the rest of the run.  The EnIGMA lesson (arXiv:2409.16165) is that the
dropped original must remain retrievable, or the model answers from a
half-visible fact.  This module writes the *complete* output once, keyed by
its own content hash, and exposes three read-only views that cut on meaning
(function boundary / JSON top-level key / hit line +-N), never on a fixed
byte or line window.

Storage
-------
``$CTFY_WORK_DIR/.ctf_obs/<run_token>/obs.jsonl``.  ``run_token`` is chosen
once per process (``CTFY_RUN_ID`` when present, else ``uuid4().hex[:12]``).
Appends only; an entry whose ``content_hash`` already exists is not rewritten,
so replaying the same history is byte-idempotent.  Records are never deleted.

The byte caps below are *memory shape* parameters, not solving budgets: the
container disk is finite and a run can produce a few MB of tool output.  A
single entry is capped at 4 MiB and a run at 32 MiB; past that a new output
simply falls back to the ordinary content cap (no pointer, no data loss of
older entries).  ``/tmp`` is unusable here (16m tmpfs, hidden by the jail), so
the ledger always lives under the injected working directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Final

OBS_ROOT: Final = ".ctf_obs"
OBS_FILE: Final = "obs.jsonl"

#: One record may hold a large response; tool output above this is not stored.
_ENTRY_MAX: Final = 4 * 1024 * 1024
#: Whole-run cap.  Old records stay; new ones stop being added.
_RUN_MAX: Final = 32 * 1024 * 1024
#: Lines kept on each side of a fact hit in the stub (whole-line aligned).
HIT_CONTEXT: Final = 2
#: Head bytes kept in a non-process stub, so the model still sees the opening.
_STUB_HEAD_CHARS: Final = 400

_lock = threading.Lock()
_RUN_TOKEN: str = os.environ.get("CTFY_RUN_ID", "").strip() or uuid.uuid4().hex[:12]

# ------------------------------------------------------------------ patterns

#: Disassembly symbol headers: ``0000000000401136 <main>:``.
_DISASM_FUNC_RE: Final = re.compile(
    r"(?m)^[ \t]*(?P<addr>[0-9a-fA-F]{4,16})[ \t]+<(?P<name>[^>\n]{1,120})>:[ \t]*$"
)
_PY_FUNC_RE: Final = re.compile(
    r"(?m)^[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*\("
)
_CLASS_RE: Final = re.compile(r"(?m)^[ \t]*class[ \t]+(?P<name>[A-Za-z_]\w*)")
_JS_FUNC_RE: Final = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?(?:async[ \t]+)?function[ \t]+"
    r"(?P<name>[A-Za-z_$][\w$]*)[ \t]*\("
)
_IMPORT_RE: Final = re.compile(
    r"(?m)^[ \t]*(?:from[ \t]+\S+[ \t]+import[ \t]+[^\n]+|import[ \t]+[^\n]+)$"
)
_STRING_LINE_RE: Final = re.compile(
    r"""(?m)^[ \t]*(?P<q>["'])(?P<val>[^"'\n]{4,120})(?P=q)[ \t]*[,;)]?[ \t]*$"""
)


def _token() -> str:
    """Filesystem-safe run token."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", _RUN_TOKEN)[:64] or "run"


def base_dir() -> Path | None:
    """Directory for this run's observations, or ``None`` when not injected.

    Local runs and unit tests do not set ``CTFY_WORK_DIR``; externalisation is
    then disabled entirely so nothing is written to the caller's cwd.
    """
    raw = os.environ.get("CTFY_WORK_DIR", "").strip()
    if not raw:
        return None
    return Path(raw) / OBS_ROOT / _token()


def store_path() -> Path | None:
    root = base_dir()
    return root / OBS_FILE if root is not None else None


def disabled() -> bool:
    """``CTF_OBS_OFF=1`` turns the whole v1 triple off (ordinary cap remains)."""
    return os.environ.get("CTF_OBS_OFF", "").strip().lower() in ("1", "true", "yes")


def _ctx_off() -> bool:
    return os.environ.get("CTF_CTX_OFF", "").strip().lower() in ("1", "true", "yes")


def enabled() -> bool:
    """The triple runs only with a work dir and neither off-switch set."""
    return not disabled() and not _ctx_off() and base_dir() is not None


def set_run_token(token: str) -> None:
    """Test seam: pin the run token so two stores can be compared."""
    global _RUN_TOKEN
    _cache.clear()
    _RUN_TOKEN = (token or "").strip() or uuid.uuid4().hex[:12]


def reset_for_tests() -> None:
    """Test seam: new token, next call starts a fresh run namespace."""
    _cache.clear()
    set_run_token(uuid.uuid4().hex[:12])


# -------------------------------------------------------------- extraction


def fact_hit_lines(text: str) -> list[int]:
    """1-based line numbers carrying a fact-shaped hit.

    The shapes are the exact same family :mod:`ctf_strix.context` already uses
    for evidence preservation and :mod:`ctf_strix.fact_ledger` uses for facts:
    flag, credential-like key/value, JWT.  No concrete sample value appears
    anywhere in this module.
    """
    from ctf_strix import context as ctf_context

    hits: list[int] = []
    for number, line in enumerate(text.splitlines(), 1):
        if (
            ctf_context._FLAG_RE.search(line)
            or ctf_context._EVIDENCE_KV_RE.search(line)
            or ctf_context._EVIDENCE_JWT_RE.search(line)
        ):
            hits.append(number)
    return hits


def _json_value(text: str) -> Any:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except (TypeError, ValueError):
        return None


def summary_meta(text: str) -> dict[str, Any]:
    """Structural names a summary stub can show without the body."""
    meta: dict[str, Any] = {
        "functions": [],
        "imports": [],
        "json_keys": [],
        "strings": [],
        "is_summary": False,
    }
    data = _json_value(text)
    if data is not None:
        meta["is_summary"] = True
        if isinstance(data, dict):
            meta["json_keys"] = [str(key) for key in list(data)[:40]]
        else:
            meta["json_keys"] = [f"[{index}]" for index in range(min(len(data), 40))]

    names: list[str] = []
    for pattern in (_DISASM_FUNC_RE, _PY_FUNC_RE, _CLASS_RE, _JS_FUNC_RE):
        for match in pattern.finditer(text):
            name = match.group("name").strip()
            if name and name not in names:
                names.append(name)
    meta["functions"] = names[:20]
    meta["imports"] = [" ".join(m.group(0).split()) for m in _IMPORT_RE.finditer(text)][:12]
    meta["strings"] = [m.group("val") for m in _STRING_LINE_RE.finditer(text)][:12]
    if names or meta["imports"]:
        meta["is_summary"] = True
    return meta


def classify(text: str) -> tuple[str, dict[str, Any], list[int]]:
    """Return ``(class, meta, fact_hit_lines)`` for one tool output."""
    hits = fact_hit_lines(text)
    if hits:
        return "fact", summary_meta(text), hits
    meta = summary_meta(text)
    if meta["is_summary"]:
        return "summary", meta, []
    return "process", meta, []


# ------------------------------------------------------------------- store


def _read_entries(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except (TypeError, ValueError):
                    continue
                if isinstance(row, dict) and isinstance(row.get("id"), str):
                    out.append(row)
    except OSError:
        return []
    return out


_cache: dict[str, list[dict[str, Any]]] = {}


def _cached(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    key = str(path)
    if key not in _cache:
        _cache[key] = _read_entries(path)
    return _cache[key]


def clear_cache() -> None:
    """Test seam; the cache is otherwise process-lifetime."""
    _cache.clear()


def entries() -> list[dict[str, Any]]:
    """All entries of the current run, append order."""
    return list(_cached(store_path()))


def count_entries() -> int:
    return len(entries())


def offload(
    text: str,
    *,
    tool_name: str = "",
    cls: str = "process",
    hit_lines: list[int] | None = None,
) -> dict[str, Any] | None:
    """Append ``text`` once; return its entry (existing entry when replayed)."""
    path = store_path()
    if path is None:
        return None
    raw = text.encode("utf-8", "replace")
    if len(raw) > _ENTRY_MAX:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    entry = {
        "id": digest[:12],
        "content_hash": digest,
        "tool_name": (tool_name or "")[:80],
        "size": len(raw),
        "class": cls,
        "hit_lines": sorted({int(n) for n in (hit_lines or [])}),
        "ts": round(time.time(), 3),
        "rel": f"{OBS_ROOT}/{_token()}/{OBS_FILE}",
        "text": text,
    }
    with _lock:
        existing = _cached(path)
        for row in existing:
            if row.get("content_hash") == digest:
                return row
        line = json.dumps(entry, ensure_ascii=False)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            used = path.stat().st_size if path.exists() else 0
            if used + len(line.encode("utf-8")) > _RUN_MAX:
                return None
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
            existing.append(entry)
        except OSError:
            return None
    return entry


# ------------------------------------------------------------------- stubs


def _line_ranges(lines: list[str], hits: list[int], context: int) -> list[tuple[int, int]]:
    spans = sorted(
        (max(1, number - context), min(len(lines), number + context)) for number in hits
    )
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _head_of(text: str, limit: int = _STUB_HEAD_CHARS) -> str:
    if len(text) <= limit:
        return text
    cut = text.rfind("\n", 0, limit)
    return text[: cut if cut >= 0 else limit]


def _fmt_lines(numbers: list[int], limit: int = 20) -> str:
    shown = ", ".join(str(n) for n in numbers[:limit])
    if len(numbers) > limit:
        shown += f", ... +{len(numbers) - limit}"
    return shown


def build_stub(
    text: str,
    entry: dict[str, Any],
    *,
    cls: str,
    hit_lines: list[int],
    meta: dict[str, Any],
    body: str = "",
) -> str:
    """Structured replacement for one degraded output.

    Pure function of ``text`` (the id is its hash) plus the process-constant
    run path.  It always carries the same elision marker the ordinary cap uses,
    so a second pass sees it as already processed and returns it unchanged.
    """
    lines = text.splitlines() or [text]
    parts = [
        "[ctf-obs stub]",
        f"class: {cls}",
        f"original: {len(text)} chars, sha256:{entry['content_hash'][:16]}",
        f"obs: {entry.get('rel', '')} id={entry['id']}",
    ]
    if entry.get("tool_name"):
        parts.append(f"tool: {entry['tool_name']}")

    if cls == "fact":
        parts.append(f"fact lines: {_fmt_lines(hit_lines)}")
        parts.append("[ctf-obs hit context, whole lines]")
        for start, end in _line_ranges(lines, hit_lines, HIT_CONTEXT):
            parts.append(f"[lines {start}-{end}]")
            parts.extend(lines[start - 1 : end])
    elif cls == "summary":
        functions = meta.get("functions") or []
        keys = meta.get("json_keys") or []
        imports = meta.get("imports") or []
        strings = meta.get("strings") or []
        if functions:
            parts.append("functions: " + ", ".join(functions[:20]))
        if keys:
            parts.append("json keys: " + ", ".join(keys[:20]))
        if imports:
            parts.append("imports: " + " | ".join(imports[:8]))
        if strings:
            parts.append("strings: " + " | ".join(f'"{s[:60]}"' for s in strings[:8]))

    if cls in ("fact", "summary"):
        head = _head_of(text)
        if head:
            parts.append("[ctf-obs head]")
            parts.append(head)
        if body:
            parts.append(body)
        else:
            parts.append(f"[... {len(text)} chars capped by CTF context manager ...]")
    elif body:
        parts.append(body)
    else:
        parts.append(f"[... {len(text)} chars capped by CTF context manager ...]")

    parts.append(
        '[ctf-obs] the complete output is on disk; read it with '
        f'obs_view(obs_id="{entry["id"]}", sel="hits"|"block"|"grep"). '
        "Line numbers are 1-based."
    )
    return "\n".join(parts)


# ------------------------------------------------------------------- views


def _gutter(lines: list[str], start: int = 1) -> list[str]:
    return [f"{start + offset:>5}: {line}" for offset, line in enumerate(lines)]


def _blocks(text: str) -> list[tuple[str, str]]:
    """Semantic blocks: JSON top-level key or one whole function/class."""
    data = _json_value(text)
    if data is not None:
        if isinstance(data, dict):
            return [
                (str(key), f"{key}: " + json.dumps(value, ensure_ascii=False, sort_keys=True))
                for key, value in data.items()
            ]
        return [
            (f"[{index}]", json.dumps(value, ensure_ascii=False, sort_keys=True))
            for index, value in enumerate(data)
        ]

    lines = text.splitlines() or [text]
    starts: list[tuple[int, str]] = []
    for pattern in (_DISASM_FUNC_RE, _PY_FUNC_RE, _CLASS_RE, _JS_FUNC_RE):
        for match in pattern.finditer(text):
            number = text.count("\n", 0, match.start()) + 1
            starts.append((number, match.group("name").strip()))
    starts = sorted({(number, name) for number, name in starts})
    if not starts:
        return [("all", text)]
    out: list[tuple[str, str]] = []
    for index, (number, name) in enumerate(starts):
        end = starts[index + 1][0] - 1 if index + 1 < len(starts) else len(lines)
        out.append((name, "\n".join(lines[number - 1 : end])))
    return out


def obs_list(limit: int = 25) -> str:
    """List this run's offloaded outputs; read-only, never touches the target."""
    path = store_path()
    if path is None:
        return (
            "[obs] externalisation is off here (CTFY_WORK_DIR unset). "
            "Only the ordinary content cap applies."
        )
    rows = entries()
    if not rows:
        return "[obs] nothing offloaded yet; large tool outputs are stored automatically."
    wanted = max(1, min(100, int(limit or 25)))
    shown = rows[-wanted:]
    lines = [f"[obs] {len(rows)} stored output(s) at {OBS_ROOT}/{_token()}/{OBS_FILE}"]
    for row in shown:
        lines.append(
            f"{row['id']}  {str(row.get('class', '')):<8} {int(row.get('size', 0)):>8}B  "
            f"hits={len(row.get('hit_lines') or [])}  {row.get('tool_name') or '-'}"
        )
    if len(rows) > len(shown):
        lines.append(f"  ... {len(rows) - len(shown)} older; raise limit")
    return "\n".join(lines)


def _find(obs_id: str) -> dict[str, Any] | None:
    wanted = (obs_id or "").strip()
    for row in entries():
        if row.get("id") == wanted:
            return row
    return None


def obs_view(obs_id: str = "", sel: str = "hits", arg: str = "", context: int = 3) -> str:
    """Read one stored output by meaning -- never by a fixed line window.

    Args:
        obs_id: id from ``obs_list``.
        sel: ``hits`` (fact lines +-N), ``block`` (function/JSON key) or
            ``grep`` (regular expression).
        arg: block number/name for ``block``; regex for ``grep``; optional
            line number for ``hits``.
        context: lines on each side for ``hits``/``grep`` (0-20).

    Returns:
        The selected excerpt, or a hint naming known ids.
    """
    row = _find(obs_id)
    if row is None:
        known = ", ".join(item["id"] for item in entries()[-12:]) or "(none)"
        return f"[obs] no entry {obs_id!r}. Known ids: {known}. Call obs_list."
    text = str(row.get("text") or "")
    lines = text.splitlines() or [text]
    mode = (sel or "hits").strip().lower()
    around = max(0, min(20, int(context or 0)))
    header = f"[obs] {row['id']} class={row.get('class')} {row.get('size')}B lines={len(lines)}"

    if mode == "hits":
        wanted = [int(n) for n in re.findall(r"\d+", arg or "")] if arg else []
        hits = wanted or [int(n) for n in (row.get("hit_lines") or [])]
        if not hits:
            return header + "\n(no hit lines; use sel=block to list blocks, sel=grep to search)"
        spans = _line_ranges(lines, sorted(set(hits)), around)
        out = [header]
        for start, end in spans:
            out.append(f"[lines {start}-{end}]")
            out.extend(_gutter(lines[start - 1 : end], start))
        return "\n".join(out)

    if mode == "block":
        blocks = _blocks(text)
        if not (arg or "").strip():
            out = [header, "blocks:"]
            for index, (name, body) in enumerate(blocks, 1):
                out.append(f"  {index}. {name} ({len(body.splitlines())} lines)")
            out.append('read one with sel="block", arg="<number or name>"')
            return "\n".join(out)
        wanted = (arg or "").strip()
        chosen: tuple[str, str] | None = None
        if wanted.isdigit():
            index = int(wanted) - 1
            if 0 <= index < len(blocks):
                chosen = blocks[index]
        else:
            for name, body in blocks:
                if wanted.lower() in name.lower():
                    chosen = (name, body)
                    break
        if chosen is None:
            names = ", ".join(name for name, _ in blocks[:20]) or "(none)"
            return header + f"\nno block {wanted!r}; available: {names}"
        name, body = chosen
        return "\n".join([header, f"block: {name}", body])

    if mode == "grep":
        pattern = (arg or "").strip()
        if not pattern:
            return header + "\nsel=grep needs a regular expression in arg"
        try:
            regex = re.compile(pattern, re.I)
        except re.error as exc:
            return header + f"\nbad regex: {exc}"
        hits = [number for number, line in enumerate(lines, 1) if regex.search(line)]
        if not hits:
            return header + f"\nno line matches {pattern!r}"
        out = [header, f"matches: {_fmt_lines(hits)}"]
        for start, end in _line_ranges(lines, hits, around):
            out.append(f"[lines {start}-{end}]")
            out.extend(_gutter(lines[start - 1 : end], start))
        return "\n".join(out)

    return header + f"\nunknown sel={mode!r}; use hits, block or grep"


TOOLS: Final = (obs_list, obs_view)


def _as_async(func):
    """Register a sync helper as an async tool without losing its signature."""
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner


def register(register_fn=None) -> list[str]:
    """Register ``obs_list`` / ``obs_view``; no-op when the triple is off."""
    if not enabled():
        return []
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=60)(_as_async(fn)) for fn in TOOLS]
    fresh = [tool for tool in wrapped if getattr(tool, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [tool.name for tool in fresh]
