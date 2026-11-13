"""One table decides both what is registered and what the prompt says.

Why this module exists
----------------------
The system prompt listed the web primitives by hand, while registration was
decided by ``kind`` in the entrypoint.  The two drifted in both directions
(docs/27 C3/C4):

* a non-web challenge paid ~3.8k chars of schema for four HTTP tools it could
  not use (37.5% of the file tool surface when it was measured);
* a file challenge *had* six primitives it never heard about, because the
  prompt's Tools section named only the web four.

A list with two sources is a list that will be wrong.  Each tool therefore gets
one row here: the kinds it is registered for, and the one line the prompt uses
to describe it.  Registration reads the table, the prompt reads the table, and
``tests/test_catalogue.py`` fails when a registered tool has no row.

Each summary is deliberately one line.  The prompt is paid on every request,
and a tool the model cannot name is a tool it will not call.  When this table
and the code disagree about a name, the name is the bug.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ToolInfo:
    """One registered tool: its name, its prompt line, and where it belongs.

    Attributes:
        name: the tool name the model calls; must match the registered
            function name.
        summary: one line for the prompt's Tools section, without a trailing
            full stop (the renderer adds the bullet).
        kinds: challenge kinds this tool is registered for.  ``"*"`` means all
            of them, including the non-web ones.
        group: which installer owns it -- ``base`` / ``web`` / ``file`` /
            ``tcp`` / ``aisec``.  Used for diagnostics and wiring tests.
    """

    name: str
    summary: str
    kinds: frozenset[str]
    group: str

    def applies(self, kind: str) -> bool:
        """Return whether this tool is offered for ``kind``."""
        return "*" in self.kinds or kind in self.kinds


#: Kinds with a live network target.  Everything else is an attachment
#: challenge and would pay for HTTP primitives it never calls.
WEB_KINDS: Final[frozenset[str]] = frozenset({"web", "checker", "engagement"})
#: Attachment challenge: files on disk.
FILE_KINDS: Final[frozenset[str]] = frozenset({"file"})
#: Remote binary service (pwn), reached over a socket.
TCP_KINDS: Final[frozenset[str]] = frozenset({"tcp"})
#: Present on every kind, including kinds not named above.
ALL_KINDS: Final[frozenset[str]] = frozenset({"*"})


CATALOGUE: Final[tuple[ToolInfo, ...]] = (
    # -- always present ----------------------------------------------------
    ToolInfo(
        "exec_command",
        "shell. Use it for Python scripts, payload loops and every file read "
        "after you get execution; there is no second host",
        ALL_KINDS,
        "base",
    ),
    ToolInfo(
        "load_skill",
        "load at most one discipline index; its line at the end says when; "
        "subfiles: `exec_command` (cat/sed -n), images `view_image`",
        ALL_KINDS,
        "base",
    ),
    ToolInfo(
        "think",
        "reasoning scratchpad. It does not touch the target and yields no new "
        "information",
        ALL_KINDS,
        "base",
    ),
    # -- web ---------------------------------------------------------------
    ToolInfo(
        "http_probe",
        "one HTTP exchange in, one structured line out; a per-host cookie jar "
        "keeps a login alive across calls; bodies and headers need no script",
        WEB_KINDS,
        "web",
    ),
    ToolInfo(
        "route_map",
        "crawl the site once and list API paths plus unverified `?` candidates "
        "taken from the page's own vocabulary",
        WEB_KINDS,
        "web",
    ),
    ToolInfo(
        "method_sweep",
        "send one method across many paths in a single call, to find which "
        "route answers at all",
        WEB_KINDS,
        "web",
    ),
    ToolInfo(
        "path_variants",
        "retry one path under case, encoding and prefix variants, for auth "
        "filters that match a string instead of a route",
        WEB_KINDS,
        "web",
    ),
    ToolInfo(
        "traffic_list",
        "list this run exchanges plus ids the target returned that nobody "
        "fetched yet; read-only, no network",
        WEB_KINDS,
        "web",
    ),
    ToolInfo(
        "traffic_view",
        "re-read one stored exchange, paginated by offset, without re-sending "
        "it; read-only",
        WEB_KINDS,
        "web",
    ),
    ToolInfo(
        "web_cve_lookup",
        "offline CVE index for web products; KEV entries first",
        WEB_KINDS,
        "web",
    ),
    # -- attachment --------------------------------------------------------
    ToolInfo(
        "file_triage",
        "identify a file or directory: family, size, entropy, flag-like "
        "strings, and the one command to run next",
        FILE_KINDS | TCP_KINDS,
        "file",
    ),
    ToolInfo(
        "decode_blob",
        "decode a multi-layer blob and report the chain: "
        "base64/base32/base58/base85/ascii85/hex/binary, gzip/zlib/utf-16 "
        "between layers, rot13/rot47/url/html-entity on top",
        FILE_KINDS | TCP_KINDS,
        "file",
    ),
    ToolInfo(
        "unpack_archive",
        "extract an archive safely and keep going into nested archives: "
        "zip/tar/gzip/bzip2/xz/zstd, plus 7z/rar through the system 7z; "
        "refuses entries that escape the output directory",
        FILE_KINDS | TCP_KINDS,
        "file",
    ),
    ToolInfo(
        "hexpeek",
        "bytes as hex and ASCII with offsets, for reading a header without "
        "guessing at `xxd` flags",
        FILE_KINDS | TCP_KINDS,
        "file",
    ),
    ToolInfo(
        "elfpeek",
        "inspect an ELF: info/sections/symbols/strings/gadgets/disasm. Static "
        "first, never run an unknown binary; disasm symbol='name' reads one "
        "whole function",
        FILE_KINDS | TCP_KINDS,
        "file",
    ),
    ToolInfo(
        "elffind",
        "resolve an ELF symbol or byte string to both file offset and vaddr, "
        "which is what a ret2* chain needs",
        FILE_KINDS | TCP_KINDS,
        "file",
    ),
    # -- remote service ----------------------------------------------------
    ToolInfo(
        "tcp",
        "connect once, optionally send a payload, show the banner and the "
        "reply as text and hex",
        TCP_KINDS,
        "tcp",
    ),
    ToolInfo(
        "tcp_batch",
        "send several payloads to one service and get one compact line per "
        "response, for offset and format-string probing",
        TCP_KINDS,
        "tcp",
    ),
    # -- ai security (opt-in; registered only when the rules are present) --
    ToolInfo(
        "ai_fingerprint",
        "fingerprint an LLM/agent endpoint: framework, model family, exposed "
        "tool surface",
        WEB_KINDS,
        "aisec",
    ),
    ToolInfo(
        "ai_cve_lookup",
        "look one component and version up in the bundled rule base; there is "
        "no internet, so this is the only CVE source",
        # tcp too: the lookup needs no target and no network, and a remote
        # service's banner is where the component and version come from.
        WEB_KINDS | TCP_KINDS,
        "aisec",
    ),
    ToolInfo(
        "ai_quick_scan",
        "fingerprint plus matching CVEs in one call, for the first probe of an "
        "AI-facing target",
        WEB_KINDS,
        "aisec",
    ),
)

_BY_NAME: Final[dict[str, ToolInfo]] = {info.name: info for info in CATALOGUE}


def for_kind(
    kind: str,
    groups: tuple[str, ...] | None = None,
    names: frozenset[str] | set[str] | None = None,
) -> list[ToolInfo]:
    """Return the catalogue rows offered for one challenge kind.

    Args:
        kind: ``web`` / ``file`` / ``tcp`` / ``checker`` / ``engagement``.
        groups: restrict to these installer groups; ``None`` means all.
        names: restrict to tools that are really in the registry; ``None``
            means "do not check".  Groups alone are too coarse: one installer
            can fail halfway through a group, and the prompt would then still
            promise the tools that did not make it.  Callers in the running
            process pass the measured names, so a promised tool is a callable
            tool.

    Returns:
        Rows in catalogue order, which is the order they should be read in.
    """
    return [
        info
        for info in CATALOGUE
        if info.applies(kind)
        and (groups is None or info.group in groups)
        # ``base`` tools are vendor built-ins: they live in the factory's base
        # set, never in the extendable registry, so a name check against that
        # registry would silently drop ``exec_command`` from the prompt.
        and (names is None or info.group == "base" or info.name in names)
    ]


def describe(name: str) -> str:
    """Return the prompt line for one tool name, or an empty string."""
    info = _BY_NAME.get(name)
    return info.summary if info else ""


def prompt_block(
    kind: str,
    groups: tuple[str, ...] | None = None,
    names: frozenset[str] | set[str] | None = None,
) -> str:
    """Render the prompt's Tools section for one kind.

    Args:
        kind: challenge kind, as returned by ``agent._challenge_kind``.
        groups: installer groups that actually succeeded.
        names: tools measured in the registry; see :func:`for_kind`.

    Returns:
        A markdown section, or an empty string when nothing applies.
    """
    rows = for_kind(kind, groups, names)
    if not rows:
        return ""
    lines = ["## Tools", ""]
    lines.extend(f"- `{info.name}` \u2014 {info.summary}" for info in rows)
    return "\n".join(lines)


def registered_names(
    kind: str,
    groups: tuple[str, ...] | None = None,
    names: frozenset[str] | set[str] | None = None,
) -> set[str]:
    """Names the prompt will promise for ``kind``; used by the wiring tests."""
    return {info.name for info in for_kind(kind, groups, names)}
