"""Which tools actually reach the target -- one list, four consumers.

## Why this module exists

Four runtime guards need to know "did the agent just touch the challenge, or
did it read a local file?".  Each of them used to carry its own tuple:

* ``enum_guard._PROBE_TOOLS``   -> 7 names (the only complete one)
* ``journey_guard._PROBE_TOOLS`` -> 3 names
* ``sweep_guard._PROBE_TOOLS``  -> 3 names

Nothing failed.  Nothing logged.  The three-name copies simply never matched
``http_probe`` / ``route_map`` / ``method_sweep`` / ``path_variants``, so for a
whole class of calls the guards were switched off.  Measured on the last batch:
those four primitives carried 10-13% of all probe calls, and the journey guard
recorded ``observe_calls=0`` when replaying them.

An incomplete name list is indistinguishable from "the guard had nothing to
report" -- that is the same silent-failure shape as the 2026-10-31 mount bug.
The fix is structural: there is one list, and it lives here.

## What belongs on it

Only tools whose arguments can carry a request to the challenge.  Reading
``/etc/passwd`` from the container, writing a note, or thinking does not
count: counting them would make every guard fire on noise.
"""

from __future__ import annotations

from typing import Final

#: Tools whose arguments can address the target.
#:
#: Keep this list next to reality, not next to intent.  Every name falls into
#: exactly one of two buckets, and the bucket is documented because the
#: distinction is not visible from the name:
#:
#: * **always present** -- ``exec_command`` / ``write_stdin`` (Shell
#:   capability) and the four primitives registered by ``capabilities``;
#: * **conditionally present** -- ``repeat_request`` is a Caido tool, and
#:   ``tool_trim`` drops the six Caido tools by default because the image has
#:   no ``caido-cli``.  Keeping it here is still correct: if an image ever
#:   ships Caido, the guard already knows the tool.  ``tests`` assert instead
#:   that the name is either registered *or* deliberately dropped by
#:   ``tool_trim`` -- so a genuinely invented name still fails.
PROBE_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "exec_command",
        "write_stdin",
        "repeat_request",
        "http_probe",
        "route_map",
        "method_sweep",
        "path_variants",
    }
)

#: Tools that talk to a target but are deliberately **not** probe tools.
#:
#: ``tcp`` / ``tcp_batch`` reach the challenge, so the naive move is to add
#: them to :data:`PROBE_TOOLS`.  Do not.  ``sweep_guard`` fires when one call
#: carries >= 24 distinct values; ``tcp_batch`` exists precisely to send 200
#: candidates (a padding oracle needs all 256 byte values).  Adding it there
#: would make the guard scream at the correct use of the tool, and a hint that
#: is always on is worse than no hint -- the model learns to ignore it.
#:
#: The auth-wall and duplicate-response guards also key on HTTP shapes
#: (``host:port`` paths, status codes); a raw socket has neither.
NETWORK_TOOLS: Final[frozenset[str]] = frozenset({"tcp", "tcp_batch"})

#: Names that are legitimately absent from the default tool surface.
#:
#: Used only by tests, to tell "conditionally dropped" apart from "invented".
CONDITIONAL_TOOLS: Final[frozenset[str]] = frozenset({"repeat_request"})

#: Prefixes instead of exact names, for tools whose instances are numbered or
#: namespaced (``browser_tab_1`` style).  Empty today, kept explicit so the
#: helper below does not silently change meaning if one is added.
PROBE_PREFIXES: Final[tuple[str, ...]] = ()


def is_probe_tool(name: str) -> bool:
    """Return True when ``name`` can carry a request to the target.

    Args:
        name: Registered tool name.

    Returns:
        True for exact members of :data:`PROBE_TOOLS` or a matching prefix.
    """
    if name in PROBE_TOOLS:
        return True
    return any(name.startswith(prefix) for prefix in PROBE_PREFIXES)
