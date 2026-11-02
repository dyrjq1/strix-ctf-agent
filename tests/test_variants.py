"""path_variants: the variant matrix must actually vary the path.

095 regression: DeepSeek stayed on one decoding hypothesis for 29 calls and
never tried uppercase. These tests pin the generation logic and the
"differing vs baseline" filter, without any network.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.variants import (  # noqa: E402
    _VARIANT_KINDS,
    _encode_pct,
    _variant_paths,
    path_variants,
)


def test_upper_variant_is_generated():
    """/internal/banner -> /INTERNAL/BANNER. This is the 095 miss."""
    out = dict(_variant_paths("/internal/banner", ("upper",)))
    assert out["upper"] == "/INTERNAL/BANNER"


def test_case_variants_keep_the_hierarchy():
    for kind in ("upper", "lower", "title"):
        for _kind, path in _variant_paths("/api/Plugin/Stats", (kind,)):
            assert path.count("/") == 3, path


def test_pct_keeps_slashes_so_it_hits_a_real_path():
    """Encoding the whole string would collapse it into one bogus segment."""
    assert _encode_pct("a b") == "a%20b"
    assert "/" not in _encode_pct("ab")
    for _kind, path in _variant_paths("/a/b", ("pct",)):
        assert path.startswith("/") and path.count("/") == 2


def test_dot_semicolon_and_slash_variants_differ_from_input():
    for kind in ("dot", "semi", "slash"):
        pairs = _variant_paths("/internal/banner", (kind,))
        assert pairs, kind
        assert pairs[0][1] != "/internal/banner", kind


def test_as_is_is_not_returned_as_a_variant():
    """A no-op variant would double the request count for zero information."""
    for kind in _VARIANT_KINDS:
        assert all(p != "/a" for _k, p in _variant_paths("/a", (kind,)))


def _call(fn, *args, **kwargs):
    """`path_variants` is async (function_tool requires it); await it plainly."""
    return asyncio.run(fn(*args, **kwargs))


def test_unknown_kind_is_rejected_before_any_request():
    out = _call(path_variants, "/a", base_url="https://example.test", kinds="bogus")
    assert "unknown kinds" in out


def test_relative_path_without_base_url_is_rejected():
    out = _call(path_variants, "/a")
    assert "needs base_url" in out


def test_empty_urls_is_rejected():
    assert "urls empty" in _call(path_variants, "   ")

def test_registers_as_a_real_async_tool():
    """A sync handler silently fails registration.

    `agents.function_tool(timeout=...)` only accepts async handlers; a sync one
    raises `ValueError: FunctionTool timeout_seconds is only supported for
    async ... handlers`, which `capabilities._install` records as an error and
    an empty tool list. The tool then simply is not there -- no exception at
    call time, just a missing name in the tool surface. Caught on 2026-10-31
    when `installed["variants"] == []` while everything else looked fine.
    """
    import asyncio
    import inspect

    from agents import function_tool

    from ctf_strix import variants

    assert inspect.iscoroutinefunction(variants.path_variants)

    # Registration itself is the assertion: before the fix this raised
    # ValueError, which capabilities._install turned into variants: [].
    tool = function_tool(timeout=180)(variants.path_variants)
    assert tool.name == "path_variants"
    assert tool.timeout_seconds == 180


def test_register_returns_the_tool_name():
    from ctf_strix import variants

    seen: list[str] = []

    def register_fn(*tools):
        seen.extend(t.name for t in tools)

    names = variants.register(register_fn=register_fn)

    assert names == ["path_variants"]
    assert seen == ["path_variants"]
