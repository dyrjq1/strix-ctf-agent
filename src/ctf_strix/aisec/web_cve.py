"""Offline web-product CVE index: CPE version rules plus KEV flags.

The rules are generated at build time from NVD CPE matches and are evaluated
with :func:`ctf_strix.aisec.verrule.evaluate`, the same evaluator the AI rule
base uses.  Nothing here touches the network.

Three behaviours are deliberate and are pinned by tests:

* An unknown version never falls through to ``evaluate("")`` -- an empty rule
  evaluates to true, which would report every entry for the product.
* A version is normalised before evaluation, because banners carry suffixes
  such as ``(Unix)`` or ``-ubuntu0.1`` that would otherwise change the order.
* KEV entries sort first: they are the ones known to be exploited in the wild.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Final

from ctf_strix.aisec.verrule import evaluate

_HERE: Final = Path(__file__).resolve().parent
_DEFAULT_INDEX: Final = _HERE / "data" / "web_cve_index.json"
_DEFAULT_ALIASES: Final = _HERE / "data" / "web_cve_aliases.json"

_SEV_ORDER: Final[dict[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_PAREN: Final = re.compile(r"\s*\([^)]*\)")
_PRODUCT_PREFIX: Final = re.compile(r"^[a-z][a-z0-9._-]*/", re.IGNORECASE)
_DISTRO_SUFFIX: Final = re.compile(
    r"[-+~]\d*\.?(?:ubuntu|deb|el|fc|amzn|alpine|suse|centos|rhel)[\w.~-]*$",
    re.IGNORECASE,
)


def data_paths() -> tuple[Path | None, Path]:
    """Return ``(index_path, aliases_path)``; the index may be absent.

    ``CTF_WEB_CVE_DATA`` overrides the bundled directory or file.  It is read at
    call time so a test or a deployment can point at a snapshot after import.
    """

    override = os.environ.get("CTF_WEB_CVE_DATA", "").strip()
    if override:
        root = Path(override)
        index = root / "web_cve_index.json" if root.is_dir() else root
        aliases = index.parent / "web_cve_aliases.json"
    else:
        index = _DEFAULT_INDEX
        aliases = _DEFAULT_ALIASES
    return (index if index.is_file() else None, aliases)


class _Index:
    """Lazily loaded index; a changed file is re-read rather than cached stale."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key: tuple[str, int, int] | None = None
        self._data: dict[str, dict[str, dict[str, Any]]] = {}

    def load(self) -> dict[str, dict[str, dict[str, Any]]]:
        path, _ = data_paths()
        if path is None:
            return {}
        try:
            stat = path.stat()
            key = (str(path), stat.st_mtime_ns, stat.st_size)
        except OSError:
            return {}
        with self._lock:
            if key == self._key:
                return self._data
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return {}
            self._key, self._data = key, data if isinstance(data, dict) else {}
            return self._data


_INDEX: Final = _Index()
_ALIAS_CACHE: dict[str, Any] = {"key": None, "data": {}}


def _alias_data() -> dict[str, Any]:
    _, path = data_paths()
    try:
        stat = path.stat()
        key: tuple[str, int, int] | None = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        key = None
    if key is not None and _ALIAS_CACHE["key"] == key:
        return _ALIAS_CACHE["data"]
    data: dict[str, Any] = {}
    if key is not None:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            data = {}
    _ALIAS_CACHE["key"], _ALIAS_CACHE["data"] = key, data
    return data


def normalize_version(version: str | None) -> str:
    """Strip banner noise that would otherwise change version comparison.

    Parenthesised platform tags and distro package suffixes are removed; a
    vendor update suffix such as ``-sp1`` is kept, because it is part of the
    version the CPE rule was built from.

    Args:
        version: raw banner version.

    Returns:
        A comparable version string, or ``""`` when none was supplied.
    """

    v = str(version or "").strip().strip('"').strip("'")
    if not v:
        return ""
    v = _PAREN.sub("", v).strip()
    v = _PRODUCT_PREFIX.sub("", v).strip()
    v = _DISTRO_SUFFIX.sub("", v).strip()
    v = v.lstrip("vV")
    return v.strip()


def _norm_name(name: str) -> str:
    return " ".join(str(name or "").strip().lower().replace("_", " ").split())


def alias_table(index: dict[str, Any] | None = None) -> dict[str, tuple[str, ...]]:
    """Build the name → product-key table.

    Explicit aliases from ``web_cve_aliases.json`` win.  Bare product names are
    derived from the index so ``tomcat`` works without a hand-written row; a
    name shared by two vendors maps to both and results are de-duplicated by
    CVE at query time.

    Args:
        index: loaded index; ``None`` loads it.

    Returns:
        Normalised name → tuple of ``vendor:product`` keys.
    """

    idx = _INDEX.load() if index is None else index
    table: dict[str, set[str]] = {}
    explicit: set[str] = set()
    raw = _alias_data().get("aliases")
    if isinstance(raw, dict):
        for name, keys in raw.items():
            if isinstance(keys, str):
                keys = [keys]
            if not isinstance(keys, list):
                continue
            norm = _norm_name(name)
            explicit.add(norm)
            table.setdefault(norm, set()).update(
                str(k).lower() for k in keys if isinstance(k, str) and ":" in k
            )
    for key in idx:
        if ":" not in key:
            continue
        vendor, product = key.split(":", 1)
        names = {
            product,
            product.replace("_", " "),
            product.replace("_", "-"),
            f"{vendor} {product.replace('_', ' ')}",
            f"{vendor}/{product.replace('_', ' ')}",
        }
        for name in names:
            norm = _norm_name(name)
            # A hand-written alias wins: ``nginx`` must reach ``f5:nginx`` even
            # though ``nginx:nginx`` also exists in the index.
            if norm not in explicit:
                table.setdefault(norm, set()).add(key.lower())
    return {name: tuple(sorted(keys)) for name, keys in table.items()}


def resolve_component(component: str, index: dict[str, Any] | None = None) -> tuple[str, ...]:
    """Resolve a banner name or ``vendor:product`` to index keys.

    Args:
        component: product name as it appears in a banner or a guess.
        index: loaded index; ``None`` loads it.

    Returns:
        Keys present in the index, in alias order; empty when nothing matches.
    """

    idx = _INDEX.load() if index is None else index
    if not component:
        return ()
    raw = str(component).strip().lower()
    table = alias_table(idx)
    # Explicit aliases are checked before the literal index key.  NVD carries
    # both ``nginx:nginx`` and ``f5:nginx``; the literal key must not win just
    # because it exists, or the vendor-spelling table has no effect.
    hits = table.get(_norm_name(component), ())
    resolved = tuple(k for k in hits if k in idx)
    if resolved:
        return resolved
    return (raw,) if raw in idx else ()


def _sort_key(hit: dict[str, Any]) -> tuple[int, int, str]:
    return (
        0 if hit.get("kev") else 1,
        _SEV_ORDER.get(str(hit.get("severity") or "").lower(), 9),
        str(hit.get("cve") or ""),
    )


def lookup(
    component: str,
    version: str | None = None,
    top_k: int = 8,
) -> list[dict[str, Any]]:
    """Return CVE rules for one product, KEV first.

    With a version, only rules that evaluate true are returned.  Without one,
    no rule is evaluated; only KEV entries are returned, marked as candidates.

    Args:
        component: product name or ``vendor:product``.
        version: banner version; empty/``None`` means "list candidates only".
        top_k: maximum rows.

    Returns:
        Hits with ``cve / severity / rule / kev / product / matched``.
    """

    idx = _INDEX.load()
    if not idx:
        return []
    keys = resolve_component(component, idx)
    if not keys:
        return []
    ver = normalize_version(version)
    limit = max(1, min(int(top_k or 8), 50))
    merged: dict[str, dict[str, Any]] = {}
    for key in keys:
        for cve, entry in (idx.get(key) or {}).items():
            rule = str(entry.get("r") or "")
            kev = bool(entry.get("k"))
            if ver:
                if not rule or not evaluate(rule, ver, {}):
                    continue
                matched = True
            else:
                if not kev:
                    continue
                matched = False
            prev = merged.get(cve)
            if prev:
                prev["product"] = f"{prev['product']},{key}"
                continue
            merged[cve] = {
                "cve": cve,
                "severity": str(entry.get("s") or "?"),
                "rule": rule,
                "kev": kev,
                "product": key,
                "matched": matched,
            }
    return sorted(merged.values(), key=_sort_key)[:limit]


def cpe_match_rule(
    criteria: str,
    match: dict[str, Any],
    *,
    use_update: bool = True,
) -> str | None:
    """Turn one NVD ``cpeMatch`` into a verrule expression.

    The CPE update segment (``sp1`` / ``rc1`` / ...) is part of the exact
    version: dropping it collapses several distinct affected releases into one
    rule.  Range bounds keep their numeric value; an update qualifier on a
    bound is not a version suffix and cannot be expressed by the evaluator.

    Args:
        criteria: CPE 2.3 string from ``cpeMatch.criteria``.
        match: the ``cpeMatch`` object (version range fields).
        use_update: append the CPE update segment to an exact version.  The
            builder calls this with ``False`` once to measure the difference.

    Returns:
        A rule string, or ``None`` when the match carries no version.
    """

    parts = str(criteria or "").split(":")
    if len(parts) < 6:
        return None
    exact = parts[5]
    update = parts[6] if len(parts) > 6 else "*"
    if '"' in exact or '"' in update:
        return None
    clauses: list[str] = []
    if exact not in ("*", "-", ""):
        value = exact
        if use_update and update not in ("*", "-", ""):
            value = f"{exact}-{update}"
        clauses.append(f'version == "{value}"')
    for field, op in (
        ("versionStartIncluding", ">="),
        ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="),
        ("versionEndExcluding", "<"),
    ):
        bound = match.get(field)
        if bound:
            bound = str(bound)
            if '"' in bound:
                continue
            clauses.append(f'version {op} "{bound}"')
    return " && ".join(clauses) or None
