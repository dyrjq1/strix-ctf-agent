"""Offline web-CVE index: query semantics and build invariants.

Each test pins a behaviour that is easy to get subtly wrong:

* aliases from banner names to NVD vendor:product keys;
* the CPE update segment (``sp1`` / ``rc1``) in exact-version rules;
* no version must never mean "evaluate everything";
* banner suffixes must not change version order;
* KEV rows first, top_k honoured, missing data degrades to text.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.aisec import web_cve  # noqa: E402
from ctf_strix.aisec.verrule import evaluate  # noqa: E402

DATA = ROOT / "src" / "ctf_strix" / "aisec" / "data"


def test_alias_resolves_banner_names_to_index_keys():
    assert web_cve.resolve_component("nginx") == ("f5:nginx",)
    assert web_cve.resolve_component("Apache Tomcat") == ("apache:tomcat",)
    assert web_cve.resolve_component("node.js") == ("nodejs:node.js",)
    assert web_cve.resolve_component("apache:http_server") == ("apache:http_server",)


def test_explicit_alias_beats_a_literal_vendor_key():
    # NVD carries both ``nginx:nginx`` and ``f5:nginx``.  Spelling the vendor
    # out must not bypass the alias table and land on the thin duplicate.
    assert web_cve.resolve_component("nginx:nginx") == ("f5:nginx",)
    assert web_cve.resolve_component("node.js:node.js") == ("nodejs:node.js",)


def test_unknown_alias_is_empty_not_an_error():
    assert web_cve.resolve_component("no-such-product-xyz") == ()
    assert web_cve.lookup("no-such-product-xyz", "1.0") == []


def test_update_segment_is_part_of_an_exact_version_rule():
    match = {"criteria": "cpe:2.3:a:microsoft:exchange_server:5.5:sp1:*:*:*:*:*:*"}
    with_update = web_cve.cpe_match_rule("cpe:2.3:a:microsoft:exchange_server:5.5:sp1:*:*:*:*:*:*", match)
    without = web_cve.cpe_match_rule(
        "cpe:2.3:a:microsoft:exchange_server:5.5:sp1:*:*:*:*:*:*", match, use_update=False
    )
    assert 'version == "5.5-sp1"' in (with_update or "")
    assert 'version == "5.5"' == (without or "").strip()
    assert evaluate(with_update, "5.5-sp1") is True
    assert evaluate(with_update, "5.5") is False


def test_update_segment_is_kept_in_the_built_index():
    exchange = web_cve._INDEX.load()["microsoft:exchange_server"]
    assert any("sp1" in entry["r"] for entry in exchange.values())


def test_version_none_returns_only_kev_candidates():
    hits = web_cve.lookup("apache:http_server", None, top_k=50)
    assert hits, "apache httpd has KEV entries"
    assert all(hit["kev"] for hit in hits)
    assert all(hit["matched"] is False for hit in hits)
    # Without a version the full product must not be reported; that is the
    # evaluate("") failure this design exists to avoid.
    assert len(hits) < len(web_cve._INDEX.load()["apache:http_server"])


def test_default_version_is_candidates_only_not_a_wildcard():
    hits = web_cve.lookup("apache:tomcat")
    assert hits and all(hit["kev"] for hit in hits)


def test_version_suffixes_are_stripped_before_evaluation():
    base = {h["cve"] for h in web_cve.lookup("apache:http_server", "2.4.49", top_k=50)}
    for noisy in ("2.4.49 (Unix)", "2.4.49-ubuntu0.1", "2.4.49+deb12u1", "v2.4.49"):
        got = {h["cve"] for h in web_cve.lookup("apache:http_server", noisy, top_k=50)}
        assert got == base, noisy


def test_kev_rows_sort_first():
    hits = web_cve.lookup("apache:http_server", "2.4.49", top_k=20)
    flags = [hit["kev"] for hit in hits]
    assert flags == sorted(flags, reverse=True)
    assert flags[0] is True


def test_top_k_truncates():
    assert len(web_cve.lookup("apache:http_server", "2.4.49", top_k=3)) == 3
    assert len(web_cve.lookup("apache:http_server", "2.4.49", top_k=1)) == 1


def test_missing_index_degrades_to_a_message(tmp_path, monkeypatch):
    from ctf_strix.aisec.tools import web_cve_lookup

    monkeypatch.setenv("CTF_WEB_CVE_DATA", str(tmp_path))
    out = asyncio.run(web_cve_lookup("apache:http_server", "2.4.49"))
    assert "索引缺失" in out
    assert "Traceback" not in out


def test_non_web_kinds_do_not_get_the_tool():
    from ctf_strix import catalogue

    assert "web_cve_lookup" in catalogue.registered_names("web")
    for kind in ("file", "tcp"):
        assert "web_cve_lookup" not in catalogue.registered_names(kind)


def test_manifest_matches_the_index_bytes():
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    raw = (DATA / "web_cve_index.json").read_bytes()
    import hashlib

    assert manifest["sha256"] == hashlib.sha256(raw).hexdigest()
    assert manifest["bytes"] == len(raw)
    assert manifest["product_families"] == 79
    assert manifest["entries"] == 10678


def test_notice_covers_both_sources():
    text = (DATA / "NOTICE").read_text(encoding="utf-8")
    assert "CC0" in text
    assert "NIST" in text or "NVD" in text


def test_sample_cves_across_products():
    samples = [
        ("apache:http_server", "2.4.49", "CVE-2021-41773"),
        ("apache:tomcat", "9.0.30", "CVE-2020-1938"),
        ("php:php", "8.3.7", "CVE-2024-4577"),
        ("apache:log4j", "2.14.1", "CVE-2021-44228"),
        ("drupal:drupal", "7.57", "CVE-2018-7600"),
        ("vmware:spring_framework", "5.3.17", "CVE-2022-22965"),
        ("progress:moveit_transfer", "2021.0.4", "CVE-2023-34362"),
        ("nginx", "1.12.0", "CVE-2017-7529"),
        ("oracle:weblogic_server", "12.2.1.3.0", "CVE-2020-14882"),
        ("thinkphp", "3.2.3", "CVE-2019-9082"),
        ("wordpress", "4.9.8", "CVE-2019-8942"),
    ]
    for component, version, cve in samples:
        hits = {hit["cve"] for hit in web_cve.lookup(component, version, top_k=50)}
        assert cve in hits, (component, version, cve)


def test_patched_version_drops_the_rule():
    vulnerable = {h["cve"] for h in web_cve.lookup("apache:http_server", "2.4.49", top_k=50)}
    patched = {h["cve"] for h in web_cve.lookup("apache:http_server", "2.4.51", top_k=50)}
    assert "CVE-2021-41773" in vulnerable
    assert "CVE-2021-41773" not in patched


def test_tool_output_marks_candidate_mode_and_kev():
    from ctf_strix.aisec.tools import web_cve_lookup

    out = asyncio.run(web_cve_lookup("apache:http_server"))
    assert "无版本，仅候选" in out
    assert "[KEV 在野利用]" in out


def test_tool_output_honours_top_k():
    from ctf_strix.aisec.tools import web_cve_lookup

    out = asyncio.run(web_cve_lookup("apache:http_server", "2.4.49", top_k=2))
    assert "命中 2 条" in out


def test_prompt_surface_has_no_cve_ids_and_stays_small():
    """The constant prompt surface must not name any CVE."""
    import re

    from ctf_strix import catalogue
    from ctf_strix.aisec.tools import web_cve_lookup

    row = next(info for info in catalogue.CATALOGUE if info.name == "web_cve_lookup")
    doc = web_cve_lookup.__doc__ or ""
    assert len(row.summary) + len(doc) <= 750
    for text in (row.summary, doc):
        assert re.search(r"CVE-\d{4}-\d+", text) is None
