"""Build the offline web-CVE index used by ``web_cve_lookup``.

Inputs are the local NVD annual feeds and the CISA KEV snapshot; the script
never downloads anything.  The product universe is the prototype's ``TARGETS``
verbatim (``ctfwork/kev_probe/build_full.py``), so the delivered index covers
the same families it was measured on.

Outputs (all written through a temporary file and ``os.replace``):

* ``web_cve_index.json``  -- ``{vendor:product: {cve: {s, r, k?}}}``
* ``manifest.json``       -- source versions, SHA-256, sizes, family count
* ``NOTICE``              -- CISA KEV (CC0) and NVD attribution

The CPE ``update`` segment is applied to exact-version matches: NVD encodes
patch levels such as ``sp1`` or ``rc1`` there, and dropping it collapses
distinct affected releases into one rule.

Run::

    .venv\\Scripts\\python.exe scripts\\build_web_cve.py
"""

from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.aisec.web_cve import cpe_match_rule  # noqa: E402

#: The prototype's product universe, copied without additions or removals.
TARGETS: set[str] = {
    "apache:http_server", "apache:tomcat", "apache:log4j", "apache:struts", "apache:struts2",
    "apache:activemq", "apache:camel", "apache:shiro", "apache:solr", "apache:flink", "apache:druid",
    "apache:ofbiz", "apache:zookeeper", "apache:tika", "apache:jspwiki", "apache:archiva",
    "apache:airflow", "apache:nifi", "apache:knox", "apache:ranger",
    "apache:geode", "apache:ignite", "apache:openmeetings", "apache:skywalking",
    "oracle:weblogic_server", "oracle:fusion_middleware", "oracle:http_server",
    "php:php", "php:phpmyadmin", "phpunit:phpunit", "phpmailer:phpmailer",
    "wordpress:wordpress", "drupal:drupal", "joomla:joomla", "magento:magento", "typo3:typo3",
    "nginx:nginx", "f5:nginx", "openresty:openresty",
    "atlassian:confluence", "atlassian:jira", "atlassian:bamboo", "atlassian:bitbucket",
    "vmware:spring_framework", "vmware:spring_cloud_gateway", "vmware:tanzu_spring_cloud_function",
    "vmware:spring_cloud_config", "vmware:spring_data_commons", "pivotal:spring_framework",
    "laravel:laravel", "thinkphp:thinkphp", "symfony:symfony", "cakephp:cakephp", "codeigniter:codeigniter",
    "microsoft:exchange_server", "microsoft:sharepoint_server", "microsoft:iis", "microsoft:asp.net",
    "citrix:netscaler", "citrix:adc", "citrix:gateway", "citrix:storefront",
    "fortinet:fortios", "fortinet:fortiproxy", "fortinet:fortimanager",
    "ivanti:connect_secure", "ivanti:policy_secure", "ivanti:epmm", "pulse_secure:pulse_connect_secure",
    "jenkins:jenkins", "gitlab:gitlab", "gitea:gitea", "bitbucket:bitbucket",
    "ibm:websphere_application_server", "ibm:websphere_liberty", "ibm:db2", "ibm:lotus_domino",
    "sonicwall:sonicos", "zyxel:zyxel", "netgear:netgear", "dlink:dir", "d-link:dir",
    "elastic:elasticsearch", "elastic:kibana", "elastic:logstash", "grafana:grafana",
    "zoho:manageengine", "zohocorp:manageengine", "solarwinds:orion_platform",
    "progress:moveit_transfer", "progress:whatsup_gold", "red_hat:jboss_enterprise_application_platform",
    "spring:spring_framework", "spring:spring_security", "spring:spring_boot",
    "nodejs:node.js", "node.js:node.js", "expressjs:express", "nextjs:next.js",
    "rubyonrails:rails", "rails:rails", "django:django", "flask:flask", "fastapi:fastapi",
    "cpanel:cpanel", "plesk:plesk", "webmin:webmin", "adminer:adminer",
    "confluence:confluence", "jira:jira", "couchdb:apache_couchdb", "mongodb:mongodb",
    "redis:redis", "nexus:nexus", "sonarqube:sonarqube",
}

_SEVERITY_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _cpe_matches(cve: dict) -> list[dict]:
    out: list[dict] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable"):
                    out.append(match)
    return out


def _rule(match: dict, *, use_update: bool) -> str | None:
    """Turn one cpeMatch into a verrule expression.

    Delegates to the runtime helper so the builder and the query side cannot
    disagree about the CPE update segment.

    Args:
        match: one NVD ``cpeMatch`` object.
        use_update: append the CPE update segment to exact versions.

    Returns:
        Expression, or ``None`` when the match carries no usable version.
    """

    return cpe_match_rule(str(match.get("criteria") or ""), match, use_update=use_update)


def _severity(cve: dict) -> str:
    for key in _SEVERITY_KEYS:
        metrics = (cve.get("metrics") or {}).get(key) or []
        if metrics:
            value = metrics[0].get("cvssData", {}).get("baseSeverity")
            if value:
                return str(value).lower()
            if key == "cvssMetricV2":
                return "high"
            return "?"
    return "?"


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def build(feeds: Path, kev_path: Path) -> tuple[bytes, dict]:
    kev_raw = json.loads(kev_path.read_text(encoding="utf-8"))
    kev_ids = {str(v.get("cveID") or "").upper() for v in kev_raw.get("vulnerabilities") or []}
    files = sorted(feeds.glob("nvdcve-2.0-*.json.gz"))
    if not files:
        raise SystemExit(f"no NVD feeds under {feeds}")

    with_update: dict[str, dict[str, list[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
    without_update: dict[str, dict[str, list[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
    severity: dict[str, str] = {}
    seen: set[str] = set()
    total_matches = 0
    update_matches = 0
    update_range_only = 0

    for feed in files:
        with gzip.open(feed, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cid = str(cve.get("id") or "").upper()
            if not cid or cid in seen:
                continue
            matches = _cpe_matches(cve)
            if not matches:
                continue
            keys: set[str] = set()
            for match in matches:
                parts = str(match.get("criteria") or "").split(":")
                if len(parts) < 6 or parts[3] + ":" + parts[4] not in TARGETS:
                    continue
                total_matches += 1
                update = parts[6] if len(parts) > 6 else "*"
                if update not in ("*", "-", ""):
                    update_matches += 1
                    if parts[5] in ("*", "-", ""):
                        update_range_only += 1
                key = parts[3] + ":" + parts[4]
                keys.add(key)
                old = _rule(match, use_update=False)
                new = _rule(match, use_update=True)
                if old:
                    without_update[key][cid].append(old)
                if new:
                    with_update[key][cid].append(new)
            if keys:
                seen.add(cid)
                severity[cid] = _severity(cve)

    index: dict[str, dict[str, dict]] = {}
    changed = 0
    added = 0
    affected: set[str] = set()
    for key in sorted(with_update):
        rows: dict[str, dict] = {}
        for cid in sorted(with_update[key]):
            new_rules = list(dict.fromkeys(with_update[key][cid]))
            old_rules = list(dict.fromkeys(without_update.get(key, {}).get(cid, [])))
            new_rule = " || ".join(f"({rule})" for rule in new_rules)
            old_rule = " || ".join(f"({rule})" for rule in old_rules)
            if cid not in without_update.get(key, {}):
                added += 1
                affected.add(cid)
            elif old_rule != new_rule:
                changed += 1
                affected.add(cid)
            entry: dict[str, object] = {"s": severity.get(cid, "?"), "r": new_rule}
            if cid in kev_ids:
                entry["k"] = 1
            rows[cid] = entry
        index[key] = rows

    raw = json.dumps(index, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        fetched = max(
            [kev_path.stat().st_mtime] + [path.stat().st_mtime for path in files]
        )
        fetched_at = datetime.fromtimestamp(fetched, timezone.utc).isoformat(timespec="seconds")
    except OSError:
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    stats = {
        "product_families": len(index),
        "entries": sum(len(rows) for rows in index.values()),
        "cves": len(seen),
        "kev_marked": sum(1 for rows in index.values() for e in rows.values() if e.get("k")),
        "rule_changed_by_update": changed,
        "rule_added_by_update": added,
        "cves_changed_by_update": len(affected),
        "cpe_matches_in_families": total_matches,
        "cpe_matches_with_update": update_matches,
        "update_on_range_only": update_range_only,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "gzip_bytes": len(gzip.compress(raw, 9)),
        "feeds": len(files),
        "fetched_at": fetched_at,
        "kev_count": len(kev_ids),
        "kev_catalog_version": str(kev_raw.get("catalogVersion") or ""),
        "kev_date_released": str(kev_raw.get("dateReleased") or ""),
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return raw, stats


_NOTICE = """\
Offline web-CVE index -- data sources and attribution
=====================================================

CISA Known Exploited Vulnerabilities (KEV)
  Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  License: CC0 1.0 (https://creativecommons.org/publicdomain/zero/1.0/)
  This build only copies the CVE identifier and its exploited-in-the-wild
  flag; the catalogue text is not redistributed.

NVD CVE feeds, CPE match data
  Source: https://nvd.nist.gov/feeds/json/cve/2.0/
  NIST states that information presented on NIST sites is public information
  and may be distributed or copied, and requests an appropriate byline or
  source credit.  This file is that credit.

The index contains derived version expressions only.  It is a build-time
snapshot and is never refreshed over the network by the agent.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--feeds",
        type=Path,
        default=ROOT / "ctfwork" / "kev_probe" / "nvd",
        help="directory holding nvdcve-2.0-*.json.gz",
    )
    parser.add_argument(
        "--kev",
        type=Path,
        default=ROOT / "ctfwork" / "kev_probe" / "kev.json",
        help="CISA KEV JSON snapshot",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "src" / "ctf_strix" / "aisec" / "data",
        help="output directory",
    )
    args = parser.parse_args(argv)

    raw, stats = build(args.feeds, args.kev)
    args.out.mkdir(parents=True, exist_ok=True)
    _atomic_write(args.out / "web_cve_index.json", raw)
    manifest = {
        "catalogVersion": stats["kev_catalog_version"],
        "fetched_at": stats["fetched_at"],
        "kev_released": stats["kev_date_released"],
        "built_at": stats["built_at"],
        "sha256": stats["sha256"],
        "bytes": stats["bytes"],
        "gzip_bytes": stats["gzip_bytes"],
        "product_families": stats["product_families"],
        "target_families": len(TARGETS),
        "entries": stats["entries"],
        "kev_marked": stats["kev_marked"],
        "nvd_feeds": stats["feeds"],
        "update_rule_changes": stats["rule_changed_by_update"],
        "update_rule_additions": stats["rule_added_by_update"],
        "update_affected_cves": stats["cves_changed_by_update"],
        "source": {
            "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "nvd": "https://nvd.nist.gov/feeds/json/cve/2.0/",
        },
    }
    _atomic_write(
        args.out / "manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
    )
    _atomic_write(args.out / "NOTICE", _NOTICE.encode("utf-8"))

    for key, value in stats.items():
        print(f"{key}: {value}")
    print(f"index: {args.out / 'web_cve_index.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
