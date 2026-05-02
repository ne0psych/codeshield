"""
NVD (National Vulnerability Database) Sync

Fetches CVE data from NVD REST API v2.0.
Docs: https://nvd.nist.gov/developers/vulnerabilities
- Supports API key for higher rate limits (50 req/30s vs 5 req/30s).
- Uses lastModStartDate/lastModEndDate for incremental sync.
- Normalizes into unified vulnerability schema.
"""

import time
import json
import hashlib
import logging
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

from ..config import SyncConfig
from ..database.connection import get_db
from .engine import _get_cached_hash, _update_sync_metadata

logger = logging.getLogger("codeshield.sync.nvd")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS_PER_PAGE = 200
RATE_LIMIT_DELAY_NO_KEY = 6.5   # seconds between requests without API key
RATE_LIMIT_DELAY_WITH_KEY = 0.6  # seconds with API key


def sync_nvd_data(config: SyncConfig) -> dict:
    """
    Fetch CVE data from NVD API v2.0 with incremental sync.
    Returns dict with status, added, modified counts.
    """
    result = {"status": "updated", "added": 0, "modified": 0}
    db = get_db()
    api_key = config.nvd_api_key

    logger.info("Syncing vulnerability data from NVD API v2.0...")

    # Determine date range for incremental sync
    last_sync = _get_last_nvd_sync()
    if last_sync:
        start_date = last_sync
        logger.info("NVD incremental sync from %s", start_date)
    else:
        # First sync: fetch last 90 days only to avoid long startup
        start_date = (datetime.now(timezone.utc) - timedelta(days=90)).strftime(
            "%Y-%m-%dT%H:%M:%S.000"
        )
        logger.info("NVD initial sync (last 90 days)")

    end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    delay = RATE_LIMIT_DELAY_WITH_KEY if api_key else RATE_LIMIT_DELAY_NO_KEY

    start_index = 0
    total_results = None
    page = 0

    while True:
        params = {
            "lastModStartDate": start_date,
            "lastModEndDate": end_date,
            "resultsPerPage": MAX_RESULTS_PER_PAGE,
            "startIndex": start_index,
        }
        headers = {"User-Agent": "CodeShield/2.1"}
        if api_key:
            headers["apiKey"] = api_key

        try:
            resp = requests.get(
                NVD_API_URL, params=params, headers=headers,
                timeout=config.sync_timeout,
            )
            if resp.status_code == 403:
                logger.warning("NVD rate limit hit, backing off 30s...")
                time.sleep(30)
                continue
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.warning("NVD API request failed: %s", exc)
            break

        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info("NVD reports %d total CVEs to sync", total_results)

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve = item.get("cve", {})
            counts = _upsert_nvd_cve(db, cve)
            result["added"] += counts["added"]
            result["modified"] += counts["modified"]

        page += 1
        start_index += MAX_RESULTS_PER_PAGE
        if start_index >= total_results:
            break

        # Rate limit compliance
        time.sleep(delay)

        # Safety cap: max 10 pages per sync to avoid blocking startup
        if page >= 10:
            logger.info("NVD sync capped at %d pages, will continue next startup", page)
            break

    _update_sync_metadata(
        "nvd_vulnerabilities",
        content_hash=hashlib.sha256(str(result).encode()).hexdigest(),
        records_count=result["added"] + result["modified"],
        status="ok",
    )

    logger.info("NVD sync complete: added=%d, modified=%d",
                result["added"], result["modified"])
    return result


def _get_last_nvd_sync() -> Optional[str]:
    """Get the timestamp of the last NVD sync."""
    db = get_db()
    row = db.fetchone(
        "SELECT last_sync_at FROM sync_metadata WHERE source_name = ?",
        ("nvd_vulnerabilities",)
    )
    if row and row["last_sync_at"]:
        return row["last_sync_at"].replace("Z", "").split("+")[0]
    return None


def _upsert_nvd_cve(db, cve: dict) -> dict:
    """Insert or update a CVE from NVD data."""
    counts = {"added": 0, "modified": 0}

    cve_id = cve.get("id", "")
    if not cve_id:
        return counts

    # Extract description (English preferred)
    descriptions = cve.get("descriptions", [])
    summary = ""
    for d in descriptions:
        if d.get("lang") == "en":
            summary = d.get("value", "")[:1000]
            break
    if not summary and descriptions:
        summary = descriptions[0].get("value", "")[:1000]

    # Extract CVSS v3.1 score
    cvss_score = 0.0
    cvss_vector = ""
    severity = "MEDIUM"
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            break

    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    elif cvss_score > 0:
        severity = "LOW"

    # Extract references
    refs = cve.get("references", [])
    refs_json = json.dumps(refs[:10]) if refs else "[]"

    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    try:
        with db.transaction() as conn:
            existing = conn.execute(
                "SELECT id FROM vulnerabilities WHERE vuln_id = ?",
                (cve_id,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE vulnerabilities SET summary=?, severity=?, "
                    "cvss_score=?, cvss_vector=?, references_json=?, "
                    "modified_at=?, updated_at=? WHERE vuln_id=?",
                    (summary, severity, cvss_score, cvss_vector,
                     refs_json, modified,
                     datetime.now(timezone.utc).isoformat(), cve_id)
                )
                counts["modified"] = 1
            else:
                conn.execute(
                    "INSERT INTO vulnerabilities "
                    "(vuln_id, summary, details, severity, cvss_score, "
                    "cvss_vector, source, published_at, modified_at, "
                    "references_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (cve_id, summary, "", severity, cvss_score,
                     cvss_vector, "nvd", published, modified, refs_json)
                )
                counts["added"] = 1

            # Process affected configurations (CPE)
            configurations = cve.get("configurations", [])
            if existing:
                vuln_db_id = existing["id"]
            else:
                row = conn.execute(
                    "SELECT id FROM vulnerabilities WHERE vuln_id = ?",
                    (cve_id,)
                ).fetchone()
                vuln_db_id = row["id"] if row else None

            if vuln_db_id and configurations:
                _process_nvd_configurations(conn, vuln_db_id, configurations)

    except Exception as exc:
        logger.debug("Failed to upsert NVD CVE %s: %s", cve_id, exc)

    return counts


def _process_nvd_configurations(conn, vuln_db_id: int, configurations: list):
    """Extract affected packages from NVD CPE configurations."""
    for config_node in configurations:
        for node in config_node.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                criteria = cpe_match.get("criteria", "")
                # Parse CPE 2.3: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue

                vendor = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                if not product or product == "*":
                    continue

                package_name = f"{vendor}:{product}" if vendor and vendor != "*" else product

                cursor = conn.execute(
                    "INSERT INTO affected_packages "
                    "(vulnerability_id, ecosystem, package_name) "
                    "VALUES (?,?,?)",
                    (vuln_db_id, "NVD", package_name)
                )
                ap_id = cursor.lastrowid

                introduced = cpe_match.get("versionStartIncluding", "")
                fixed = cpe_match.get("versionEndExcluding", "")
                if not fixed:
                    fixed = cpe_match.get("versionEndIncluding", "")

                if introduced or fixed:
                    conn.execute(
                        "INSERT INTO version_ranges "
                        "(affected_package_id, range_type, introduced, fixed) "
                        "VALUES (?,?,?,?)",
                        (ap_id, "CPE", introduced, fixed)
                    )
