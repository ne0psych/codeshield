"""
OSS Index Sync (Sonatype)

Docs: https://ossindex.sonatype.org/doc/rest
- Free tier: 128 components per batch, 8 requests/minute.
- Uses Package URL (purl) for querying.
- No API key required for basic usage.
"""

import time
import json
import hashlib
import logging
import requests
from datetime import datetime, timezone

from ..config import SyncConfig
from ..database.connection import get_db
from .engine import _update_sync_metadata

logger = logging.getLogger("codeshield.sync.ossindex")

OSSINDEX_API_URL = "https://ossindex.sonatype.org/api/v3/component-report"
BATCH_SIZE = 128
RATE_LIMIT_DELAY = 8  # seconds between batch requests


def sync_ossindex_data(config: SyncConfig) -> dict:
    """
    Query OSS Index for known vulnerabilities using purls from our DB.
    This enriches existing SBOM components with vulnerability data.
    """
    result = {"status": "updated", "added": 0, "modified": 0}
    db = get_db()

    logger.info("Enriching vulnerability data from OSS Index...")

    # Get all unique packages from affected_packages table
    rows = db.fetchall(
        "SELECT DISTINCT package_name, ecosystem FROM affected_packages "
        "LIMIT 500"
    )

    if not rows:
        logger.info("No packages to query against OSS Index")
        return {"status": "unchanged", "added": 0, "modified": 0}

    # Build purls from existing packages
    purls = []
    for row in rows:
        purl = _make_purl(row["ecosystem"], row["package_name"])
        if purl:
            purls.append(purl)

    # Batch query
    for i in range(0, len(purls), BATCH_SIZE):
        batch = purls[i:i + BATCH_SIZE]
        try:
            resp = requests.post(
                OSSINDEX_API_URL,
                json={"coordinates": batch},
                headers={
                    "User-Agent": "CodeShield/2.1",
                    "Content-Type": "application/json",
                },
                timeout=config.sync_timeout,
            )
            resp.raise_for_status()
            components = resp.json()

            for component in components:
                vulns = component.get("vulnerabilities", [])
                for vuln in vulns:
                    counts = _upsert_ossindex_vuln(db, vuln, component)
                    result["added"] += counts["added"]
                    result["modified"] += counts["modified"]

        except requests.RequestException as exc:
            logger.warning("OSS Index batch request failed: %s", exc)

        if i + BATCH_SIZE < len(purls):
            time.sleep(RATE_LIMIT_DELAY)

    _update_sync_metadata(
        "ossindex",
        content_hash=hashlib.sha256(str(result).encode()).hexdigest(),
        records_count=result["added"] + result["modified"],
        status="ok",
    )

    logger.info("OSS Index sync complete: added=%d, modified=%d",
                result["added"], result["modified"])
    return result


def _make_purl(ecosystem: str, package_name: str) -> str:
    """Convert ecosystem + package_name to Package URL."""
    eco_map = {
        "PyPI": "pypi", "npm": "npm", "Maven": "maven",
        "Go": "golang", "crates.io": "cargo", "RubyGems": "gem",
        "NuGet": "nuget", "Packagist": "composer",
    }
    purl_type = eco_map.get(ecosystem, "")
    if not purl_type or not package_name:
        return ""
    # Maven uses group:artifact format
    if purl_type == "maven" and ":" in package_name:
        parts = package_name.split(":", 1)
        return f"pkg:{purl_type}/{parts[0]}/{parts[1]}"
    return f"pkg:{purl_type}/{package_name}"


def _upsert_ossindex_vuln(db, vuln: dict, component: dict) -> dict:
    """Insert or update a vulnerability from OSS Index."""
    counts = {"added": 0, "modified": 0}

    vuln_id = vuln.get("id", "")
    if not vuln_id:
        return counts

    title = vuln.get("title", "")[:1000]
    description = vuln.get("description", "")[:5000]
    cvss_score = vuln.get("cvssScore", 0.0)
    cvss_vector = vuln.get("cvssVector", "")
    reference = vuln.get("reference", "")

    # Determine severity from CVSS
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    elif cvss_score > 0:
        severity = "LOW"
    else:
        severity = "MEDIUM"

    # Extract CVE from reference URL if present
    cve_id = ""
    if reference and "CVE-" in reference:
        import re
        m = re.search(r'(CVE-\d{4}-\d+)', reference)
        if m:
            cve_id = m.group(1)

    actual_id = cve_id if cve_id else f"OSSINDEX-{vuln_id[-12:]}"

    refs_json = json.dumps([{"url": reference}]) if reference else "[]"

    try:
        with db.transaction() as conn:
            existing = conn.execute(
                "SELECT id FROM vulnerabilities WHERE vuln_id = ?",
                (actual_id,)
            ).fetchone()

            if existing:
                # Only update CVSS if OSS Index has a score and existing doesn't
                conn.execute(
                    "UPDATE vulnerabilities SET cvss_score = MAX(cvss_score, ?), "
                    "cvss_vector = CASE WHEN cvss_vector = '' THEN ? ELSE cvss_vector END, "
                    "updated_at = ? WHERE vuln_id = ?",
                    (cvss_score, cvss_vector,
                     datetime.now(timezone.utc).isoformat(), actual_id)
                )
                counts["modified"] = 1
            else:
                conn.execute(
                    "INSERT INTO vulnerabilities "
                    "(vuln_id, summary, details, severity, cvss_score, "
                    "cvss_vector, source, references_json) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (actual_id, title, description, severity, cvss_score,
                     cvss_vector, "ossindex", refs_json)
                )
                counts["added"] = 1

    except Exception as exc:
        logger.debug("Failed to upsert OSS Index vuln %s: %s", actual_id, exc)

    return counts
