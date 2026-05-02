"""
GitHub Advisory Database Sync

Fetches security advisories from GitHub's GraphQL API.
Docs: https://docs.github.com/en/graphql/reference/objects#securityadvisory
- Requires GITHUB_TOKEN env var for authentication.
- Paginates via cursor-based pagination.
- Maps to unified vulnerability schema.
"""

import os
import json
import hashlib
import logging
import requests
from datetime import datetime, timezone, timedelta

from ..config import SyncConfig
from ..database.connection import get_db
from .engine import _get_cached_hash, _update_sync_metadata

logger = logging.getLogger("codeshield.sync.github_advisory")

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

ADVISORY_QUERY = """
query($first: Int!, $after: String, $updatedSince: DateTime) {
  securityAdvisories(first: $first, after: $after, updatedSince: $updatedSince, orderBy: {field: UPDATED_AT, direction: DESC}) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      references { url }
      identifiers { type value }
      vulnerabilities(first: 25) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH",
    "MODERATE": "MEDIUM", "LOW": "LOW",
}


def sync_github_advisories(config: SyncConfig) -> dict:
    """Fetch advisories from GitHub Advisory Database via GraphQL."""
    result = {"status": "updated", "added": 0, "modified": 0}
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        logger.info("GITHUB_TOKEN not set, skipping GitHub Advisory sync")
        return {"status": "unchanged", "added": 0, "modified": 0}

    db = get_db()
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "CodeShield/2.1",
    }

    # Incremental: get advisories updated since last sync
    last_sync = _get_last_github_sync()
    updated_since = last_sync if last_sync else (
        datetime.now(timezone.utc) - timedelta(days=90)
    ).isoformat()

    logger.info("Syncing GitHub Advisory Database (since %s)...", updated_since[:10])

    has_next = True
    cursor = None
    page = 0

    while has_next and page < 10:
        variables = {"first": 100, "after": cursor, "updatedSince": updated_since}

        try:
            resp = requests.post(
                GITHUB_GRAPHQL_URL,
                json={"query": ADVISORY_QUERY, "variables": variables},
                headers=headers,
                timeout=config.sync_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.warning("GitHub Advisory API failed: %s", exc)
            break

        if "errors" in data:
            logger.warning("GitHub GraphQL errors: %s", data["errors"])
            break

        advisories_data = data.get("data", {}).get("securityAdvisories", {})
        page_info = advisories_data.get("pageInfo", {})
        nodes = advisories_data.get("nodes", [])

        for advisory in nodes:
            counts = _upsert_advisory(db, advisory)
            result["added"] += counts["added"]
            result["modified"] += counts["modified"]

        has_next = page_info.get("hasNextPage", False)
        cursor = page_info.get("endCursor")
        page += 1

    _update_sync_metadata(
        "github_advisories",
        content_hash=hashlib.sha256(str(result).encode()).hexdigest(),
        records_count=result["added"] + result["modified"],
        status="ok",
    )

    logger.info("GitHub Advisory sync complete: added=%d, modified=%d",
                result["added"], result["modified"])
    return result


def _get_last_github_sync():
    db = get_db()
    row = db.fetchone(
        "SELECT last_sync_at FROM sync_metadata WHERE source_name = ?",
        ("github_advisories",)
    )
    return row["last_sync_at"] if row and row["last_sync_at"] else None


def _upsert_advisory(db, advisory: dict) -> dict:
    """Insert or update a GitHub security advisory."""
    counts = {"added": 0, "modified": 0}

    ghsa_id = advisory.get("ghsaId", "")
    if not ghsa_id:
        return counts

    summary = advisory.get("summary", "")[:1000]
    description = advisory.get("description", "")[:5000]
    severity = SEVERITY_MAP.get(advisory.get("severity", ""), "MEDIUM")
    published = advisory.get("publishedAt", "")
    modified = advisory.get("updatedAt", "")

    # Extract CVE from identifiers
    cve_id = ""
    for ident in advisory.get("identifiers", []):
        if ident.get("type") == "CVE":
            cve_id = ident.get("value", "")
            break

    # Use CVE ID as primary key if available, otherwise GHSA ID
    vuln_id = cve_id if cve_id else ghsa_id

    refs = [{"url": r.get("url", "")} for r in advisory.get("references", [])[:10]]
    refs_json = json.dumps(refs)

    try:
        with db.transaction() as conn:
            existing = conn.execute(
                "SELECT id FROM vulnerabilities WHERE vuln_id = ?",
                (vuln_id,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE vulnerabilities SET summary=?, details=?, "
                    "severity=?, references_json=?, modified_at=?, "
                    "updated_at=? WHERE vuln_id=?",
                    (summary, description, severity, refs_json, modified,
                     datetime.now(timezone.utc).isoformat(), vuln_id)
                )
                vuln_db_id = existing["id"]
                counts["modified"] = 1
            else:
                cursor = conn.execute(
                    "INSERT INTO vulnerabilities "
                    "(vuln_id, summary, details, severity, cvss_score, "
                    "cvss_vector, source, published_at, modified_at, "
                    "references_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (vuln_id, summary, description, severity, 0.0,
                     "", "github", published, modified, refs_json)
                )
                vuln_db_id = cursor.lastrowid
                counts["added"] = 1

            # Process affected packages
            vuln_nodes = advisory.get("vulnerabilities", {}).get("nodes", [])
            for vuln in vuln_nodes:
                pkg = vuln.get("package", {})
                name = pkg.get("name", "")
                ecosystem = pkg.get("ecosystem", "")
                if not name:
                    continue

                cursor = conn.execute(
                    "INSERT INTO affected_packages "
                    "(vulnerability_id, ecosystem, package_name) "
                    "VALUES (?,?,?)",
                    (vuln_db_id, ecosystem, name)
                )
                ap_id = cursor.lastrowid

                version_range = vuln.get("vulnerableVersionRange", "")
                fixed_ver = ""
                patched = vuln.get("firstPatchedVersion")
                if patched:
                    fixed_ver = patched.get("identifier", "")

                introduced = ""
                if version_range:
                    # Parse ">= 1.0, < 2.0" format
                    parts = version_range.split(",")
                    for part in parts:
                        part = part.strip()
                        if part.startswith(">="):
                            introduced = part[2:].strip()
                        elif part.startswith(">"):
                            introduced = part[1:].strip()

                conn.execute(
                    "INSERT INTO version_ranges "
                    "(affected_package_id, range_type, introduced, fixed) "
                    "VALUES (?,?,?,?)",
                    (ap_id, "SEMVER", introduced, fixed_ver)
                )

    except Exception as exc:
        logger.debug("Failed to upsert advisory %s: %s", vuln_id, exc)

    return counts
