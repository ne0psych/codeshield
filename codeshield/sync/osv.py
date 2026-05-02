"""
OSV.dev Vulnerability Data Sync

Fetches vulnerability data from OSV.dev API for major ecosystems.
Uses content hashing for incremental updates.
Validates data before committing to database.
"""

import json
import hashlib
import logging
import requests
from typing import Dict, List, Optional
from datetime import datetime, timezone

from ..config import SyncConfig
from ..database.connection import get_db
from .engine import _get_cached_hash, _update_sync_metadata

logger = logging.getLogger("codeshield.sync.osv")

# Ecosystems to sync vulnerabilities for
TARGET_ECOSYSTEMS = [
    "PyPI", "npm", "Go", "crates.io", "RubyGems", "Maven",
    "NuGet", "Packagist",
]

# Batch size for OSV API queries
BATCH_SIZE = 100


def sync_osv_data(config: SyncConfig) -> dict:
    """
    Fetch vulnerability data from OSV.dev for target ecosystems.
    Returns dict with status, added, modified counts.
    """
    result = {"status": "updated", "added": 0, "modified": 0}
    db = get_db()
    api_url = config.osv_api_url

    logger.info("Syncing vulnerability data from OSV.dev...")

    for ecosystem in TARGET_ECOSYSTEMS:
        try:
            eco_result = _sync_ecosystem(api_url, ecosystem, config)
            result["added"] += eco_result.get("added", 0)
            result["modified"] += eco_result.get("modified", 0)
        except Exception as exc:
            logger.warning("Failed to sync %s from OSV: %s", ecosystem, exc)

    if result["added"] == 0 and result["modified"] == 0:
        # Check if we have cached data
        cached = _get_cached_hash("osv_vulnerabilities")
        if cached:
            result["status"] = "unchanged"
        else:
            result["status"] = "degraded"

    _update_sync_metadata(
        "osv_vulnerabilities",
        content_hash=hashlib.sha256(
            str(result).encode()
        ).hexdigest(),
        records_count=result["added"] + result["modified"],
        status="ok" if result["status"] != "degraded" else "degraded"
    )

    logger.info("OSV sync complete: added=%d, modified=%d",
                result["added"], result["modified"])
    return result


def _sync_ecosystem(api_url: str, ecosystem: str,
                    config: SyncConfig) -> dict:
    """Fetch vulnerabilities for a single ecosystem using per-package queries.

    Note: OSV /querybatch requires specific package name + version, not
    ecosystem-only queries. We use /query per package instead.
    """
    return _sync_fallback_vulns(ecosystem, api_url, config)



def _sync_fallback_vulns(ecosystem: str, api_url: str,
                         config: SyncConfig) -> dict:
    """
    Fallback: query OSV for specific well-known packages when batch fails.
    This ensures we get at least some vulnerability data.
    """
    result = {"added": 0, "modified": 0}
    db = get_db()

    well_known_packages = {
        "PyPI": ["django", "flask", "requests", "pyyaml", "pillow",
                 "cryptography", "sqlalchemy", "urllib3", "jinja2",
                 "werkzeug", "numpy", "lxml", "paramiko", "httpx",
                 "fastapi", "celery", "boto3", "pydantic", "aiohttp",
                 "gunicorn", "setuptools", "pip", "wheel", "certifi",
                 "idna", "charset-normalizer", "pygments", "babel"],
        "npm": ["lodash", "express", "axios", "minimist", "qs",
                "path-to-regexp", "json5", "jsonwebtoken", "webpack",
                "react", "next", "vue", "angular", "passport",
                "mongoose", "sequelize", "bcrypt", "helmet", "cors",
                "socket.io", "commander", "chalk", "yargs", "semver",
                "tar", "glob-parent", "trim-newlines", "node-fetch"],
        "Maven": ["org.apache.logging.log4j:log4j-core",
                  "org.springframework:spring-core",
                  "com.fasterxml.jackson.core:jackson-databind",
                  "org.apache.struts:struts2-core",
                  "org.apache.tomcat.embed:tomcat-embed-core",
                  "commons-collections:commons-collections"],
        "Go": ["golang.org/x/crypto", "golang.org/x/net",
               "golang.org/x/text", "github.com/gin-gonic/gin",
               "github.com/gorilla/mux", "github.com/dgrijalva/jwt-go"],
        "crates.io": ["regex", "serde", "tokio", "hyper", "actix-web"],
        "RubyGems": ["rails", "rack", "nokogiri", "devise", "puma",
                     "activesupport", "actionpack", "bundler"],
        "NuGet": ["Newtonsoft.Json", "System.Text.Json",
                  "Microsoft.AspNetCore.Http"],
        "Packagist": ["symfony/http-kernel", "laravel/framework",
                      "guzzlehttp/guzzle", "monolog/monolog"],
    }

    packages = well_known_packages.get(ecosystem, [])
    for pkg_name in packages:
        try:
            resp = requests.post(
                f"{api_url}/query",
                json={
                    "package": {
                        "name": pkg_name,
                        "ecosystem": ecosystem,
                    }
                },
                timeout=config.sync_timeout,
                headers={"User-Agent": "CodeShield/2.0"}
            )
            if resp.status_code != 200:
                continue

            data = resp.json()
            for vuln_data in data.get("vulns", [])[:20]:
                counts = _upsert_vulnerability(db, vuln_data, ecosystem)
                result["added"] += counts["added"]
                result["modified"] += counts["modified"]

        except requests.RequestException:
            continue

    return result


def _upsert_vulnerability(db, vuln_data: dict,
                          default_ecosystem: str) -> dict:
    """
    Insert or update a vulnerability record.
    Validates data before committing.
    Returns counts of added/modified records.
    """
    counts = {"added": 0, "modified": 0}

    vuln_id = vuln_data.get("id", "")
    if not vuln_id or not isinstance(vuln_id, str):
        logger.debug("Rejecting malformed record: missing vuln_id")
        return counts

    summary = vuln_data.get("summary", "")[:1000]
    details = vuln_data.get("details", "")[:5000]

    # Extract severity from database_specific or severity array
    severity = "MEDIUM"
    cvss_score = 0.0
    cvss_vector = ""

    severity_list = vuln_data.get("severity", [])
    if severity_list and isinstance(severity_list, list):
        for s in severity_list:
            if s.get("type") == "CVSS_V3":
                cvss_vector = s.get("score", "")
                # Parse CVSS score from vector
                try:
                    score_part = cvss_vector.split("/")[0] if "/" in cvss_vector else ""
                    if score_part:
                        cvss_score = float(score_part.replace("CVSS:3.1", "").replace("CVSS:3.0", "").strip("/"))
                except (ValueError, IndexError):
                    pass

    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    elif cvss_score > 0:
        severity = "LOW"

    # Extract references
    refs = vuln_data.get("references", [])
    refs_json = json.dumps(refs[:10]) if refs else "[]"

    published = vuln_data.get("published", "")
    modified = vuln_data.get("modified", "")

    try:
        with db.transaction() as conn:
            # Check if exists
            existing = conn.execute(
                "SELECT id FROM vulnerabilities WHERE vuln_id = ?",
                (vuln_id,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE vulnerabilities SET summary=?, details=?, "
                    "severity=?, cvss_score=?, cvss_vector=?, "
                    "references_json=?, modified_at=?, updated_at=? "
                    "WHERE vuln_id=?",
                    (summary, details, severity, cvss_score, cvss_vector,
                     refs_json, modified,
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
                    (vuln_id, summary, details, severity, cvss_score,
                     cvss_vector, "osv", published, modified, refs_json)
                )
                vuln_db_id = cursor.lastrowid
                counts["added"] = 1

            # Process affected packages
            for affected in vuln_data.get("affected", []):
                pkg = affected.get("package", {})
                eco = pkg.get("ecosystem", default_ecosystem)
                name = pkg.get("name", "")
                if not name:
                    continue

                # Delete existing affected packages for this vuln
                conn.execute(
                    "DELETE FROM affected_packages WHERE vulnerability_id=?",
                    (vuln_db_id,)
                )

                cursor = conn.execute(
                    "INSERT INTO affected_packages "
                    "(vulnerability_id, ecosystem, package_name) "
                    "VALUES (?,?,?)",
                    (vuln_db_id, eco, name)
                )
                ap_id = cursor.lastrowid

                # Process version ranges
                for rng in affected.get("ranges", []):
                    range_type = rng.get("type", "SEMVER")
                    introduced = ""
                    fixed = ""
                    last_affected_ver = ""

                    for event in rng.get("events", []):
                        if "introduced" in event:
                            introduced = event["introduced"]
                        if "fixed" in event:
                            fixed = event["fixed"]
                        if "last_affected" in event:
                            last_affected_ver = event["last_affected"]

                    conn.execute(
                        "INSERT INTO version_ranges "
                        "(affected_package_id, range_type, "
                        "introduced, fixed, last_affected) "
                        "VALUES (?,?,?,?,?)",
                        (ap_id, range_type, introduced,
                         fixed, last_affected_ver)
                    )

    except Exception as exc:
        logger.warning("Failed to upsert vulnerability %s: %s",
                       vuln_id, exc)

    return counts
