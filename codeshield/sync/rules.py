"""
Remote Rules Sync

Fetches SAST rules and secrets patterns from configurable remote JSON sources.
Validates schema before committing to database.
Uses content hashing for incremental updates.
"""

import json
import hashlib
import logging
import requests
from typing import Dict

from ..config import SyncConfig
from ..database.connection import get_db
from .engine import _get_cached_hash, _update_sync_metadata

logger = logging.getLogger("codeshield.sync.rules")

# Required fields for SAST rules
SAST_REQUIRED_FIELDS = {"rule_id", "title", "pattern", "severity"}

# Required fields for secrets patterns
SECRETS_REQUIRED_FIELDS = {"pattern_id", "name", "pattern", "severity"}


def sync_remote_rules(config: SyncConfig, rule_type: str) -> dict:
    """
    Fetch and sync remote rules (SAST or secrets patterns).

    Args:
        config: Sync configuration
        rule_type: "sast" or "secrets"

    Returns:
        dict with status, added, modified counts
    """
    if rule_type == "sast":
        url = config.sast_rules_url
        source_name = "remote_sast_rules"
    else:
        url = config.secrets_patterns_url
        source_name = "remote_secrets_patterns"

    if not url:
        return {"status": "unchanged", "added": 0, "modified": 0}

    result = {"status": "updated", "added": 0, "modified": 0}

    logger.info("Fetching remote %s rules from %s", rule_type, url)

    try:
        # Fetch with timeout and retry
        response = _fetch_with_retry(url, config.sync_timeout)
        data = response.json()

    except Exception as exc:
        logger.warning("Failed to fetch remote %s rules: %s",
                       rule_type, exc)
        cached = _get_cached_hash(source_name)
        status = "unchanged" if cached else "degraded"
        return {"status": status, "added": 0, "modified": 0}

    # Validate response is a list of rules
    if not isinstance(data, list):
        # Try extracting from a wrapper object
        if isinstance(data, dict):
            data = data.get("rules", data.get("patterns", []))
        if not isinstance(data, list):
            logger.error("Invalid remote rules format: expected array")
            return {"status": "degraded", "added": 0, "modified": 0}

    # Content hash check
    content_hash = hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()

    cached_hash = _get_cached_hash(source_name)
    if cached_hash == content_hash:
        logger.info("Remote %s rules unchanged", rule_type)
        return {"status": "unchanged", "added": 0, "modified": 0}

    # Process and validate each rule
    if rule_type == "sast":
        result = _sync_sast_rules(data)
    else:
        result = _sync_secrets_patterns(data)

    _update_sync_metadata(
        source_name,
        content_hash=content_hash,
        records_count=result["added"] + result["modified"],
    )

    return result


def _fetch_with_retry(url: str, timeout: int,
                      max_retries: int = 3) -> requests.Response:
    """Fetch URL with retry logic and timeout."""
    last_exc = None
    for attempt in range(max_retries):
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "CodeShield/2.0"}
            )
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                logger.debug("Retry %d/%d for %s: %s",
                             attempt + 1, max_retries, url, exc)
    raise last_exc


def _sync_sast_rules(rules: list) -> dict:
    """Validate and sync SAST rules to database."""
    result = {"status": "updated", "added": 0, "modified": 0}
    db = get_db()

    with db.transaction() as conn:
        for rule in rules:
            # Validate required fields
            if not SAST_REQUIRED_FIELDS.issubset(rule.keys()):
                missing = SAST_REQUIRED_FIELDS - set(rule.keys())
                logger.debug("Skipping malformed SAST rule: missing %s",
                             missing)
                continue

            rule_id = str(rule["rule_id"]).strip()
            if not rule_id:
                continue

            existing = conn.execute(
                "SELECT id FROM sast_rules WHERE rule_id = ?",
                (rule_id,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE sast_rules SET title=?, pattern=?, "
                    "language=?, severity=?, cwe_id=?, "
                    "owasp_category=?, description=?, remediation=? "
                    "WHERE rule_id=?",
                    (rule.get("title", ""), rule["pattern"],
                     rule.get("language", "*"), rule["severity"],
                     rule.get("cwe_id", ""),
                     rule.get("owasp_category", ""),
                     rule.get("description", ""),
                     rule.get("remediation", ""),
                     rule_id)
                )
                result["modified"] += 1
            else:
                conn.execute(
                    "INSERT INTO sast_rules "
                    "(rule_id, title, pattern, language, severity, "
                    "cwe_id, owasp_category, description, remediation) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (rule_id, rule.get("title", ""), rule["pattern"],
                     rule.get("language", "*"), rule["severity"],
                     rule.get("cwe_id", ""),
                     rule.get("owasp_category", ""),
                     rule.get("description", ""),
                     rule.get("remediation", ""))
                )
                result["added"] += 1

    return result


def _sync_secrets_patterns(patterns: list) -> dict:
    """Validate and sync secrets patterns to database."""
    result = {"status": "updated", "added": 0, "modified": 0}
    db = get_db()

    with db.transaction() as conn:
        for pat in patterns:
            if not SECRETS_REQUIRED_FIELDS.issubset(pat.keys()):
                missing = SECRETS_REQUIRED_FIELDS - set(pat.keys())
                logger.debug("Skipping malformed secrets pattern: missing %s",
                             missing)
                continue

            pid = str(pat["pattern_id"]).strip()
            if not pid:
                continue

            existing = conn.execute(
                "SELECT id FROM secrets_patterns WHERE pattern_id = ?",
                (pid,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE secrets_patterns SET name=?, pattern=?, "
                    "severity=?, description=?, entropy_threshold=? "
                    "WHERE pattern_id=?",
                    (pat.get("name", ""), pat["pattern"],
                     pat["severity"], pat.get("description", ""),
                     pat.get("entropy_threshold", 0.0), pid)
                )
                result["modified"] += 1
            else:
                conn.execute(
                    "INSERT INTO secrets_patterns "
                    "(pattern_id, name, pattern, severity, "
                    "description, entropy_threshold) "
                    "VALUES (?,?,?,?,?,?)",
                    (pid, pat.get("name", ""), pat["pattern"],
                     pat["severity"], pat.get("description", ""),
                     pat.get("entropy_threshold", 0.0))
                )
                result["added"] += 1

    return result
