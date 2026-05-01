"""
SPDX License List Sync

Fetches the official SPDX license list and normalizes it into the
local database. Uses content hashing for incremental updates.
"""

import json
import hashlib
import logging
import requests
from typing import Dict

from ..config import SyncConfig
from ..database.connection import get_db
from .engine import _get_cached_hash, _update_sync_metadata

logger = logging.getLogger("codeshield.sync.spdx")

# License category classification based on SPDX properties
_COPYLEFT_IDS = frozenset({
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later",
})
_WEAK_COPYLEFT_IDS = frozenset({
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
    "LGPL-3.0-or-later", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0",
})


def _classify_license(spdx_id: str, is_osi: bool, is_fsf: bool) -> str:
    """Classify a license by category based on known properties."""
    if spdx_id in _COPYLEFT_IDS:
        return "strong_copyleft"
    if spdx_id in _WEAK_COPYLEFT_IDS:
        return "weak_copyleft"
    if is_osi:
        return "permissive"
    if is_fsf:
        return "permissive"
    return "unknown"


def sync_spdx_data(config: SyncConfig) -> dict:
    """
    Fetch SPDX license list and sync to local database.
    Returns dict with status, added, modified counts.
    """
    result = {"status": "updated", "added": 0, "modified": 0}
    db = get_db()

    logger.info("Syncing SPDX license list...")

    try:
        response = requests.get(
            config.spdx_url,
            timeout=config.sync_timeout,
            headers={"User-Agent": "CodeShield/2.0"}
        )
        response.raise_for_status()
        data = response.json()

    except requests.RequestException as exc:
        logger.warning("SPDX fetch failed: %s", exc)
        cached = _get_cached_hash("spdx_licenses")
        if cached:
            return {"status": "unchanged", "added": 0, "modified": 0}
        return {"status": "degraded", "added": 0, "modified": 0}

    # Validate data structure
    if not isinstance(data, dict) or "licenses" not in data:
        logger.error("Invalid SPDX data format — missing 'licenses' key")
        return {"status": "degraded", "added": 0, "modified": 0}

    # Content hash for incremental check
    content_hash = hashlib.sha256(
        json.dumps(data["licenses"], sort_keys=True).encode()
    ).hexdigest()

    cached_hash = _get_cached_hash("spdx_licenses")
    if cached_hash == content_hash:
        logger.info("SPDX data unchanged (hash match)")
        return {"status": "unchanged", "added": 0, "modified": 0}

    # Process licenses
    licenses = data.get("licenses", [])
    logger.info("Processing %d SPDX licenses", len(licenses))

    with db.transaction() as conn:
        for lic in licenses:
            # Validate required fields
            spdx_id = lic.get("licenseId", "")
            name = lic.get("name", "")
            if not spdx_id or not isinstance(spdx_id, str):
                logger.debug("Skipping malformed license record: %s", lic)
                continue

            is_osi = bool(lic.get("isOsiApproved", False))
            is_fsf = bool(lic.get("isFsfLibre", False))
            ref_url = lic.get("reference", "")
            category = _classify_license(spdx_id, is_osi, is_fsf)

            # Upsert
            existing = conn.execute(
                "SELECT id FROM license_definitions WHERE spdx_id = ?",
                (spdx_id,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE license_definitions SET name=?, "
                    "is_osi_approved=?, is_fsf_libre=?, category=?, "
                    "reference_url=? WHERE spdx_id=?",
                    (name, int(is_osi), int(is_fsf), category,
                     ref_url, spdx_id)
                )
                result["modified"] += 1
            else:
                conn.execute(
                    "INSERT INTO license_definitions "
                    "(spdx_id, name, is_osi_approved, is_fsf_libre, "
                    "category, reference_url) VALUES (?,?,?,?,?,?)",
                    (spdx_id, name, int(is_osi), int(is_fsf),
                     category, ref_url)
                )
                result["added"] += 1

    _update_sync_metadata(
        "spdx_licenses",
        content_hash=content_hash,
        records_count=result["added"] + result["modified"],
    )

    logger.info("SPDX sync complete: added=%d, modified=%d",
                result["added"], result["modified"])
    return result
