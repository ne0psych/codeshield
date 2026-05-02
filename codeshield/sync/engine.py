"""
CodeShield Data Sync Engine
Orchestrates startup data synchronization from remote sources.
Uses ETags/content hashing for incremental updates.
Fails gracefully per source — cached data used when sources unavailable.

Sources:
  - OSV.dev (primary vulnerability data)
  - NVD (CVE/CVSS enrichment)
  - GitHub Advisory Database (GHSA advisories)
  - OSS Index (purl-based enrichment)
  - SPDX (license definitions)
  - Remote rules (SAST/secrets patterns)
"""

import time
import hashlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Callable, Optional
from datetime import datetime, timezone

from ..config import SyncConfig
from ..database.connection import get_db

logger = logging.getLogger("codeshield.sync")


class SyncReport:
    """Structured sync report tracking status of each source."""

    def __init__(self):
        self.sources: Dict[str, dict] = {}
        self.start_time = time.time()
        self.end_time = 0.0

    def add_source(self, name: str, status: str,
                   records_added: int = 0, records_modified: int = 0,
                   error: str = "") -> None:
        self.sources[name] = {
            "status": status,  # "updated", "unchanged", "degraded", "failed"
            "records_added": records_added,
            "records_modified": records_modified,
            "error": error,
        }

    def finalize(self) -> None:
        self.end_time = time.time()

    @property
    def duration(self) -> float:
        return round(self.end_time - self.start_time, 2)

    def log_report(self) -> None:
        logger.info("=" * 60)
        logger.info("DATA SYNC REPORT (%.1fs)", self.duration)
        logger.info("=" * 60)
        for name, info in self.sources.items():
            status_icon = {
                "updated": "[OK]", "unchanged": "[--]",
                "degraded": "[!!]", "failed": "[XX]"
            }.get(info["status"], "[??]")
            logger.info(
                "  %s %-24s status=%-10s added=%d modified=%d%s",
                status_icon, name, info["status"],
                info["records_added"], info["records_modified"],
                f" error={info['error']}" if info["error"] else ""
            )
        logger.info("=" * 60)


def _get_cached_hash(source_name: str) -> Optional[str]:
    """Get the cached content hash for a data source."""
    db = get_db()
    row = db.fetchone(
        "SELECT content_hash FROM sync_metadata WHERE source_name = ?",
        (source_name,)
    )
    return row["content_hash"] if row else None


def _update_sync_metadata(source_name: str, content_hash: str = "",
                          etag: str = "", records_count: int = 0,
                          status: str = "ok") -> None:
    """Update sync metadata for a source."""
    db = get_db()
    with db.transaction() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sync_metadata "
            "(source_name, content_hash, etag, records_count, "
            "status, last_sync_at) VALUES (?, ?, ?, ?, ?, ?)",
            (source_name, content_hash, etag, records_count,
             status, datetime.now(timezone.utc).isoformat())
        )


def run_sync(config: SyncConfig) -> SyncReport:
    """
    Run primary data sync (OSV + SPDX) at startup, then kick off
    background sync for NVD, GitHub Advisory, and OSS Index.
    Primary sources block startup; secondary sources run in background.
    """
    from .osv import sync_osv_data
    from .spdx import sync_spdx_data
    from .rules import sync_remote_rules

    report = SyncReport()

    if not config.enabled:
        logger.info("Data sync disabled by configuration")
        report.finalize()
        return report

    # ── Primary sync tasks (block startup) ──
    primary_tasks: Dict[str, Callable] = {
        "osv_vulnerabilities": lambda: sync_osv_data(config),
        "spdx_licenses": lambda: sync_spdx_data(config),
    }

    # Optional primary sources
    if config.sast_rules_url:
        primary_tasks["remote_sast_rules"] = lambda: sync_remote_rules(
            config, "sast"
        )
    if config.secrets_patterns_url:
        primary_tasks["remote_secrets_patterns"] = lambda: sync_remote_rules(
            config, "secrets"
        )

    logger.info("Starting data sync for %d sources...", len(primary_tasks))

    # Execute primary tasks concurrently
    max_workers = min(config.sync_concurrency, len(primary_tasks))
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        future_map = {
            pool.submit(func): name
            for name, func in primary_tasks.items()
        }

        for future in as_completed(future_map):
            name = future_map[future]
            try:
                result = future.result(timeout=config.sync_timeout)
                report.add_source(
                    name,
                    status=result.get("status", "updated"),
                    records_added=result.get("added", 0),
                    records_modified=result.get("modified", 0),
                )
            except Exception as exc:
                logger.error("Sync failed for %s: %s", name, exc)
                report.add_source(
                    name, status="failed", error=str(exc)
                )
                _update_sync_metadata(name, status="degraded")

    report.finalize()
    report.log_report()

    # ── Background sync tasks (don't block startup) ──
    _start_background_sync(config)

    return report


def _start_background_sync(config: SyncConfig):
    """Launch background thread for secondary data sources."""

    def _run():
        from .nvd import sync_nvd_data
        from .github_advisory import sync_github_advisories
        from .ossindex import sync_ossindex_data

        secondary_tasks = {
            "nvd_vulnerabilities": lambda: sync_nvd_data(config),
            "github_advisories": lambda: sync_github_advisories(config),
            "ossindex": lambda: sync_ossindex_data(config),
        }

        logger.info("Background sync started for %d secondary sources...",
                     len(secondary_tasks))

        for name, func in secondary_tasks.items():
            try:
                result = func()
                logger.info(
                    "Background sync [%s]: status=%s added=%d modified=%d",
                    name, result.get("status", "?"),
                    result.get("added", 0), result.get("modified", 0)
                )
            except Exception as exc:
                logger.warning("Background sync failed for %s: %s", name, exc)
                _update_sync_metadata(name, status="degraded")

        logger.info("Background sync complete for all secondary sources")

    thread = threading.Thread(target=_run, daemon=True, name="bg-sync")
    thread.start()
