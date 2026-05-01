"""
CodeShield Scan Engine — Pure Orchestrator
Contains ZERO detection logic. Invokes plugins, collects results, persists findings.
"""

import os
import uuid
import time
import shutil
import hashlib
import logging
import zipfile
import tempfile
import threading
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Callable

from .config import AppConfig
from .context import build_scan_context, ScanContext
from .database.connection import get_db
from .plugins.base import PluginResult, Finding
from .plugins.registry import PluginRegistry

logger = logging.getLogger("codeshield.engine")


class ScanEngine:
    """
    Core scan orchestrator.
    - Validates and extracts ZIP uploads securely
    - Builds scan context
    - Invokes plugins concurrently via thread pool
    - Persists results to SQLite
    - Reports progress via callback
    """

    def __init__(self, config: AppConfig, registry: PluginRegistry):
        self._config = config
        self._registry = registry

    def validate_zip(self, file_path: str, file_size: int) -> Optional[str]:
        """
        Validate ZIP file before processing.
        Returns error message if invalid, None if OK.
        """
        # Check file size
        if file_size > self._config.scan.max_zip_size:
            return (f"File exceeds maximum size limit "
                    f"({file_size} > {self._config.scan.max_zip_size} bytes)")

        # Check magic bytes (PK\x03\x04 for ZIP)
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
            if magic[:2] != b"PK":
                return "File is not a valid ZIP archive (invalid magic bytes)"
        except IOError as exc:
            return f"Cannot read file: {exc}"

        # Validate ZIP structure
        if not zipfile.is_zipfile(file_path):
            return "File is not a valid ZIP archive"

        # Scan for path traversal and zip bombs
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                total_uncompressed = 0
                file_count = 0

                for info in zf.infolist():
                    file_count += 1
                    total_uncompressed += info.file_size

                    # Reject path traversal attempts
                    if info.filename.startswith("/") or ".." in info.filename:
                        return (f"ZIP contains path traversal attempt: "
                                f"{info.filename}")

                    # Reject absolute paths
                    if os.path.isabs(info.filename):
                        return (f"ZIP contains absolute path: "
                                f"{info.filename}")

                # Check total file count
                if file_count > self._config.scan.max_file_count:
                    return (f"ZIP contains too many files "
                            f"({file_count} > {self._config.scan.max_file_count})")

                # Check total uncompressed size (zip bomb defense)
                if total_uncompressed > self._config.scan.max_uncompressed_size:
                    return (f"ZIP uncompressed size exceeds limit "
                            f"({total_uncompressed} > "
                            f"{self._config.scan.max_uncompressed_size} bytes)")

        except zipfile.BadZipFile:
            return "Corrupted ZIP file"

        return None

    def extract_zip(self, zip_path: str, target_dir: str) -> None:
        """
        Safely extract ZIP contents into an isolated directory.
        Validates each entry before extraction to prevent path traversal.
        """
        real_target = os.path.realpath(target_dir)

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                # Sanitize filename — strip leading slashes, reject ..
                member_path = os.path.normpath(member.filename)
                if member_path.startswith("..") or os.path.isabs(member_path):
                    logger.warning("Skipping dangerous path: %s",
                                   member.filename)
                    continue

                # Verify extraction target stays within target_dir
                dest = os.path.realpath(
                    os.path.join(target_dir, member_path)
                )
                if not dest.startswith(real_target):
                    logger.warning("Path traversal blocked: %s -> %s",
                                   member.filename, dest)
                    continue

                # Check nesting depth
                depth = member_path.count(os.sep)
                if depth > self._config.scan.max_nesting_depth:
                    logger.warning("Skipping deeply nested file: %s (depth %d)",
                                   member.filename, depth)
                    continue

                # Extract
                zf.extract(member, target_dir)

    def start_scan(self, zip_path: str, original_filename: str,
                   progress_callback: Optional[Callable] = None) -> str:
        """
        Execute a full scan pipeline:
        1. Create scan record
        2. Extract ZIP to isolated temp dir
        3. Build scan context
        4. Run all plugins concurrently
        5. Persist results
        6. Clean up temp directory

        Returns: scan_id
        """
        scan_id = str(uuid.uuid4())
        db = get_db()

        # Compute file hash
        file_hash = self._hash_file(zip_path)

        # Create scan record
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO scans (scan_id, filename, file_hash, status, started_at) "
                "VALUES (?, ?, ?, 'running', ?)",
                (scan_id, original_filename, file_hash,
                 datetime.now(timezone.utc).isoformat())
            )

        def notify(plugin_name: str, status: str, detail: str = ""):
            if progress_callback:
                progress_callback(scan_id, plugin_name, status, detail)

        # Create isolated temp directory with randomized name
        temp_base = self._config.scan.temp_directory or tempfile.gettempdir()
        tmp_dir = tempfile.mkdtemp(
            prefix="codeshield_scan_",
            dir=temp_base
        )

        try:
            # Extract
            notify("engine", "extracting", "Extracting ZIP archive...")
            self.extract_zip(zip_path, tmp_dir)

            # Build context
            notify("engine", "analyzing", "Building file tree...")
            context = build_scan_context(
                scan_id=scan_id,
                code_dir=tmp_dir,
                config=self._config
            )

            # Run plugins concurrently
            plugins = self._registry.get_all_plugins()
            results: Dict[str, PluginResult] = {}

            # Mark all plugins as queued
            for p in plugins:
                notify(p.name, "queued")

            pool_size = min(
                self._config.scan.thread_pool_size,
                len(plugins)
            )

            with ThreadPoolExecutor(max_workers=max(1, pool_size)) as pool:
                future_to_plugin = {}
                for plugin in plugins:
                    notify(plugin.name, "running")
                    future = pool.submit(plugin.run, context)
                    future_to_plugin[future] = plugin

                for future in as_completed(future_to_plugin):
                    plugin = future_to_plugin[future]
                    try:
                        result = future.result(
                            timeout=self._config.scan.plugin_timeout
                        )
                        results[plugin.name] = result
                        status = "complete" if result.status == "complete" else "failed"
                        notify(plugin.name, status,
                               f"{len(result.findings)} findings in {result.duration_sec}s")
                    except Exception as exc:
                        logger.error("Plugin '%s' raised exception: %s",
                                     plugin.name, exc)
                        results[plugin.name] = PluginResult(
                            plugin_name=plugin.name,
                            status="failed",
                            error_message=str(exc)
                        )
                        notify(plugin.name, "failed", str(exc))

            # Persist findings to database
            self._persist_results(scan_id, results)

            notify("engine", "complete", "Scan completed successfully")

        except Exception as exc:
            logger.error("Scan %s failed: %s", scan_id, exc, exc_info=True)
            with db.transaction() as conn:
                conn.execute(
                    "UPDATE scans SET status = 'failed', completed_at = ? "
                    "WHERE scan_id = ?",
                    (datetime.now(timezone.utc).isoformat(), scan_id)
                )
            notify("engine", "failed", "Scan failed due to an internal error")

        finally:
            # Always clean up temp directory
            shutil.rmtree(tmp_dir, ignore_errors=True)
            logger.info("Cleaned up temp directory for scan %s", scan_id)

        return scan_id

    def _persist_results(self, scan_id: str,
                         results: Dict[str, PluginResult]) -> None:
        """Persist all findings to the database within a single transaction."""
        from .mappings import enrich_finding, compute_risk_score

        db = get_db()
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                           "LOW": 0, "INFO": 0}
        total = 0
        all_findings = []

        # Load previous scan findings for trend analysis
        prev_keys = set()
        prev_scan = db.fetchone(
            "SELECT scan_id FROM scans WHERE scan_id != ? "
            "ORDER BY created_at DESC LIMIT 1",
            (scan_id,)
        )
        if prev_scan:
            prev_rows = db.fetchall(
                "SELECT rule_id, file_path, line_number, cve_id, title "
                "FROM findings WHERE scan_id = ?",
                (prev_scan["scan_id"],)
            )
            for r in prev_rows:
                key = f"{r['rule_id']}|{r['file_path']}|{r['line_number']}|{r['cve_id']}|{r['title']}"
                prev_keys.add(key)

        for plugin_name, result in results.items():
            for finding in result.findings:
                total += 1
                sev = finding.severity.upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1

                # Build enrichment dict from Finding fields
                f_dict = {
                    "cwe_id": finding.cwe_id,
                    "severity": finding.severity,
                    "owasp_category": finding.owasp_category,
                }
                enrich_finding(f_dict)

                # Apply enrichment back to finding
                finding.mitre_id = f_dict.get("mitre_id", "")
                finding.mitre_label = f_dict.get("mitre_label", "")
                finding.pci_dss = f_dict.get("pci_dss", "")
                finding.hipaa = f_dict.get("hipaa", "")
                finding.exploit_available = f_dict.get("exploit_available", "unknown")
                finding.fix_effort_hours = f_dict.get("fix_effort_hours", 2.0)
                finding.cwe_label = f_dict.get("cwe_label", "")
                finding.owasp_label = f_dict.get("owasp_label", "")
                if not finding.owasp_category:
                    finding.owasp_category = f_dict.get("owasp_category", "")

                # Trend analysis
                fkey = f"{finding.rule_id}|{finding.file_path}|{finding.line_number}|{finding.cve_id}|{finding.title}"
                finding.trend_status = "recurring" if fkey in prev_keys else "new"

                all_findings.append((
                    scan_id, finding.plugin_name, finding.severity,
                    finding.title, finding.description, finding.file_path,
                    finding.line_number, finding.code_snippet,
                    finding.remediation, finding.rule_id, finding.cve_id,
                    finding.cvss_score, finding.cwe_id, finding.owasp_category,
                    finding.package_name, finding.package_version,
                    finding.fixed_version, finding.license_id,
                    "{}",
                    finding.mitre_id, finding.mitre_label,
                    finding.pci_dss, finding.hipaa,
                    finding.exploit_available,
                    1 if finding.false_positive else 0,
                    finding.confidence, finding.fix_effort_hours,
                    finding.trend_status, finding.cwe_label,
                    finding.owasp_label,
                ))

        with db.transaction() as conn:
            # Insert all findings
            conn.executemany(
                "INSERT INTO findings "
                "(scan_id, plugin_name, severity, title, description, "
                "file_path, line_number, code_snippet, remediation, "
                "rule_id, cve_id, cvss_score, cwe_id, owasp_category, "
                "package_name, package_version, fixed_version, license_id, "
                "extra_json, "
                "mitre_id, mitre_label, pci_dss, hipaa, "
                "exploit_available, false_positive, confidence, "
                "fix_effort_hours, trend_status, cwe_label, owasp_label) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                all_findings
            )

            # Update scan record
            conn.execute(
                "UPDATE scans SET status = 'complete', completed_at = ?, "
                "total_findings = ?, critical_count = ?, high_count = ?, "
                "medium_count = ?, low_count = ?, info_count = ? "
                "WHERE scan_id = ?",
                (datetime.now(timezone.utc).isoformat(), total,
                 severity_counts["CRITICAL"], severity_counts["HIGH"],
                 severity_counts["MEDIUM"], severity_counts["LOW"],
                 severity_counts["INFO"], scan_id)
            )

        logger.info("Persisted %d findings for scan %s", total, scan_id)

    def _hash_file(self, path: str) -> str:
        """Compute SHA-256 hash of a file using streaming reads."""
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
