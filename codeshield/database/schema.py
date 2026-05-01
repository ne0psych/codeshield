"""
CodeShield Database Schema & Migrations
Normalized schema with versioning for automatic migration on startup.
"""

import logging
from .connection import DatabaseManager

logger = logging.getLogger("codeshield.database")

CURRENT_SCHEMA_VERSION = 2

# Migration v2: add enrichment columns to findings
MIGRATION_V2_SQL = """
ALTER TABLE findings ADD COLUMN mitre_id TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN mitre_label TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN pci_dss TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN hipaa TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN exploit_available TEXT DEFAULT 'unknown';
ALTER TABLE findings ADD COLUMN false_positive INTEGER DEFAULT 0;
ALTER TABLE findings ADD COLUMN confidence REAL DEFAULT 0.85;
ALTER TABLE findings ADD COLUMN fix_effort_hours REAL DEFAULT 2.0;
ALTER TABLE findings ADD COLUMN trend_status TEXT DEFAULT 'new';
ALTER TABLE findings ADD COLUMN cwe_label TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN owasp_label TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_finding_cwe ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_finding_owasp ON findings(owasp_category);
CREATE INDEX IF NOT EXISTS idx_finding_mitre ON findings(mitre_id);
CREATE INDEX IF NOT EXISTS idx_finding_trend ON findings(trend_status);
"""

SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability data from OSV/NVD
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id TEXT NOT NULL UNIQUE,
    summary TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
    cvss_score REAL DEFAULT 0.0,
    cvss_vector TEXT DEFAULT '',
    source TEXT NOT NULL DEFAULT 'osv',
    published_at TEXT DEFAULT '',
    modified_at TEXT DEFAULT '',
    references_json TEXT DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(vuln_id);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);

-- Affected packages linked to vulnerabilities
CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    ecosystem TEXT NOT NULL DEFAULT '',
    package_name TEXT NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_affected_pkg ON affected_packages(package_name, ecosystem);

-- Version ranges for affected packages
CREATE TABLE IF NOT EXISTS version_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    affected_package_id INTEGER NOT NULL,
    range_type TEXT NOT NULL DEFAULT 'SEMVER',
    introduced TEXT DEFAULT '',
    fixed TEXT DEFAULT '',
    last_affected TEXT DEFAULT '',
    FOREIGN KEY (affected_package_id) REFERENCES affected_packages(id) ON DELETE CASCADE
);

-- SAST rules loaded from database
CREATE TABLE IF NOT EXISTS sast_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    pattern TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT '*',
    severity TEXT NOT NULL DEFAULT 'MEDIUM',
    cwe_id TEXT DEFAULT '',
    owasp_category TEXT DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sast_rule_id ON sast_rules(rule_id);
CREATE INDEX IF NOT EXISTS idx_sast_language ON sast_rules(language);
CREATE INDEX IF NOT EXISTS idx_sast_severity ON sast_rules(severity);
CREATE INDEX IF NOT EXISTS idx_sast_cwe ON sast_rules(cwe_id);

-- Secrets detection patterns
CREATE TABLE IF NOT EXISTS secrets_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'HIGH',
    description TEXT NOT NULL DEFAULT '',
    entropy_threshold REAL DEFAULT 0.0,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_secrets_pattern_id ON secrets_patterns(pattern_id);

-- License definitions from SPDX
CREATE TABLE IF NOT EXISTS license_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    spdx_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    is_osi_approved INTEGER DEFAULT 0,
    is_fsf_libre INTEGER DEFAULT 0,
    category TEXT NOT NULL DEFAULT 'unknown',
    reference_url TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_license_spdx ON license_definitions(spdx_id);

-- Scan records
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    file_hash TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    sbom_json TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_id ON scans(scan_id);

-- Individual findings from scans
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    plugin_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    file_path TEXT DEFAULT '',
    line_number INTEGER DEFAULT 0,
    code_snippet TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    rule_id TEXT DEFAULT '',
    cve_id TEXT DEFAULT '',
    cvss_score REAL DEFAULT 0.0,
    cwe_id TEXT DEFAULT '',
    owasp_category TEXT DEFAULT '',
    package_name TEXT DEFAULT '',
    package_version TEXT DEFAULT '',
    fixed_version TEXT DEFAULT '',
    license_id TEXT DEFAULT '',
    extra_json TEXT DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_finding_plugin ON findings(plugin_name);

-- Sync metadata for incremental updates (ETags, hashes)
CREATE TABLE IF NOT EXISTS sync_metadata (
    source_name TEXT PRIMARY KEY,
    etag TEXT DEFAULT '',
    last_modified TEXT DEFAULT '',
    content_hash TEXT DEFAULT '',
    last_sync_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    records_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'ok'
);
"""


def initialize_schema(db: DatabaseManager) -> None:
    """Create or migrate the database schema."""
    with db.transaction() as conn:
        # Check current version
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version "
            "(version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        row = conn.execute(
            "SELECT MAX(version) as v FROM schema_version"
        ).fetchone()
        current = row["v"] if row and row["v"] else 0

        if current < 1:
            logger.info("Applying schema version 1 (current: %d)", current)
            conn.executescript(SCHEMA_SQL)
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                (1,)
            )
            logger.info("Schema version 1 applied successfully")
            current = 1

        if current < 2:
            logger.info("Applying schema migration v2 (current: %d)", current)
            # ALTER TABLE statements must run individually
            for line in MIGRATION_V2_SQL.strip().split(";"):
                line = line.strip()
                if line:
                    try:
                        conn.execute(line)
                    except Exception as exc:
                        # Column may already exist from a partial migration
                        if "duplicate column" not in str(exc).lower():
                            logger.debug("Migration v2 statement skipped: %s", exc)
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                (2,)
            )
            logger.info("Schema version 2 applied successfully")
            current = 2

        if current >= CURRENT_SCHEMA_VERSION:
            logger.debug("Schema up to date (version %d)", current)
