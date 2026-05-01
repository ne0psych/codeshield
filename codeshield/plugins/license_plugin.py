"""
License Compliance Plugin

Detects license declarations from LICENSE files, SPDX headers,
package.json, pyproject.toml, etc. Normalizes to SPDX identifiers
using the synced SPDX database. Classifies by category and flags
incompatibilities based on configurable allowed/denied lists.
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple

from .base import ScannerPlugin, PluginResult, Finding
from ..database.connection import get_db
from ..structures.lru_cache import LRUCache

logger = logging.getLogger("codeshield.plugins.license")

# License category classification
LICENSE_CATEGORIES = {
    # Permissive licenses
    "MIT": "permissive",
    "Apache-2.0": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "ISC": "permissive",
    "0BSD": "permissive",
    "Unlicense": "permissive",
    "CC0-1.0": "permissive",
    "Zlib": "permissive",
    "BSL-1.0": "permissive",
    "PostgreSQL": "permissive",
    "X11": "permissive",
    "JSON": "permissive",
    # Weak copyleft
    "LGPL-2.1-only": "weak_copyleft",
    "LGPL-2.1-or-later": "weak_copyleft",
    "LGPL-3.0-only": "weak_copyleft",
    "LGPL-3.0-or-later": "weak_copyleft",
    "MPL-2.0": "weak_copyleft",
    "EPL-1.0": "weak_copyleft",
    "EPL-2.0": "weak_copyleft",
    "CDDL-1.0": "weak_copyleft",
    # Strong copyleft
    "GPL-2.0-only": "strong_copyleft",
    "GPL-2.0-or-later": "strong_copyleft",
    "GPL-3.0-only": "strong_copyleft",
    "GPL-3.0-or-later": "strong_copyleft",
    "AGPL-3.0-only": "strong_copyleft",
    "AGPL-3.0-or-later": "strong_copyleft",
    "SSPL-1.0": "proprietary",
    # Proprietary/other
    "BUSL-1.1": "proprietary",
    "Elastic-2.0": "proprietary",
}

# Common license name variations mapped to SPDX IDs
LICENSE_ALIASES = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "new bsd": "BSD-3-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gplv2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "agpl-3.0": "AGPL-3.0-only",
    "unlicense": "Unlicense",
    "unlicensed": "Unlicense",
    "public domain": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "cc0": "CC0-1.0",
    "wtfpl": "WTFPL",
    "0bsd": "0BSD",
    "artistic-2.0": "Artistic-2.0",
}


class LicensePlugin(ScannerPlugin):
    """
    License compliance scanner.
    Detects licenses, normalizes to SPDX, classifies, and flags violations.
    """

    def __init__(self):
        self._spdx_licenses: Dict[str, dict] = {}
        self._allowed: Set[str] = set()
        self._denied: Set[str] = set()
        self._cache = LRUCache(capacity=128)

    @property
    def name(self) -> str:
        return "license"

    @property
    def description(self) -> str:
        return "License compliance — detect and validate software licenses"

    @property
    def priority(self) -> int:
        return 40

    def initialize(self) -> None:
        """Load SPDX license data and compliance config."""
        self._load_spdx_data()

    def _load_spdx_data(self) -> None:
        """Load SPDX license definitions from database."""
        db = get_db()
        rows = db.fetchall("SELECT * FROM license_definitions")
        for row in rows:
            self._spdx_licenses[row["spdx_id"].lower()] = dict(row)
        logger.info("Loaded %d SPDX license definitions",
                     len(self._spdx_licenses))

    def execute(self, context) -> PluginResult:
        """Detect and validate licenses in the codebase."""
        # Load compliance config
        if context.config:
            lc = context.config.license_compliance
            self._allowed = set(lc.allowed_licenses)
            self._denied = set(lc.denied_licenses)

        findings = []
        files_scanned = 0
        detected_licenses: List[Tuple[str, str, str]] = []  # spdx_id, source, file

        # 1. Scan LICENSE/COPYING files
        for fi in context.files:
            fname = Path(fi.path).name.upper()
            if fname in ("LICENSE", "LICENSE.TXT", "LICENSE.MD",
                         "LICENCE", "LICENCE.TXT", "LICENCE.MD",
                         "COPYING", "COPYING.TXT"):
                files_scanned += 1
                lic = self._detect_from_license_file(fi.absolute_path)
                if lic:
                    detected_licenses.append((lic, "license_file", fi.path))

        # 2. Scan for SPDX-License-Identifier headers
        for fi in context.source_files:
            if fi.is_binary or fi.is_minified:
                continue
            files_scanned += 1
            header_lic = self._detect_spdx_header(fi.absolute_path)
            if header_lic:
                detected_licenses.append(
                    (header_lic, "spdx_header", fi.path)
                )

        # 3. Scan package.json for license field
        for fi in context.manifests:
            fname = Path(fi.path).name
            if fname == "package.json":
                lic = self._detect_from_package_json(fi.absolute_path)
                if lic:
                    detected_licenses.append(
                        (lic, "package.json", fi.path)
                    )
            elif fname == "pyproject.toml":
                lic = self._detect_from_pyproject(fi.absolute_path)
                if lic:
                    detected_licenses.append(
                        (lic, "pyproject.toml", fi.path)
                    )

        # 4. Generate findings for each detected license
        for spdx_id, source, file_path in detected_licenses:
            category = self._get_category(spdx_id)
            status = self._check_compliance(spdx_id)

            severity = "INFO"
            if status == "denied":
                severity = "CRITICAL"
            elif status == "not_allowed":
                severity = "HIGH"
            elif category == "strong_copyleft":
                severity = "MEDIUM"
            elif category == "unknown":
                severity = "LOW"

            findings.append(Finding(
                plugin_name=self.name,
                severity=severity,
                title=f"License: {spdx_id} ({category})",
                description=(
                    f"License '{spdx_id}' detected in {source}. "
                    f"Category: {category}. Compliance: {status}."
                ),
                file_path=file_path,
                remediation=self._get_remediation(spdx_id, status, category),
                license_id=spdx_id,
                extra={"category": category, "compliance": status},
            ))

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            files_scanned=files_scanned,
            metadata={
                "licenses_detected": len(detected_licenses),
                "spdx_db_size": len(self._spdx_licenses),
            }
        )

    def _normalize_license(self, text: str) -> Optional[str]:
        """Normalize a license string to a canonical SPDX identifier."""
        if not text:
            return None

        clean = text.strip().lower()
        # Direct SPDX match
        if clean in self._spdx_licenses:
            return self._spdx_licenses[clean]["spdx_id"]

        # Alias match
        if clean in LICENSE_ALIASES:
            return LICENSE_ALIASES[clean]

        # Fuzzy match: check if any known alias is a substring
        for alias, spdx_id in LICENSE_ALIASES.items():
            if alias in clean:
                return spdx_id

        return text.strip()  # Return as-is if no match

    def _detect_from_license_file(self, path: str) -> Optional[str]:
        """Detect license type from LICENSE file content."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(4096)  # Read first 4KB only

            lower = content.lower()

            # Check for common license text signatures
            signatures = [
                ("mit license", "MIT"),
                ("permission is hereby granted, free of charge", "MIT"),
                ("apache license", "Apache-2.0"),
                ("version 2.0, january 2004", "Apache-2.0"),
                ("bsd 2-clause", "BSD-2-Clause"),
                ("redistribution and use in source and binary", "BSD-3-Clause"),
                ("gnu general public license", None),  # Need version check
                ("gnu lesser general public", None),
                ("mozilla public license", "MPL-2.0"),
                ("isc license", "ISC"),
                ("the unlicense", "Unlicense"),
            ]

            for sig, spdx_id in signatures:
                if sig in lower:
                    if spdx_id:
                        return spdx_id
                    # GPL version detection
                    if "version 3" in lower or "gpl-3" in lower:
                        if "lesser" in lower:
                            return "LGPL-3.0-only"
                        if "affero" in lower:
                            return "AGPL-3.0-only"
                        return "GPL-3.0-only"
                    if "version 2" in lower or "gpl-2" in lower:
                        if "lesser" in lower:
                            return "LGPL-2.1-only"
                        return "GPL-2.0-only"

            # Check for SPDX identifier in the file
            m = re.search(r'SPDX-License-Identifier:\s*(\S+)', content)
            if m:
                return self._normalize_license(m.group(1))

        except Exception as exc:
            logger.warning("Error reading license file %s: %s", path, exc)

        return None

    def _detect_spdx_header(self, path: str) -> Optional[str]:
        """Scan first 20 lines for SPDX-License-Identifier header."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh):
                    if i >= 20:
                        break
                    m = re.search(
                        r'SPDX-License-Identifier:\s*(\S+)', line
                    )
                    if m:
                        return self._normalize_license(m.group(1))
        except Exception:
            pass
        return None

    def _detect_from_package_json(self, path: str) -> Optional[str]:
        """Extract license from package.json."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            lic = data.get("license", "")
            if isinstance(lic, str) and lic:
                return self._normalize_license(lic)
            if isinstance(lic, dict):
                return self._normalize_license(lic.get("type", ""))
        except Exception:
            pass
        return None

    def _detect_from_pyproject(self, path: str) -> Optional[str]:
        """Extract license from pyproject.toml."""
        try:
            import toml
            with open(path, "r", encoding="utf-8") as fh:
                data = toml.load(fh)
            project = data.get("project", data.get("tool", {}).get("poetry", {}))
            lic = project.get("license", "")
            if isinstance(lic, str):
                return self._normalize_license(lic)
            if isinstance(lic, dict):
                return self._normalize_license(
                    lic.get("text", lic.get("type", ""))
                )
        except Exception:
            pass
        return None

    def _get_category(self, spdx_id: str) -> str:
        """Classify a license into a category."""
        if spdx_id in LICENSE_CATEGORIES:
            return LICENSE_CATEGORIES[spdx_id]

        # Check database
        db_entry = self._spdx_licenses.get(spdx_id.lower())
        if db_entry and db_entry.get("category"):
            return db_entry["category"]

        return "unknown"

    def _check_compliance(self, spdx_id: str) -> str:
        """
        Check license against allowed/denied lists.
        Returns: 'compliant', 'denied', 'not_allowed', or 'unchecked'
        """
        if spdx_id in self._denied:
            return "denied"
        if self._allowed and spdx_id not in self._allowed:
            return "not_allowed"
        if self._allowed and spdx_id in self._allowed:
            return "compliant"
        return "unchecked"

    def _get_remediation(self, spdx_id: str, status: str,
                         category: str) -> str:
        """Generate remediation guidance based on compliance status."""
        if status == "denied":
            return (f"License '{spdx_id}' is on the denied list. "
                    f"Replace this dependency with an alternative "
                    f"using a permissive license.")
        if status == "not_allowed":
            return (f"License '{spdx_id}' is not on the allowed list. "
                    f"Request approval or find an alternative dependency.")
        if category == "strong_copyleft":
            return (f"Strong copyleft license '{spdx_id}' may require "
                    f"releasing your source code. Review compliance "
                    f"obligations carefully.")
        if category == "unknown":
            return (f"Could not classify license '{spdx_id}'. "
                    f"Manual review recommended.")
        return "No action required."
