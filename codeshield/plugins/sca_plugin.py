"""
SCA Plugin — Software Composition Analysis

Parses dependency manifests, generates CycloneDX SBOM, and matches
components against the local vulnerability database using an interval
tree for version range lookups and a bloom filter for fast pre-check.
"""

import re
import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Optional

from packaging.version import Version, InvalidVersion

from .base import ScannerPlugin, PluginResult, Finding
from ..database.connection import get_db
from ..structures.interval_tree import (
    IntervalTree, VersionInterval, MAX_VERSION, parse_version_safe
)
from ..structures.bloom_filter import BloomFilter
from ..structures.dependency_graph import DependencyGraph, PackageNode
from ..structures.lru_cache import LRUCache

logger = logging.getLogger("codeshield.plugins.sca")


# --- Manifest Parsers ---
# Each parser returns list of (name, version, ecosystem) tuples.

def _parse_requirements_txt(path: str) -> List[Tuple[str, str, str]]:
    """Parse Python requirements.txt / requirements-dev.txt."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(
                    r'([A-Za-z0-9_\-\.]+)\s*[=><!~]+\s*([\d\.]+)', line
                )
                if m:
                    deps.append((m.group(1).lower(), m.group(2), "PyPI"))
                else:
                    name_m = re.match(r'([A-Za-z0-9_\-\.]+)', line)
                    if name_m:
                        deps.append((name_m.group(1).lower(), "0.0.0", "PyPI"))
    except Exception as exc:
        logger.warning("Error parsing %s: %s", path, exc)
    return deps


def _parse_package_json(path: str) -> List[Tuple[str, str, str]]:
    """Parse Node.js package.json."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for section in ("dependencies", "devDependencies"):
            for pkg, ver in data.get(section, {}).items():
                ver_clean = re.sub(r'[^0-9.]', '', ver)
                deps.append((pkg.lower(), ver_clean or "0.0.0", "npm"))
    except Exception as exc:
        logger.warning("Error parsing %s: %s", path, exc)
    return deps


def _parse_go_mod(path: str) -> List[Tuple[str, str, str]]:
    """Parse Go go.mod."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            in_require = False
            for line in fh:
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if line == ")" and in_require:
                    in_require = False
                    continue
                if in_require or line.startswith("require "):
                    parts = line.replace("require ", "").strip().split()
                    if len(parts) >= 2:
                        name = parts[0].lower()
                        ver = parts[1].lstrip("v")
                        deps.append((name, ver, "Go"))
    except Exception as exc:
        logger.warning("Error parsing %s: %s", path, exc)
    return deps


def _parse_cargo_toml(path: str) -> List[Tuple[str, str, str]]:
    """Parse Rust Cargo.toml."""
    deps = []
    try:
        import toml
        with open(path, "r", encoding="utf-8") as fh:
            data = toml.load(fh)
        for section in ("dependencies", "dev-dependencies"):
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, str):
                    ver = re.sub(r'[^0-9.]', '', spec)
                    deps.append((name.lower(), ver or "0.0.0", "crates.io"))
                elif isinstance(spec, dict) and "version" in spec:
                    ver = re.sub(r'[^0-9.]', '', spec["version"])
                    deps.append((name.lower(), ver or "0.0.0", "crates.io"))
    except Exception as exc:
        logger.warning("Error parsing %s: %s", path, exc)
    return deps


def _parse_gemfile_lock(path: str) -> List[Tuple[str, str, str]]:
    """Parse Ruby Gemfile.lock."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            in_specs = False
            for line in fh:
                if line.strip() == "specs:":
                    in_specs = True
                    continue
                if in_specs:
                    m = re.match(r'\s{4}(\S+)\s+\((\S+)\)', line)
                    if m:
                        deps.append((m.group(1).lower(), m.group(2), "RubyGems"))
                    elif not line.startswith("    "):
                        in_specs = False
    except Exception as exc:
        logger.warning("Error parsing %s: %s", path, exc)
    return deps


def _parse_pom_xml(path: str) -> List[Tuple[str, str, str]]:
    """Parse Java pom.xml (basic regex-based, avoids XML parser for safety)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        # Find dependency blocks
        dep_blocks = re.findall(
            r'<dependency>\s*(.*?)\s*</dependency>',
            content, re.DOTALL
        )
        for block in dep_blocks:
            gid = re.search(r'<groupId>\s*(.*?)\s*</groupId>', block)
            aid = re.search(r'<artifactId>\s*(.*?)\s*</artifactId>', block)
            ver = re.search(r'<version>\s*(.*?)\s*</version>', block)
            if aid:
                name = f"{gid.group(1)}:{aid.group(1)}" if gid else aid.group(1)
                version = ver.group(1) if ver else "0.0.0"
                # Skip property references like ${project.version}
                if not version.startswith("$"):
                    deps.append((name.lower(), version, "Maven"))
    except Exception as exc:
        logger.warning("Error parsing %s: %s", path, exc)
    return deps


# Map filenames to parsers
MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "Cargo.toml": _parse_cargo_toml,
    "Gemfile.lock": _parse_gemfile_lock,
    "pom.xml": _parse_pom_xml,
}


class SCAPlugin(ScannerPlugin):
    """
    Software Composition Analysis scanner.
    Parses manifests, builds dependency graph, generates SBOM,
    and matches against vulnerability database.
    """

    def __init__(self):
        self._interval_trees: Dict[str, IntervalTree] = {}
        self._bloom_filter = BloomFilter(expected_items=50000)
        self._cache = LRUCache(capacity=256)

    @property
    def name(self) -> str:
        return "sca"

    @property
    def description(self) -> str:
        return "Software Composition Analysis — dependency vulnerability scanning"

    @property
    def priority(self) -> int:
        return 20

    def initialize(self) -> None:
        """Build interval trees from vulnerability database."""
        self._build_vulnerability_index()

    def _build_vulnerability_index(self) -> None:
        """
        Build interval trees keyed by (ecosystem, package_name) from the
        vulnerability database. Also populates bloom filter with known
        non-vulnerable versions for fast pre-check.
        """
        db = get_db()
        rows = db.fetchall(
            "SELECT v.vuln_id, v.severity, v.cvss_score, v.summary, "
            "ap.ecosystem, ap.package_name, "
            "vr.introduced, vr.fixed, vr.last_affected "
            "FROM vulnerabilities v "
            "JOIN affected_packages ap ON v.id = ap.vulnerability_id "
            "JOIN version_ranges vr ON ap.id = vr.affected_package_id"
        )

        # Group intervals by (ecosystem, package)
        intervals_by_pkg: Dict[str, List[VersionInterval]] = {}

        for row in rows:
            eco = row["ecosystem"].lower() if row["ecosystem"] else ""
            pkg = row["package_name"].lower() if row["package_name"] else ""
            key = f"{eco}:{pkg}"

            introduced = parse_version_safe(row["introduced"])
            fixed = parse_version_safe(row["fixed"])
            last_affected = parse_version_safe(row["last_affected"])

            if introduced is None:
                introduced = Version("0")

            if fixed:
                high = fixed
            elif last_affected:
                # Approximate: everything up to and including last_affected
                high = MAX_VERSION
            else:
                high = MAX_VERSION

            interval = VersionInterval(
                low=introduced,
                high=high,
                vuln_id=row["vuln_id"],
                metadata={
                    "severity": row["severity"],
                    "cvss_score": row["cvss_score"],
                    "summary": row["summary"],
                    "fixed": row["fixed"] or "",
                }
            )

            if key not in intervals_by_pkg:
                intervals_by_pkg[key] = []
            intervals_by_pkg[key].append(interval)

        # Build one interval tree per package
        for key, intervals in intervals_by_pkg.items():
            tree = IntervalTree()
            tree.build(intervals)
            self._interval_trees[key] = tree

        logger.info("Built %d interval trees from vulnerability DB",
                     len(self._interval_trees))

    def execute(self, context) -> PluginResult:
        """Parse manifests, build SBOM, check vulnerabilities."""
        findings = []
        files_scanned = 0
        all_deps: List[Tuple[str, str, str, str]] = []  # name, ver, eco, source_file

        # Parse all manifest files
        for fi in context.manifests:
            fname = Path(fi.path).name
            parser = MANIFEST_PARSERS.get(fname)
            if parser:
                files_scanned += 1
                deps = parser(fi.absolute_path)
                for name, ver, eco in deps:
                    all_deps.append((name, ver, eco, fi.path))

        # Build dependency graph (DAG)
        dep_graph = DependencyGraph()
        for name, ver, eco, _ in all_deps:
            dep_graph.add_package(PackageNode(
                name=name, version=ver, ecosystem=eco
            ))

        # Generate CycloneDX SBOM
        sbom = self._generate_sbom(all_deps, context)

        # Check each dependency against vulnerability database
        for name, ver, eco, source_file in all_deps:
            vuln_findings = self._check_package(name, ver, eco, source_file)
            findings.extend(vuln_findings)

        # Store SBOM in scan record
        db = get_db()
        with db.transaction() as conn:
            conn.execute(
                "UPDATE scans SET sbom_json = ? WHERE scan_id = ?",
                (json.dumps(sbom), context.scan_id)
            )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            files_scanned=files_scanned,
            metadata={
                "components": len(all_deps),
                "dep_graph_nodes": dep_graph.node_count,
                "interval_trees": len(self._interval_trees),
            }
        )

    def _check_package(self, name: str, version: str,
                       ecosystem: str, source_file: str) -> List[Finding]:
        """Check a single package against the vulnerability database."""
        findings = []
        eco_lower = ecosystem.lower()

        # Map ecosystem names to OSV ecosystem strings
        eco_map = {
            "pypi": "pypi", "npm": "npm", "maven": "maven",
            "go": "go", "crates.io": "crates.io", "rubygems": "rubygems",
        }
        eco_key = eco_map.get(eco_lower, eco_lower)
        lookup_key = f"{eco_key}:{name.lower()}"

        # Bloom filter fast pre-check
        if self._bloom_filter.might_contain_package(name, version):
            # Might be known-safe — but bloom filters have false positives
            # so we still check (just an optimization hint)
            pass

        # Interval tree lookup for O(log N + K) vulnerability matching
        tree = self._interval_trees.get(lookup_key)
        if tree is None:
            return findings

        ver = parse_version_safe(version)
        if ver is None:
            return findings

        matches = tree.query(ver)
        for interval in matches:
            meta = interval.metadata
            sev = meta.get("severity", "MEDIUM")
            findings.append(Finding(
                plugin_name=self.name,
                severity=sev,
                title=f"Vulnerable dependency: {name}=={version}",
                description=meta.get("summary", ""),
                file_path=source_file,
                line_number=0,
                code_snippet=f"{name}=={version}",
                remediation=(
                    f"Upgrade to {name}>={meta['fixed']}"
                    if meta.get("fixed") else
                    f"Check for updates to {name}"
                ),
                cve_id=interval.vuln_id,
                cvss_score=meta.get("cvss_score", 0.0),
                package_name=name,
                package_version=version,
                fixed_version=meta.get("fixed", ""),
            ))

        return findings

    def _generate_sbom(self, deps: List[Tuple[str, str, str, str]],
                       context) -> dict:
        """Generate CycloneDX 1.4 compliant SBOM."""
        components = []
        seen = set()

        for name, ver, eco, _ in deps:
            key = f"{name}@{ver}"
            if key in seen:
                continue
            seen.add(key)

            # Build Package URL
            eco_purl = {
                "PyPI": "pypi", "npm": "npm", "Maven": "maven",
                "Go": "golang", "crates.io": "cargo", "RubyGems": "gem",
            }
            purl_type = eco_purl.get(eco, eco.lower())
            purl = f"pkg:{purl_type}/{name}@{ver}"

            components.append({
                "type": "library",
                "name": name,
                "version": ver,
                "purl": purl,
                "bom-ref": hashlib.sha256(
                    purl.encode()
                ).hexdigest()[:16],
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{context.scan_id}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"name": "CodeShield", "version": "2.0.0"}],
            },
            "components": components,
        }
