"""
CodeShield Supply Chain Security Plugin
Detects typosquatting, malicious packages, dependency backdoors,
and suspicious version patterns in dependency manifests.
"""
import re
import json
import logging
from typing import List
from ..plugins.base import ScannerPlugin, PluginResult, Finding
from ..database.connection import get_db

logger = logging.getLogger("codeshield.plugins.supplychain")

# Known popular packages for typosquatting detection
POPULAR_PACKAGES = {
    "python": [
        "requests", "flask", "django", "numpy", "pandas", "scipy",
        "boto3", "pyyaml", "cryptography", "pillow", "sqlalchemy",
        "celery", "redis", "pytest", "setuptools", "urllib3",
        "jinja2", "click", "aiohttp", "fastapi", "uvicorn",
        "pydantic", "httpx", "beautifulsoup4", "scrapy", "paramiko",
    ],
    "javascript": [
        "express", "react", "lodash", "axios", "moment", "webpack",
        "typescript", "eslint", "prettier", "babel", "jest", "mocha",
        "commander", "chalk", "inquirer", "yargs", "underscore",
        "vue", "angular", "next", "nuxt", "socket.io", "mongoose",
        "passport", "jsonwebtoken", "bcrypt", "cors", "helmet",
    ],
}

SUSPICIOUS_INSTALL_SCRIPTS = [
    r"preinstall.*curl\b", r"preinstall.*wget\b",
    r"preinstall.*base64", r"preinstall.*eval\b",
    r"postinstall.*curl\b", r"postinstall.*wget\b",
    r"postinstall.*eval\b", r"postinstall.*base64",
    r"install.*\bexec\b.*http", r"install.*child_process",
]

SUSPICIOUS_VERSION_RE = [
    re.compile(r"^0\.0\.0"),          # Placeholder version
    re.compile(r"999\.\d+\.\d+"),     # Absurdly high major
    re.compile(r"\d+\.\d+\.\d+-.*dev.*hack", re.I),
]


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1,
                            prev[j] + (0 if c1 == c2 else 1)))
        prev = curr
    return prev[-1]


class SupplyChainPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "supplychain"

    @property
    def description(self) -> str:
        return "Supply chain security: typosquatting, malicious packages, backdoor detection"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def priority(self) -> int:
        return 55

    def execute(self, context) -> PluginResult:
        findings: List[Finding] = []
        files_scanned = 0

        for fi in context.manifests:
            files_scanned += 1
            try:
                with open(fi.absolute_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(512_000)
            except Exception:
                continue

            fname = fi.path.lower()
            if "package.json" in fname and not fname.endswith(".lock"):
                findings.extend(self._check_npm_manifest(fi, content))
            elif "requirements" in fname or "pipfile" in fname:
                findings.extend(self._check_python_manifest(fi, content))

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            files_scanned=files_scanned,
        )

    def _check_npm_manifest(self, fi, content: str) -> List[Finding]:
        results = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return results

        # Check install scripts for suspicious patterns
        scripts = data.get("scripts", {})
        for script_name, script_cmd in scripts.items():
            for pattern in SUSPICIOUS_INSTALL_SCRIPTS:
                if re.search(pattern, f"{script_name} {script_cmd}", re.I):
                    results.append(Finding(
                        plugin_name=self.name, severity="CRITICAL",
                        title=f"Suspicious install script: {script_name}",
                        description=f"Script '{script_name}' contains suspicious command pattern that may indicate a supply chain attack.",
                        file_path=fi.path, rule_id="SC-001",
                        cwe_id="CWE-506", owasp_category="A08:2021",
                        code_snippet=script_cmd[:200],
                        remediation="Review install scripts. Remove or audit any network calls or code execution in lifecycle scripts.",
                    ))

        # Check dependencies for typosquatting
        for dep_section in ("dependencies", "devDependencies"):
            deps = data.get(dep_section, {})
            for pkg_name, ver in deps.items():
                results.extend(self._check_typosquatting(fi, pkg_name, "javascript"))
                results.extend(self._check_suspicious_version(fi, pkg_name, str(ver)))

        return results

    def _check_python_manifest(self, fi, content: str) -> List[Finding]:
        results = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r'^([a-zA-Z0-9_.-]+)', line)
            if match:
                pkg = match.group(1).lower()
                results.extend(self._check_typosquatting(fi, pkg, "python"))
                ver_match = re.search(r'[=><!]+\s*(\S+)', line)
                if ver_match:
                    results.extend(self._check_suspicious_version(fi, pkg, ver_match.group(1)))
        return results

    def _check_typosquatting(self, fi, pkg: str, ecosystem: str) -> List[Finding]:
        results = []
        popular = POPULAR_PACKAGES.get(ecosystem, [])
        pkg_lower = pkg.lower().replace("-", "").replace("_", "")
        for known in popular:
            known_norm = known.lower().replace("-", "").replace("_", "")
            if pkg_lower == known_norm:
                continue  # exact match
            dist = _levenshtein(pkg_lower, known_norm)
            if 0 < dist <= 2 and len(pkg_lower) > 3:
                results.append(Finding(
                    plugin_name=self.name, severity="HIGH",
                    title=f"Potential typosquat: '{pkg}' (similar to '{known}')",
                    description=f"Package '{pkg}' is very similar to popular package '{known}' (edit distance: {dist}). This may be a typosquatting attack.",
                    file_path=fi.path, rule_id="SC-002",
                    cwe_id="CWE-829", owasp_category="A06:2021",
                    package_name=pkg,
                    remediation=f"Verify this is the intended package. Did you mean '{known}'?",
                ))
        return results

    def _check_suspicious_version(self, fi, pkg: str, version: str) -> List[Finding]:
        results = []
        for pat in SUSPICIOUS_VERSION_RE:
            if pat.search(version):
                results.append(Finding(
                    plugin_name=self.name, severity="MEDIUM",
                    title=f"Suspicious version pattern: {pkg}=={version}",
                    description=f"Package '{pkg}' uses version '{version}' which matches suspicious patterns.",
                    file_path=fi.path, rule_id="SC-003",
                    cwe_id="CWE-494", package_name=pkg, package_version=version,
                    remediation="Verify this version exists on the official registry and is legitimate.",
                ))
        return results
