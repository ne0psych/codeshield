"""
Secrets Detection Plugin

Scans text files for secrets using patterns from the database.
Combines Aho-Corasick keyword matching with regex validation and
Shannon entropy analysis to reduce false positives.
Never stores or displays plaintext secrets.
"""

import re
import math
import logging
from typing import List, Dict, Set

from .base import ScannerPlugin, PluginResult, Finding
from ..database.connection import get_db
from ..structures.aho_corasick import AhoCorasickAutomaton
from ..structures.lru_cache import LRUCache

logger = logging.getLogger("codeshield.plugins.secrets")

# Default secrets patterns seeded if database is empty
DEFAULT_SECRETS_PATTERNS = [
    {"pattern_id": "SEC-001", "name": "AWS Access Key",
     "pattern": r'AKIA[0-9A-Z]{16}', "severity": "CRITICAL",
     "description": "AWS Access Key ID found in source code.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-002", "name": "AWS Secret Key",
     "pattern": r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']',
     "severity": "CRITICAL",
     "description": "AWS Secret Access Key found in source code.",
     "entropy_threshold": 3.5},
    {"pattern_id": "SEC-003", "name": "GitHub Token",
     "pattern": r'ghp_[0-9a-zA-Z]{36}', "severity": "CRITICAL",
     "description": "GitHub personal access token found.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-004", "name": "Google API Key",
     "pattern": r'AIza[0-9A-Za-z\-_]{35}', "severity": "CRITICAL",
     "description": "Google API Key found in source code.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-005", "name": "Private RSA Key",
     "pattern": r'-----BEGIN RSA PRIVATE KEY-----', "severity": "CRITICAL",
     "description": "RSA private key found in source code.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-006", "name": "Private EC Key",
     "pattern": r'-----BEGIN EC PRIVATE KEY-----', "severity": "CRITICAL",
     "description": "EC private key found in source code.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-007", "name": "JWT Token",
     "pattern": r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
     "severity": "HIGH",
     "description": "JSON Web Token found in source code.",
     "entropy_threshold": 3.0},
    {"pattern_id": "SEC-008", "name": "Slack Token",
     "pattern": r'xox[baprs]-[0-9A-Za-z\-]{10,48}', "severity": "HIGH",
     "description": "Slack API token found in source code.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-009", "name": "Stripe API Key",
     "pattern": r'(?:r|s)k_(live|test)_[0-9a-zA-Z]{24}', "severity": "HIGH",
     "description": "Stripe API key found in source code.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-010", "name": "Generic Secret",
     "pattern": r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']',
     "severity": "HIGH",
     "description": "Generic secret/password assignment found.",
     "entropy_threshold": 2.5},
    {"pattern_id": "SEC-011", "name": "Database Connection String",
     "pattern": r'(?i)(mongodb|postgres|mysql|mssql)://[^"\'>\\s]+:[^"\'>\\s]+@',
     "severity": "HIGH",
     "description": "Database connection string with credentials.",
     "entropy_threshold": 0.0},
    {"pattern_id": "SEC-012", "name": "Bearer Token",
     "pattern": r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*',
     "severity": "MEDIUM",
     "description": "Bearer authentication token found.",
     "entropy_threshold": 3.0},
    {"pattern_id": "SEC-013", "name": "Generic API Key",
     "pattern": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9]{16,}["\']',
     "severity": "HIGH",
     "description": "API key assignment found in source code.",
     "entropy_threshold": 3.0},
    {"pattern_id": "SEC-014", "name": "Private Key Block",
     "pattern": r'-----BEGIN (?:DSA |OPENSSH )?PRIVATE KEY-----',
     "severity": "CRITICAL",
     "description": "Private key file content found in source.",
     "entropy_threshold": 0.0},
]


def _shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy indicates more randomness (more likely a real secret).
    Typical threshold: 3.5+ bits per character suggests high-entropy secret.
    """
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def _redact_secret(line: str) -> str:
    """
    Redact sensitive values from a line for safe storage/display.
    Never store or display plaintext secrets.
    """
    # Redact quoted strings that look like secrets
    redacted = re.sub(
        r'(["\'])(.{3}).+?(.{2})\1',
        r'\1\2****\3\1',
        line.strip()
    )
    # Redact long alphanumeric sequences
    redacted = re.sub(
        r'([A-Za-z0-9/+]{3})[A-Za-z0-9/+]{10,}([A-Za-z0-9/+]{3})',
        r'\1****\2',
        redacted
    )
    return redacted[:120]


class SecretsPlugin(ScannerPlugin):
    """
    Secrets detection scanner using Aho-Corasick + regex + entropy.
    Excludes binary files, minified files, and test fixtures.
    """

    def __init__(self):
        self._patterns: List[dict] = []
        self._automaton = AhoCorasickAutomaton()
        self._keyword_map: Dict[str, List[str]] = {}
        self._compiled: Dict[str, re.Pattern] = {}

    @property
    def name(self) -> str:
        return "secrets"

    @property
    def description(self) -> str:
        return "Secrets detection — find exposed credentials and keys"

    @property
    def priority(self) -> int:
        return 30

    def initialize(self) -> None:
        """Load patterns from database and build search structures."""
        self._load_patterns()
        self._build_automaton()

    def _load_patterns(self) -> None:
        """Load secrets patterns from database, seeding defaults if empty."""
        db = get_db()

        count = db.fetchone("SELECT COUNT(*) as c FROM secrets_patterns")
        if count and count["c"] == 0:
            logger.info("Seeding %d default secrets patterns",
                        len(DEFAULT_SECRETS_PATTERNS))
            with db.transaction() as conn:
                for pat in DEFAULT_SECRETS_PATTERNS:
                    conn.execute(
                        "INSERT OR IGNORE INTO secrets_patterns "
                        "(pattern_id, name, pattern, severity, "
                        "description, entropy_threshold) "
                        "VALUES (?,?,?,?,?,?)",
                        (pat["pattern_id"], pat["name"], pat["pattern"],
                         pat["severity"], pat["description"],
                         pat["entropy_threshold"])
                    )

        rows = db.fetchall(
            "SELECT * FROM secrets_patterns WHERE enabled = 1"
        )
        self._patterns = [dict(r) for r in rows]

        # Pre-compile regex patterns
        for pat in self._patterns:
            try:
                self._compiled[pat["pattern_id"]] = re.compile(pat["pattern"])
            except re.error as exc:
                logger.warning("Invalid regex in secret pattern %s: %s",
                               pat["pattern_id"], exc)

        logger.info("Loaded %d secrets patterns", len(self._patterns))

    def _build_automaton(self) -> None:
        """Build Aho-Corasick automaton with keywords from patterns."""
        self._automaton = AhoCorasickAutomaton()
        self._keyword_map = {}

        for pat in self._patterns:
            # Extract literal keywords from the regex
            keywords = self._extract_keywords(pat["pattern"])
            for kw in keywords:
                if kw not in self._keyword_map:
                    self._keyword_map[kw] = []
                self._keyword_map[kw].append(pat["pattern_id"])
                self._automaton.add_pattern(pat["pattern_id"], kw)

        self._automaton.build()

    def _extract_keywords(self, pattern: str) -> List[str]:
        """Extract literal keywords from regex for AC pre-filtering."""
        cleaned = re.sub(r'\(\?[imslux:]*\)', '', pattern)
        cleaned = re.sub(r'\[.*?\]', '', cleaned)
        cleaned = re.sub(r'\\[dswDSWbB]', '', cleaned)
        cleaned = re.sub(r'[{}()|?*+^$]', ' ', cleaned)
        cleaned = re.sub(r'\\(.)', r'\1', cleaned)

        words = re.findall(r'[a-zA-Z_\-]{3,}', cleaned)
        seen = set()
        result = []
        for w in words:
            lower = w.lower()
            if lower not in seen and len(lower) >= 3:
                seen.add(lower)
                result.append(lower)
        return result[:3]

    def execute(self, context) -> PluginResult:
        """Scan all text files for secrets."""
        findings = []
        files_scanned = 0

        for fi in context.text_files:
            # Skip binary, minified, and test fixture files
            if fi.is_binary or fi.is_minified:
                continue
            if fi.is_test:
                continue

            files_scanned += 1
            file_findings = self._scan_file(fi)
            findings.extend(file_findings)

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            files_scanned=files_scanned,
            metadata={"patterns_loaded": len(self._patterns)}
        )

    def _scan_file(self, file_info) -> List[Finding]:
        """Scan a single file for secrets using streaming line processing."""
        findings = []

        try:
            with open(file_info.absolute_path, "r",
                      encoding="utf-8", errors="ignore") as fh:
                for line_num, line in enumerate(fh, 1):
                    # Skip empty/whitespace lines
                    if not line.strip():
                        continue

                    # Aho-Corasick pre-filter
                    ac_matches = self._automaton.search(line)
                    if not ac_matches:
                        continue

                    # Get candidate pattern IDs
                    candidate_ids = set()
                    for match in ac_matches:
                        for pid in self._keyword_map.get(
                                match.pattern_text, []):
                            candidate_ids.add(pid)

                    # Run full regex for candidates
                    for pat in self._patterns:
                        if pat["pattern_id"] not in candidate_ids:
                            continue

                        compiled = self._compiled.get(pat["pattern_id"])
                        if not compiled:
                            continue

                        m = compiled.search(line)
                        if not m:
                            continue

                        # Entropy check to reduce false positives
                        matched_text = m.group(0)
                        threshold = pat.get("entropy_threshold", 0.0)
                        if threshold > 0:
                            entropy = _shannon_entropy(matched_text)
                            if entropy < threshold:
                                continue

                        # Redact the secret — NEVER store plaintext
                        redacted = _redact_secret(line)

                        findings.append(Finding(
                            plugin_name=self.name,
                            severity=pat["severity"],
                            title=f"Secret Detected: {pat['name']}",
                            description=pat["description"],
                            file_path=file_info.path,
                            line_number=line_num,
                            code_snippet=redacted,
                            remediation=(
                                "Remove the secret immediately. "
                                "Rotate the credential. "
                                "Use environment variables or a "
                                "secrets manager."
                            ),
                            rule_id=pat["pattern_id"],
                        ))

        except Exception as exc:
            logger.warning("Error scanning %s for secrets: %s",
                           file_info.path, exc)

        return findings
