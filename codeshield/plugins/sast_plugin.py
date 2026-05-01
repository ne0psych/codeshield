"""
SAST Plugin — Static Application Security Testing

Matches source code against rule patterns loaded from the database.
Uses Aho-Corasick automaton for multi-pattern matching plus regex
for rules requiring complex pattern syntax. Language-aware scanning
applies only relevant rules per file.
"""

import re
import logging
from typing import List, Dict, Set

from .base import ScannerPlugin, PluginResult, Finding
from ..database.connection import get_db
from ..structures.aho_corasick import AhoCorasickAutomaton
from ..structures.inverted_index import InvertedIndex
from ..structures.lru_cache import LRUCache

logger = logging.getLogger("codeshield.plugins.sast")

# Default SAST rules seeded into the database if none exist
DEFAULT_SAST_RULES = [
    {"rule_id": "SAST-001", "title": "SQL Injection", "severity": "CRITICAL",
     "pattern": r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*?%[sd]|f["\'].*?SELECT|f["\'].*?INSERT|f["\'].*?UPDATE|f["\'].*?DELETE',
     "language": "python", "cwe_id": "CWE-89", "owasp_category": "A03:2021",
     "description": "SQL query built with string formatting allows injection.",
     "remediation": "Use parameterized queries or an ORM. Never concatenate user input into SQL."},
    {"rule_id": "SAST-002", "title": "Command Injection", "severity": "CRITICAL",
     "pattern": r'(os\.system|subprocess\.call|subprocess\.Popen|os\.popen)\s*\([^)]*\+|shell\s*=\s*True',
     "language": "python", "cwe_id": "CWE-78", "owasp_category": "A03:2021",
     "description": "Shell command with user-controlled input or shell=True.",
     "remediation": "Use subprocess with argument lists, never shell=True. Validate all inputs."},
    {"rule_id": "SAST-003", "title": "Hardcoded Credentials", "severity": "HIGH",
     "pattern": r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*["\'][^"\']{6,}["\']',
     "language": "*", "cwe_id": "CWE-798", "owasp_category": "A07:2021",
     "description": "Hardcoded credential found in source code.",
     "remediation": "Store secrets in environment variables or a vault."},
    {"rule_id": "SAST-004", "title": "Path Traversal", "severity": "HIGH",
     "pattern": r'open\s*\([^)]*\+|open\s*\(.*?request\.|open\s*\(.*?input\(',
     "language": "python", "cwe_id": "CWE-22", "owasp_category": "A01:2021",
     "description": "File path from user input enables directory traversal.",
     "remediation": "Validate paths with os.path.abspath; ensure they stay within the allowed directory."},
    {"rule_id": "SAST-005", "title": "Cross-Site Scripting (XSS)", "severity": "HIGH",
     "pattern": r'(render_template_string|Markup\(|\.html\(|innerHTML\s*=)',
     "language": "*", "cwe_id": "CWE-79", "owasp_category": "A03:2021",
     "description": "User-controlled data rendered as HTML without escaping.",
     "remediation": "Use template auto-escaping. Never inject raw user data into HTML."},
    {"rule_id": "SAST-006", "title": "Weak Cryptographic Algorithm", "severity": "MEDIUM",
     "pattern": r'(?i)(hashlib\.md5|hashlib\.sha1|DES\.|RC4\.|Blowfish\.)',
     "language": "*", "cwe_id": "CWE-327", "owasp_category": "A02:2021",
     "description": "Deprecated or weak cryptographic algorithm.",
     "remediation": "Use SHA-256/SHA-3 for hashing, AES-256-GCM for encryption."},
    {"rule_id": "SAST-007", "title": "Insecure Deserialization", "severity": "HIGH",
     "pattern": r'(pickle\.loads|pickle\.load|yaml\.load\s*\([^)]*\)(?!\s*,?\s*Loader))',
     "language": "python", "cwe_id": "CWE-502", "owasp_category": "A08:2021",
     "description": "Insecure deserialization can lead to arbitrary code execution.",
     "remediation": "Use pickle only with trusted data. For YAML, use yaml.safe_load()."},
    {"rule_id": "SAST-008", "title": "Debug Code in Production", "severity": "LOW",
     "pattern": r'(console\.log\(|debugger;|pdb\.set_trace|breakpoint\(\))',
     "language": "*", "cwe_id": "CWE-489", "owasp_category": "A05:2021",
     "description": "Debug statements or breakpoints left in code.",
     "remediation": "Remove all debug statements before deploying to production."},
    {"rule_id": "SAST-009", "title": "Server-Side Request Forgery", "severity": "HIGH",
     "pattern": r'(requests\.get|requests\.post|urllib\.request\.urlopen)\s*\([^)]*request\.',
     "language": "python", "cwe_id": "CWE-918", "owasp_category": "A10:2021",
     "description": "HTTP request with user-controlled URL could allow SSRF.",
     "remediation": "Validate/allowlist URLs. Block requests to internal/private IP ranges."},
    {"rule_id": "SAST-010", "title": "Open Redirect", "severity": "MEDIUM",
     "pattern": r'(redirect|location)\s*[=(]\s*[^)]*request\.(args|form|params|GET|POST)',
     "language": "*", "cwe_id": "CWE-601", "owasp_category": "A01:2021",
     "description": "Redirect target from user input enables phishing.",
     "remediation": "Validate redirect URLs against an allowlist of trusted domains."},
    {"rule_id": "SAST-011", "title": "Code Injection via eval()", "severity": "CRITICAL",
     "pattern": r'\beval\s*\([^)]*(?:request|input|params|args)',
     "language": "*", "cwe_id": "CWE-94", "owasp_category": "A03:2021",
     "description": "eval() with user-controlled input allows arbitrary code execution.",
     "remediation": "Never use eval(). Use ast.literal_eval() for safe parsing."},
    {"rule_id": "SAST-012", "title": "Insecure Randomness", "severity": "MEDIUM",
     "pattern": r'\brandom\.(random|randint|choice|shuffle)\b',
     "language": "python", "cwe_id": "CWE-330", "owasp_category": "A02:2021",
     "description": "Non-cryptographic random used for security-sensitive operations.",
     "remediation": "Use secrets module or os.urandom() for cryptographic randomness."},
    {"rule_id": "SAST-013", "title": "SQL Injection (JavaScript)", "severity": "CRITICAL",
     "pattern": r'(?i)(\.query|\.execute)\s*\(\s*[`"\'].*?\$\{|\.query\s*\([^)]*\+',
     "language": "javascript", "cwe_id": "CWE-89", "owasp_category": "A03:2021",
     "description": "SQL query built with template literals or concatenation.",
     "remediation": "Use parameterized queries with ? placeholders."},
    {"rule_id": "SAST-014", "title": "Prototype Pollution", "severity": "HIGH",
     "pattern": r'(Object\.assign|__proto__|constructor\[|\.prototype\[)',
     "language": "javascript", "cwe_id": "CWE-1321", "owasp_category": "A03:2021",
     "description": "Potential prototype pollution via uncontrolled property assignment.",
     "remediation": "Validate object keys. Use Map instead of plain objects for dynamic keys."},
    {"rule_id": "SAST-015", "title": "Insecure TLS Configuration", "severity": "HIGH",
     "pattern": r'(?i)(verify\s*=\s*False|CERT_NONE|ssl\.PROTOCOL_TLS(?!v1_2|v1_3)|InsecureRequestWarning)',
     "language": "*", "cwe_id": "CWE-295", "owasp_category": "A07:2021",
     "description": "TLS certificate verification disabled or weak protocol used.",
     "remediation": "Always verify TLS certificates. Use TLS 1.2+ minimum."},
    {"rule_id": "SAST-016", "title": "Hardcoded IP Address", "severity": "LOW",
     "pattern": r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
     "language": "*", "cwe_id": "CWE-547", "owasp_category": "A05:2021",
     "description": "Hardcoded internal IP address found.",
     "remediation": "Use configuration files or service discovery for IP addresses."},
]


class SASTPlugin(ScannerPlugin):
    """
    Static Application Security Testing scanner.
    Loads rules from database, uses Aho-Corasick for keyword pre-filtering
    and regex for precise pattern matching. Language-aware scanning.
    """

    def __init__(self):
        self._rules: List[dict] = []
        self._rule_index = InvertedIndex()
        # Aho-Corasick for fast keyword pre-filtering
        self._automaton = AhoCorasickAutomaton()
        # Map from keyword -> list of rule_ids that use that keyword
        self._keyword_rules: Dict[str, List[str]] = {}
        self._cache = LRUCache(capacity=512)

    @property
    def name(self) -> str:
        return "sast"

    @property
    def description(self) -> str:
        return "Static Application Security Testing — pattern-based code analysis"

    @property
    def priority(self) -> int:
        return 10

    def initialize(self) -> None:
        """Load rules from database and build search structures."""
        self._load_rules()
        self._build_automaton()

    def _load_rules(self) -> None:
        """Load SAST rules from the database, seeding defaults if empty."""
        db = get_db()

        # Seed defaults if no rules exist
        count = db.fetchone("SELECT COUNT(*) as c FROM sast_rules")
        if count and count["c"] == 0:
            logger.info("Seeding %d default SAST rules", len(DEFAULT_SAST_RULES))
            with db.transaction() as conn:
                for rule in DEFAULT_SAST_RULES:
                    conn.execute(
                        "INSERT OR IGNORE INTO sast_rules "
                        "(rule_id, title, pattern, language, severity, "
                        "cwe_id, owasp_category, description, remediation) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (rule["rule_id"], rule["title"], rule["pattern"],
                         rule["language"], rule["severity"], rule["cwe_id"],
                         rule["owasp_category"], rule["description"],
                         rule["remediation"])
                    )

        # Load all enabled rules
        rows = db.fetchall(
            "SELECT * FROM sast_rules WHERE enabled = 1"
        )
        self._rules = [dict(r) for r in rows]

        # Build inverted index for language-aware lookups
        for rule in self._rules:
            self._rule_index.add_item(
                rule["rule_id"], rule,
                index_fields=["language", "severity", "cwe_id"]
            )

        logger.info("Loaded %d SAST rules", len(self._rules))

    def _build_automaton(self) -> None:
        """
        Build Aho-Corasick automaton with extracted keywords from rules.
        Each rule's pattern is analyzed for literal keywords that can
        serve as fast pre-filters before running the full regex.
        """
        self._automaton = AhoCorasickAutomaton()
        self._keyword_rules = {}

        for rule in self._rules:
            # Extract meaningful literal keywords from the regex pattern
            keywords = self._extract_keywords(rule["pattern"])
            for kw in keywords:
                if kw not in self._keyword_rules:
                    self._keyword_rules[kw] = []
                self._keyword_rules[kw].append(rule["rule_id"])
                self._automaton.add_pattern(
                    rule["rule_id"], kw,
                    metadata={"rule_id": rule["rule_id"]}
                )

        self._automaton.build()

    def _extract_keywords(self, pattern: str) -> List[str]:
        """
        Extract literal keyword strings from a regex pattern for
        Aho-Corasick pre-filtering. We find unescaped alphabetic
        sequences of length >= 3 that likely appear literally.
        """
        # Remove regex special constructs
        cleaned = re.sub(r'\(\?[imslux:]*\)', '', pattern)
        cleaned = re.sub(r'\[.*?\]', '', cleaned)
        cleaned = re.sub(r'\\[dswDSWbB]', '', cleaned)
        cleaned = re.sub(r'[{}()|?*+^$]', ' ', cleaned)
        cleaned = re.sub(r'\\(.)', r'\1', cleaned)

        words = re.findall(r'[a-zA-Z_\.]{3,}', cleaned)
        # Deduplicate while preserving order
        seen = set()
        result = []
        for w in words:
            lower = w.lower()
            if lower not in seen:
                seen.add(lower)
                result.append(lower)
        return result[:5]  # Limit to top 5 keywords per rule

    def execute(self, context) -> PluginResult:
        """Run SAST analysis on all source files in the context."""
        findings = []
        files_scanned = 0

        for file_info in context.source_files:
            if file_info.is_binary or file_info.is_minified:
                continue

            # Get rules applicable to this file's language
            applicable_rules = self._get_rules_for_language(
                file_info.language
            )
            if not applicable_rules:
                continue

            files_scanned += 1
            file_findings = self._scan_file(file_info, applicable_rules)
            findings.extend(file_findings)

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            files_scanned=files_scanned,
            metadata={"rules_loaded": len(self._rules)}
        )

    def _get_rules_for_language(self, language: str) -> List[dict]:
        """Get rules applicable to a specific language using the inverted index."""
        cache_key = f"sast_rules_{language}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        # Get rules for this specific language + universal rules ("*")
        lang_ids = self._rule_index.lookup("language", language)
        universal_ids = self._rule_index.lookup("language", "*")
        all_ids = lang_ids | universal_ids

        rules = [r for r in self._rules if r["rule_id"] in all_ids]
        self._cache.put(cache_key, rules)
        return rules

    def _scan_file(self, file_info, rules: List[dict]) -> List[Finding]:
        """
        Scan a single file against applicable rules.
        Uses streaming line-by-line processing — never loads entire file.
        """
        findings = []
        compiled_patterns = {}

        # Pre-compile regex patterns
        for rule in rules:
            try:
                compiled_patterns[rule["rule_id"]] = re.compile(
                    rule["pattern"]
                )
            except re.error:
                logger.warning("Invalid regex in rule %s", rule["rule_id"])

        try:
            # Stream file line-by-line using generator
            with open(file_info.absolute_path, "r",
                      encoding="utf-8", errors="ignore") as fh:
                for line_num, line in enumerate(fh, 1):
                    # Quick Aho-Corasick pre-filter: check for keyword hits
                    ac_matches = self._automaton.search(line)
                    if not ac_matches:
                        continue

                    # Get candidate rule IDs from keyword matches
                    candidate_ids = set()
                    for match in ac_matches:
                        for rid in self._keyword_rules.get(
                                match.pattern_text, []):
                            candidate_ids.add(rid)

                    # Run full regex only for candidate rules
                    for rule in rules:
                        if rule["rule_id"] not in candidate_ids:
                            continue
                        pattern = compiled_patterns.get(rule["rule_id"])
                        if pattern and pattern.search(line):
                            snippet = line.strip()[:120]
                            findings.append(Finding(
                                plugin_name=self.name,
                                severity=rule["severity"],
                                title=rule["title"],
                                description=rule["description"],
                                file_path=file_info.path,
                                line_number=line_num,
                                code_snippet=snippet,
                                remediation=rule["remediation"],
                                rule_id=rule["rule_id"],
                                cwe_id=rule.get("cwe_id", ""),
                                owasp_category=rule.get("owasp_category", ""),
                            ))
        except Exception as exc:
            logger.warning("Error scanning file %s: %s",
                           file_info.path, exc)

        return findings
