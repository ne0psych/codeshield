"""
CodeShield Code Quality & Complexity Plugin
Detects dead code, high cyclomatic complexity, and unsafe patterns.
"""
import re
import logging
from typing import List
from ..plugins.base import ScannerPlugin, PluginResult, Finding

logger = logging.getLogger("codeshield.plugins.codequality")

DEAD_CODE_PATTERNS = [
    {"id": "CQ-001", "pattern": r'#\s*TODO.*(?:remove|delete|dead|unused)', "title": "TODO: Dead code marker",
     "severity": "LOW", "cwe": "CWE-561", "langs": {"python", "javascript", "typescript", "java", "go", "ruby"}},
    {"id": "CQ-002", "pattern": r'^\s*(?:if\s+(?:False|false|0)\s*:)', "title": "Dead branch: always-false condition",
     "severity": "LOW", "cwe": "CWE-561", "langs": {"python"}},
    {"id": "CQ-003", "pattern": r'^\s*(?:if\s*\(\s*(?:false|0)\s*\))', "title": "Dead branch: always-false condition",
     "severity": "LOW", "cwe": "CWE-561", "langs": {"javascript", "typescript", "java", "c", "cpp", "csharp"}},
    {"id": "CQ-004", "pattern": r'^\s*//\s*@deprecated|^\s*#\s*DEPRECATED', "title": "Deprecated code still present",
     "severity": "LOW", "cwe": "CWE-561", "langs": {"python", "javascript", "typescript", "java"}},
]

UNSAFE_PATTERNS = [
    {"id": "CQ-010", "pattern": r'\bglobal\s+\w+', "title": "Global variable modification",
     "severity": "MEDIUM", "cwe": "CWE-1108", "langs": {"python"},
     "fix": "Avoid global state; use dependency injection or class attributes."},
    {"id": "CQ-011", "pattern": r'(?:catch|except)\s*(?:\(\s*\)|:)\s*$', "title": "Empty exception handler",
     "severity": "MEDIUM", "cwe": "CWE-390", "langs": {"python", "javascript", "java"},
     "fix": "Always handle or log exceptions. Never silently swallow errors."},
    {"id": "CQ-012", "pattern": r'(?:setTimeout|setInterval)\s*\(\s*["\']', "title": "String-based timer (eval-like)",
     "severity": "MEDIUM", "cwe": "CWE-95", "langs": {"javascript", "typescript"},
     "fix": "Pass function references to setTimeout/setInterval, not strings."},
    {"id": "CQ-013", "pattern": r'(?:chmod|os\.chmod)\s*\(\s*.*0o?777', "title": "World-writable file permissions",
     "severity": "HIGH", "cwe": "CWE-732", "langs": {"python", "shell"},
     "fix": "Use restrictive permissions (e.g., 0o644 or 0o600)."},
    {"id": "CQ-014", "pattern": r'(?:Thread|Process)\s*\(.*daemon\s*=\s*True', "title": "Daemon thread without cleanup",
     "severity": "LOW", "cwe": "CWE-404", "langs": {"python"},
     "fix": "Ensure daemon threads/processes have proper cleanup handlers."},
]


def _count_complexity(content: str, language: str) -> int:
    """Estimate cyclomatic complexity by counting decision points."""
    decision_kw = {
        "python": [r'\bif\b', r'\belif\b', r'\bfor\b', r'\bwhile\b',
                   r'\band\b', r'\bor\b', r'\bexcept\b', r'\bwith\b'],
        "javascript": [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b',
                       r'\bcase\b', r'\bcatch\b', r'&&', r'\|\|', r'\?\s*'],
        "typescript": [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b',
                       r'\bcase\b', r'\bcatch\b', r'&&', r'\|\|', r'\?\s*'],
        "java": [r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b',
                 r'\bcase\b', r'\bcatch\b', r'&&', r'\|\|'],
    }
    patterns = decision_kw.get(language, decision_kw.get("javascript", []))
    count = 1
    for pat in patterns:
        count += len(re.findall(pat, content))
    return count


class CodeQualityPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "codequality"

    @property
    def description(self) -> str:
        return "Code quality: dead code, cyclomatic complexity, unsafe patterns"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def priority(self) -> int:
        return 200

    def execute(self, context) -> PluginResult:
        findings: List[Finding] = []
        files_scanned = 0
        COMPLEXITY_THRESHOLD = 20

        for fi in context.source_files:
            if fi.is_binary or fi.is_minified or fi.size > 1_000_000:
                continue
            if fi.language == "unknown":
                continue
            files_scanned += 1

            try:
                with open(fi.absolute_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            # Dead code patterns
            for pat in DEAD_CODE_PATTERNS:
                if fi.language not in pat.get("langs", set()):
                    continue
                for m in re.finditer(pat["pattern"], content, re.I | re.M):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        plugin_name=self.name, severity=pat["severity"],
                        title=pat["title"], file_path=fi.path,
                        line_number=line_num, rule_id=pat["id"],
                        cwe_id=pat.get("cwe", ""),
                        code_snippet=m.group()[:150],
                        remediation="Remove dead or unreachable code to reduce attack surface.",
                    ))

            # Unsafe patterns
            for pat in UNSAFE_PATTERNS:
                if fi.language not in pat.get("langs", set()):
                    continue
                for m in re.finditer(pat["pattern"], content, re.I | re.M):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        plugin_name=self.name, severity=pat["severity"],
                        title=pat["title"], file_path=fi.path,
                        line_number=line_num, rule_id=pat["id"],
                        cwe_id=pat.get("cwe", ""),
                        code_snippet=m.group()[:150],
                        remediation=pat.get("fix", "Review and fix unsafe code pattern."),
                    ))

            # Cyclomatic complexity
            complexity = _count_complexity(content, fi.language)
            if complexity > COMPLEXITY_THRESHOLD:
                findings.append(Finding(
                    plugin_name=self.name, severity="MEDIUM",
                    title=f"High cyclomatic complexity: {complexity}",
                    description=f"File has estimated complexity of {complexity} (threshold: {COMPLEXITY_THRESHOLD}).",
                    file_path=fi.path, rule_id="CQ-100",
                    cwe_id="CWE-1121",
                    remediation="Refactor complex functions into smaller, focused functions.",
                ))

        return PluginResult(
            plugin_name=self.name, findings=findings,
            files_scanned=files_scanned,
        )
