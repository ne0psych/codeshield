"""
CodeShield API Security Plugin
Detects insecure API usage, auth misconfigs, sensitive data exposure,
and validates OpenAPI/Swagger definitions.
"""
import re
import json
import logging
from typing import List
from ..plugins.base import ScannerPlugin, PluginResult, Finding

logger = logging.getLogger("codeshield.plugins.apisecurity")

API_PATTERNS = [
    {
        "id": "API-001", "title": "HTTP Basic Auth over plaintext",
        "pattern": r'(?:Authorization|auth).*(?:Basic\s+|base64)',
        "severity": "HIGH", "cwe": "CWE-319",
        "desc": "HTTP Basic Auth transmits credentials in base64 (not encrypted).",
        "fix": "Use token-based auth (OAuth2/JWT) or ensure HTTPS enforcement.",
    },
    {
        "id": "API-002", "title": "Hardcoded API key in source",
        "pattern": r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
        "severity": "HIGH", "cwe": "CWE-798",
        "desc": "API key is hardcoded in source code.",
        "fix": "Move API keys to environment variables or a secrets manager.",
    },
    {
        "id": "API-003", "title": "CORS wildcard origin",
        "pattern": r'(?:Access-Control-Allow-Origin|cors.*origin).*\*',
        "severity": "MEDIUM", "cwe": "CWE-942",
        "desc": "CORS is configured to allow all origins.",
        "fix": "Restrict CORS to specific trusted domains.",
    },
    {
        "id": "API-004", "title": "Disabled SSL/TLS verification",
        "pattern": r'verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER.*(?:false|0)|rejectUnauthorized.*false',
        "severity": "HIGH", "cwe": "CWE-295",
        "desc": "SSL/TLS certificate verification is disabled.",
        "fix": "Enable certificate verification in all HTTP client configurations.",
    },
    {
        "id": "API-005", "title": "Sensitive data in URL query parameters",
        "pattern": r'(?:password|secret|token|api_key|ssn|credit_card)\s*=.*(?:request\.(?:args|params|query)|req\.query)',
        "severity": "HIGH", "cwe": "CWE-598",
        "desc": "Sensitive data passed in URL query parameters (logged in server/proxy logs).",
        "fix": "Send sensitive data in request body or headers, never in URL parameters.",
    },
    {
        "id": "API-006", "title": "Missing rate limiting",
        "pattern": r'@app\.route|@router\.(get|post|put|delete)',
        "severity": "INFO", "cwe": "CWE-307",
        "desc": "API endpoint without visible rate limiting.",
        "fix": "Implement rate limiting middleware on all API endpoints.",
    },
    {
        "id": "API-007", "title": "GraphQL introspection enabled",
        "pattern": r'introspection\s*[=:]\s*(?:True|true|1)',
        "severity": "MEDIUM", "cwe": "CWE-200",
        "desc": "GraphQL introspection is enabled, exposing full API schema.",
        "fix": "Disable introspection in production environments.",
    },
    {
        "id": "API-008", "title": "Verbose error response to client",
        "pattern": r'(?:traceback|stack_trace|stacktrace|exception).*(?:response|json|send|render)',
        "severity": "MEDIUM", "cwe": "CWE-209",
        "desc": "Stack traces or verbose errors may be exposed to API consumers.",
        "fix": "Return generic error messages to clients. Log details server-side only.",
    },
]

OPENAPI_CHECKS = [
    ("no-auth-scheme", "Security scheme not defined", "CWE-306", "HIGH",
     lambda spec: not spec.get("components", {}).get("securitySchemes")),
    ("no-global-security", "No global security requirement", "CWE-862", "HIGH",
     lambda spec: not spec.get("security")),
    ("http-server", "Non-HTTPS server URL", "CWE-319", "HIGH",
     lambda spec: any(s.get("url", "").startswith("http://")
                      for s in spec.get("servers", []))),
]


class APISecurityPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "apisecurity"

    @property
    def description(self) -> str:
        return "API security: insecure patterns, auth misconfigs, OpenAPI validation"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def priority(self) -> int:
        return 60

    def execute(self, context) -> PluginResult:
        findings: List[Finding] = []
        files_scanned = 0

        for fi in context.source_files:
            if fi.is_binary or fi.is_minified or fi.size > 2_000_000:
                continue
            files_scanned += 1

            try:
                with open(fi.absolute_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            # Pattern-based API checks
            for pat in API_PATTERNS:
                for m in re.finditer(pat["pattern"], content, re.I | re.M):
                    line_num = content[:m.start()].count("\n") + 1
                    start = max(0, m.start() - 40)
                    end = min(len(content), m.end() + 40)
                    snippet = content[start:end].strip()

                    findings.append(Finding(
                        plugin_name=self.name, severity=pat["severity"],
                        title=pat["title"], description=pat["desc"],
                        file_path=fi.path, line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation=pat["fix"],
                        rule_id=pat["id"], cwe_id=pat["cwe"],
                    ))

            # OpenAPI/Swagger detection and validation
            fname = fi.path.lower()
            if any(k in fname for k in ("swagger", "openapi", "api-spec")):
                findings.extend(self._check_openapi(fi, content))

        return PluginResult(
            plugin_name=self.name, findings=findings,
            files_scanned=files_scanned,
        )

    def _check_openapi(self, fi, content: str) -> List[Finding]:
        results = []
        try:
            spec = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return results

        if not spec.get("openapi") and not spec.get("swagger"):
            return results

        for check_id, title, cwe, sev, check_fn in OPENAPI_CHECKS:
            try:
                if check_fn(spec):
                    results.append(Finding(
                        plugin_name=self.name, severity=sev,
                        title=f"OpenAPI: {title}",
                        description=f"OpenAPI specification issue: {title}",
                        file_path=fi.path, rule_id=f"OAPI-{check_id}",
                        cwe_id=cwe,
                        remediation="Review and secure OpenAPI specification.",
                    ))
            except Exception:
                pass

        # Check individual endpoints for missing auth
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.startswith("x-") or not isinstance(op, dict):
                    continue
                if not op.get("security") and not spec.get("security"):
                    results.append(Finding(
                        plugin_name=self.name, severity="MEDIUM",
                        title=f"Unauthenticated endpoint: {method.upper()} {path}",
                        description=f"Endpoint {method.upper()} {path} has no security requirement.",
                        file_path=fi.path, rule_id="OAPI-no-endpoint-auth",
                        cwe_id="CWE-306",
                        remediation="Add security requirement to this endpoint.",
                    ))
        return results
