"""
CodeShield Central Security Mappings
Single source of truth for CWE, OWASP Top 10, MITRE ATT&CK, and compliance mappings.
All plugins and report generators reference this module exclusively.
"""

# ── CWE → OWASP Top 10 (2021) Mapping ──────────────────────────────────────
CWE_TO_OWASP = {
    "CWE-22":  "A01:2021", "CWE-23":  "A01:2021", "CWE-35":  "A01:2021",
    "CWE-59":  "A01:2021", "CWE-200": "A01:2021", "CWE-264": "A01:2021",
    "CWE-275": "A01:2021", "CWE-284": "A01:2021", "CWE-285": "A01:2021",
    "CWE-352": "A01:2021", "CWE-359": "A01:2021", "CWE-377": "A01:2021",
    "CWE-402": "A01:2021", "CWE-425": "A01:2021", "CWE-441": "A01:2021",
    "CWE-497": "A01:2021", "CWE-538": "A01:2021", "CWE-540": "A01:2021",
    "CWE-548": "A01:2021", "CWE-552": "A01:2021", "CWE-566": "A01:2021",
    "CWE-601": "A01:2021", "CWE-639": "A01:2021", "CWE-651": "A01:2021",
    "CWE-668": "A01:2021", "CWE-706": "A01:2021", "CWE-862": "A01:2021",
    "CWE-863": "A01:2021", "CWE-913": "A01:2021", "CWE-922": "A01:2021",
    "CWE-1275":"A01:2021",

    "CWE-261": "A02:2021", "CWE-296": "A02:2021", "CWE-310": "A02:2021",
    "CWE-319": "A02:2021", "CWE-321": "A02:2021", "CWE-322": "A02:2021",
    "CWE-323": "A02:2021", "CWE-324": "A02:2021", "CWE-325": "A02:2021",
    "CWE-326": "A02:2021", "CWE-327": "A02:2021", "CWE-328": "A02:2021",
    "CWE-329": "A02:2021", "CWE-330": "A02:2021", "CWE-331": "A02:2021",
    "CWE-335": "A02:2021", "CWE-336": "A02:2021", "CWE-338": "A02:2021",
    "CWE-340": "A02:2021", "CWE-347": "A02:2021", "CWE-523": "A02:2021",
    "CWE-720": "A02:2021", "CWE-757": "A02:2021", "CWE-759": "A02:2021",
    "CWE-760": "A02:2021", "CWE-780": "A02:2021", "CWE-818": "A02:2021",
    "CWE-916": "A02:2021",

    "CWE-20":  "A03:2021", "CWE-74":  "A03:2021", "CWE-75":  "A03:2021",
    "CWE-77":  "A03:2021", "CWE-78":  "A03:2021", "CWE-79":  "A03:2021",
    "CWE-80":  "A03:2021", "CWE-83":  "A03:2021", "CWE-87":  "A03:2021",
    "CWE-88":  "A03:2021", "CWE-89":  "A03:2021", "CWE-90":  "A03:2021",
    "CWE-91":  "A03:2021", "CWE-93":  "A03:2021", "CWE-94":  "A03:2021",
    "CWE-95":  "A03:2021", "CWE-96":  "A03:2021", "CWE-97":  "A03:2021",
    "CWE-98":  "A03:2021", "CWE-99":  "A03:2021", "CWE-100": "A03:2021",
    "CWE-113": "A03:2021", "CWE-116": "A03:2021", "CWE-138": "A03:2021",
    "CWE-184": "A03:2021", "CWE-470": "A03:2021", "CWE-471": "A03:2021",
    "CWE-564": "A03:2021", "CWE-610": "A03:2021", "CWE-643": "A03:2021",
    "CWE-644": "A03:2021", "CWE-652": "A03:2021", "CWE-917": "A03:2021",
    "CWE-1236":"A03:2021", "CWE-1321":"A03:2021",

    "CWE-73":  "A04:2021", "CWE-183": "A04:2021", "CWE-209": "A04:2021",
    "CWE-213": "A04:2021", "CWE-235": "A04:2021", "CWE-256": "A04:2021",
    "CWE-257": "A04:2021", "CWE-266": "A04:2021", "CWE-269": "A04:2021",
    "CWE-280": "A04:2021", "CWE-311": "A04:2021", "CWE-312": "A04:2021",
    "CWE-313": "A04:2021", "CWE-316": "A04:2021", "CWE-419": "A04:2021",
    "CWE-430": "A04:2021", "CWE-434": "A04:2021", "CWE-444": "A04:2021",
    "CWE-451": "A04:2021", "CWE-472": "A04:2021", "CWE-501": "A04:2021",
    "CWE-522": "A04:2021", "CWE-525": "A04:2021", "CWE-539": "A04:2021",
    "CWE-579": "A04:2021", "CWE-598": "A04:2021", "CWE-602": "A04:2021",
    "CWE-642": "A04:2021", "CWE-646": "A04:2021", "CWE-650": "A04:2021",
    "CWE-653": "A04:2021", "CWE-656": "A04:2021", "CWE-657": "A04:2021",
    "CWE-799": "A04:2021", "CWE-807": "A04:2021", "CWE-840": "A04:2021",
    "CWE-841": "A04:2021", "CWE-927": "A04:2021",

    "CWE-2":   "A05:2021", "CWE-11":  "A05:2021", "CWE-13":  "A05:2021",
    "CWE-15":  "A05:2021", "CWE-16":  "A05:2021", "CWE-260": "A05:2021",
    "CWE-315": "A05:2021", "CWE-520": "A05:2021", "CWE-526": "A05:2021",
    "CWE-537": "A05:2021", "CWE-541": "A05:2021", "CWE-547": "A05:2021",
    "CWE-611": "A05:2021", "CWE-614": "A05:2021", "CWE-756": "A05:2021",
    "CWE-776": "A05:2021", "CWE-942": "A05:2021", "CWE-1004":"A05:2021",
    "CWE-1032":"A05:2021", "CWE-1174":"A05:2021", "CWE-489": "A05:2021",

    "CWE-345": "A06:2021", "CWE-346": "A06:2021", "CWE-353": "A06:2021",
    "CWE-426": "A06:2021", "CWE-427": "A06:2021", "CWE-428": "A06:2021",
    "CWE-431": "A06:2021", "CWE-494": "A06:2021", "CWE-829": "A06:2021",
    "CWE-830": "A06:2021", "CWE-915": "A06:2021",

    "CWE-255": "A07:2021", "CWE-259": "A07:2021", "CWE-287": "A07:2021",
    "CWE-288": "A07:2021", "CWE-290": "A07:2021", "CWE-294": "A07:2021",
    "CWE-295": "A07:2021", "CWE-297": "A07:2021", "CWE-300": "A07:2021",
    "CWE-302": "A07:2021", "CWE-304": "A07:2021", "CWE-306": "A07:2021",
    "CWE-307": "A07:2021", "CWE-346": "A07:2021", "CWE-384": "A07:2021",
    "CWE-521": "A07:2021", "CWE-613": "A07:2021", "CWE-620": "A07:2021",
    "CWE-640": "A07:2021", "CWE-798": "A07:2021", "CWE-940": "A07:2021",
    "CWE-1216":"A07:2021",

    "CWE-134": "A08:2021", "CWE-190": "A08:2021", "CWE-400": "A08:2021",
    "CWE-409": "A08:2021", "CWE-470": "A08:2021", "CWE-471": "A08:2021",
    "CWE-502": "A08:2021", "CWE-506": "A08:2021", "CWE-507": "A08:2021",
    "CWE-508": "A08:2021", "CWE-509": "A08:2021", "CWE-510": "A08:2021",
    "CWE-511": "A08:2021", "CWE-512": "A08:2021", "CWE-513": "A08:2021",
    "CWE-514": "A08:2021", "CWE-515": "A08:2021", "CWE-516": "A08:2021",
    "CWE-784": "A08:2021", "CWE-787": "A08:2021", "CWE-502": "A08:2021",

    "CWE-117": "A09:2021", "CWE-223": "A09:2021", "CWE-532": "A09:2021",
    "CWE-778": "A09:2021",

    "CWE-918": "A10:2021", "CWE-1352":"A10:2021",
}

# ── OWASP Top 10 (2021) Labels ──────────────────────────────────────────────
OWASP_LABELS = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

# ── CWE → MITRE ATT&CK Technique Mapping ───────────────────────────────────
CWE_TO_MITRE = {
    "CWE-78":  "T1059",   # Command and Scripting Interpreter
    "CWE-89":  "T1190",   # Exploit Public-Facing Application
    "CWE-94":  "T1059",   # Command and Scripting Interpreter
    "CWE-79":  "T1189",   # Drive-by Compromise
    "CWE-502": "T1203",   # Exploitation for Client Execution
    "CWE-434": "T1505",   # Server Software Component
    "CWE-798": "T1552.001", # Unsecured Credentials: In Files
    "CWE-312": "T1552.001", # Unsecured Credentials: In Files
    "CWE-327": "T1600",   # Weaken Encryption
    "CWE-295": "T1557",   # Adversary-in-the-Middle
    "CWE-918": "T1090",   # Proxy
    "CWE-611": "T1190",   # Exploit Public-Facing Application
    "CWE-352": "T1185",   # Browser Session Hijacking
    "CWE-22":  "T1083",   # File and Directory Discovery
    "CWE-287": "T1078",   # Valid Accounts
    "CWE-306": "T1078",   # Valid Accounts
    "CWE-384": "T1539",   # Steal Web Session Cookie
    "CWE-601": "T1566.002", # Phishing: Spearphishing Link
    "CWE-330": "T1600",   # Weaken Encryption
    "CWE-494": "T1195",   # Supply Chain Compromise
    "CWE-829": "T1195.001", # Supply Chain: Software Dependencies
    "CWE-506": "T1195.002", # Supply Chain: Software Supply Chain
    "CWE-1321":"T1059",   # Command and Scripting Interpreter
    "CWE-190": "T1499",   # Endpoint Denial of Service
    "CWE-400": "T1499",   # Endpoint Denial of Service
    "CWE-532": "T1530",   # Data from Cloud Storage Object
    "CWE-547": "T1082",   # System Information Discovery
    "CWE-489": "T1082",   # System Information Discovery
}

# ── MITRE ATT&CK Technique Labels ──────────────────────────────────────────
MITRE_LABELS = {
    "T1059":     "Command and Scripting Interpreter",
    "T1190":     "Exploit Public-Facing Application",
    "T1189":     "Drive-by Compromise",
    "T1203":     "Exploitation for Client Execution",
    "T1505":     "Server Software Component",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1600":     "Weaken Encryption",
    "T1557":     "Adversary-in-the-Middle",
    "T1090":     "Proxy",
    "T1185":     "Browser Session Hijacking",
    "T1083":     "File and Directory Discovery",
    "T1078":     "Valid Accounts",
    "T1539":     "Steal Web Session Cookie",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1195":     "Supply Chain Compromise",
    "T1195.001": "Supply Chain: Software Dependencies",
    "T1195.002": "Supply Chain: Software Supply Chain",
    "T1499":     "Endpoint Denial of Service",
    "T1530":     "Data from Cloud Storage Object",
    "T1082":     "System Information Discovery",
}

# ── CWE → PCI-DSS v4.0 Mapping ─────────────────────────────────────────────
CWE_TO_PCI_DSS = {
    "CWE-89":  "6.2.4", "CWE-79":  "6.2.4", "CWE-78":  "6.2.4",
    "CWE-94":  "6.2.4", "CWE-22":  "6.2.4", "CWE-434": "6.2.4",
    "CWE-502": "6.2.4", "CWE-918": "6.2.4", "CWE-917": "6.2.4",
    "CWE-611": "6.2.4", "CWE-1321":"6.2.4",
    "CWE-798": "2.2.2", "CWE-259": "2.2.2", "CWE-312": "3.4.1",
    "CWE-327": "4.2.1", "CWE-326": "4.2.1", "CWE-295": "4.2.1",
    "CWE-330": "4.2.1", "CWE-328": "4.2.1",
    "CWE-287": "8.3",   "CWE-306": "8.3",   "CWE-521": "8.3.6",
    "CWE-307": "8.3.4", "CWE-384": "8.3",
    "CWE-352": "6.2.4", "CWE-601": "6.2.4",
    "CWE-532": "10.3.1", "CWE-117": "10.3.1",
}

# ── CWE → HIPAA Safeguard Mapping ──────────────────────────────────────────
CWE_TO_HIPAA = {
    "CWE-311": "164.312(a)(2)(iv)",  # Encryption and Decryption
    "CWE-312": "164.312(a)(2)(iv)",
    "CWE-319": "164.312(e)(1)",      # Transmission Security
    "CWE-326": "164.312(a)(2)(iv)",
    "CWE-327": "164.312(a)(2)(iv)",
    "CWE-287": "164.312(d)",         # Person or Entity Authentication
    "CWE-306": "164.312(d)",
    "CWE-798": "164.312(d)",
    "CWE-532": "164.312(b)",         # Audit Controls
    "CWE-117": "164.312(b)",
    "CWE-22":  "164.312(a)(1)",      # Access Control
    "CWE-284": "164.312(a)(1)",
    "CWE-862": "164.312(a)(1)",
    "CWE-863": "164.312(a)(1)",
    "CWE-200": "164.312(a)(1)",
}

# ── CWE → Exploit Likelihood (heuristic) ───────────────────────────────────
CWE_EXPLOIT_LIKELIHOOD = {
    "CWE-89":  "high",   "CWE-79":  "high",   "CWE-78":  "high",
    "CWE-94":  "high",   "CWE-798": "high",   "CWE-502": "high",
    "CWE-22":  "high",   "CWE-434": "high",   "CWE-918": "medium",
    "CWE-611": "medium", "CWE-352": "medium",  "CWE-1321":"medium",
    "CWE-327": "low",    "CWE-330": "low",     "CWE-295": "medium",
    "CWE-287": "high",   "CWE-306": "high",
    "CWE-384": "medium", "CWE-601": "medium",
    "CWE-489": "low",    "CWE-547": "low",
    "CWE-532": "medium", "CWE-117": "low",
}

# ── Fix Effort Estimation (hours) ──────────────────────────────────────────
SEVERITY_FIX_EFFORT = {
    "CRITICAL": 8.0,
    "HIGH":     4.0,
    "MEDIUM":   2.0,
    "LOW":      1.0,
    "INFO":     0.5,
}

CWE_FIX_EFFORT_OVERRIDE = {
    "CWE-89":  4.0,   # Parameterize queries
    "CWE-79":  3.0,   # Output encoding
    "CWE-78":  6.0,   # Refactor command execution
    "CWE-798": 2.0,   # Move to env vars
    "CWE-502": 4.0,   # Safe deserialization
    "CWE-327": 3.0,   # Upgrade crypto algorithm
    "CWE-295": 2.0,   # Fix TLS config
    "CWE-918": 4.0,   # URL allowlist
    "CWE-489": 0.5,   # Remove debug statements
    "CWE-547": 0.5,   # Move to config
}


# ── CWE Labels ─────────────────────────────────────────────────────────────
CWE_LABELS = {
    "CWE-20":  "Improper Input Validation",
    "CWE-22":  "Path Traversal",
    "CWE-74":  "Injection",
    "CWE-77":  "Command Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-259": "Use of Hard-coded Password",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of Broken Crypto Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-338": "Use of Cryptographically Weak PRNG",
    "CWE-346": "Origin Validation Error",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted File Upload",
    "CWE-489": "Active Debug Code",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-497": "Exposure of Sensitive System Information",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-506": "Embedded Malicious Code",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-547": "Use of Hard-coded Security-relevant Constants",
    "CWE-601": "URL Redirection to Untrusted Site",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-706": "Use of Incorrectly-Resolved Name",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
    "CWE-917": "Server-Side Template Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1236":"Improper Neutralization of Formula Elements in a CSV File",
    "CWE-1321":"Prototype Pollution",
}


def enrich_finding(finding_dict: dict) -> dict:
    """
    Enrich a finding dictionary with OWASP, MITRE, compliance, exploit,
    and fix effort metadata from central mappings.
    Modifies and returns the dict in-place.
    """
    cwe = finding_dict.get("cwe_id", "")
    severity = finding_dict.get("severity", "MEDIUM")

    # OWASP mapping
    if not finding_dict.get("owasp_category") and cwe:
        finding_dict["owasp_category"] = CWE_TO_OWASP.get(cwe, "")

    # MITRE ATT&CK
    finding_dict["mitre_id"] = CWE_TO_MITRE.get(cwe, "")
    mitre_id = finding_dict["mitre_id"]
    finding_dict["mitre_label"] = MITRE_LABELS.get(mitre_id, "")

    # Compliance
    finding_dict["pci_dss"] = CWE_TO_PCI_DSS.get(cwe, "")
    finding_dict["hipaa"] = CWE_TO_HIPAA.get(cwe, "")

    # Exploit availability heuristic
    finding_dict["exploit_available"] = CWE_EXPLOIT_LIKELIHOOD.get(cwe, "unknown")

    # False positive confidence (default: 0 = not flagged)
    if "false_positive" not in finding_dict:
        finding_dict["false_positive"] = False
    if "confidence" not in finding_dict:
        finding_dict["confidence"] = 0.85

    # Fix effort
    finding_dict["fix_effort_hours"] = CWE_FIX_EFFORT_OVERRIDE.get(
        cwe, SEVERITY_FIX_EFFORT.get(severity, 2.0)
    )

    # CWE label
    finding_dict["cwe_label"] = CWE_LABELS.get(cwe, "")

    # OWASP label
    owasp = finding_dict.get("owasp_category", "")
    finding_dict["owasp_label"] = OWASP_LABELS.get(owasp, "")

    return finding_dict


def compute_risk_score(scan_data: dict) -> float:
    """
    Compute a 0-100 global risk score from severity counts.
    Higher = more risky.
    """
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}
    raw = sum(
        scan_data.get(f"{k.lower()}_count", 0) * v
        for k, v in weights.items()
    )
    return min(100.0, round(raw, 1))
