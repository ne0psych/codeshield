#!/usr/bin/env python3
"""
CodeShield - Comprehensive Code Security Scanner
Performs SAST, SCA, SBOM, IaC, Container, and Secrets scanning
on a ZIP file containing source code.
"""

import os
import sys
import re
import ast
import json
import time
import hashlib
import zipfile
import argparse
import datetime
import subprocess
import shutil
import tempfile
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    scan_type:    str
    severity:     str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title:        str
    description:  str
    file_path:    str
    line_number:  int
    code_snippet: str
    remediation:  str
    cve_id:       str = ""
    cvss_score:   float = 0.0
    rule_id:      str = ""

@dataclass
class ScanResult:
    scan_type:       str
    tool_used:       str
    duration_sec:    float
    files_scanned:   int
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    raw_output:      str = ""

# ─── SAST Scanner ─────────────────────────────────────────────────────────────

SAST_RULES = [
    # SQL Injection
    dict(id="SAST-001", title="SQL Injection", severity="CRITICAL",
         pattern=r'(?i)(execute|exec|query|cursor\.execute)\s*\(\s*["\'].*?\%[sd]|f["\'].*?SELECT|f["\'].*?INSERT|f["\'].*?UPDATE|f["\'].*?DELETE',
         desc="SQL query constructed using string formatting. Attackers can manipulate queries.",
         fix="Use parameterised queries or an ORM. Never concatenate user input into SQL strings."),
    # Command Injection
    dict(id="SAST-002", title="Command Injection", severity="CRITICAL",
         pattern=r'(os\.system|subprocess\.call|subprocess\.Popen|os\.popen)\s*\([^)]*\+|shell\s*=\s*True',
         desc="Shell command executed with user-controlled input or shell=True.",
         fix="Avoid shell=True. Pass arguments as a list. Validate/sanitise all inputs."),
    # Hardcoded Credentials
    dict(id="SAST-003", title="Hardcoded Credentials", severity="HIGH",
         pattern=r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*["\'][^"\']{6,}["\']',
         desc="Hardcoded credential found in source code.",
         fix="Store secrets in environment variables or a vault (HashiCorp Vault, AWS Secrets Manager)."),
    # Path Traversal
    dict(id="SAST-004", title="Path Traversal", severity="HIGH",
         pattern=r'open\s*\([^)]*\+|open\s*\(.*?request\.|open\s*\(.*?input\(',
         desc="File path constructed from user input enabling directory traversal.",
         fix="Validate paths with os.path.abspath and ensure they stay within the allowed base directory."),
    # XSS
    dict(id="SAST-005", title="Cross-Site Scripting (XSS)", severity="HIGH",
         pattern=r'(render_template_string|Markup\(|\.html\(|innerHTML\s*=)',
         desc="Potential XSS: user-controlled data rendered as HTML without escaping.",
         fix="Use template auto-escaping. Never inject raw user data into HTML."),
    # Weak Crypto
    dict(id="SAST-006", title="Weak Cryptographic Algorithm", severity="MEDIUM",
         pattern=r'(?i)(hashlib\.md5|hashlib\.sha1|DES\.|RC4\.|Blowfish\.)',
         desc="Deprecated or weak cryptographic algorithm in use.",
         fix="Use SHA-256 / SHA-3 for hashing. Use AES-256-GCM for encryption."),
    # Insecure Deserialization
    dict(id="SAST-007", title="Insecure Deserialization", severity="HIGH",
         pattern=r'(pickle\.loads|pickle\.load|yaml\.load\s*\([^)]*Loader\s*=\s*None|yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader))',
         desc="Insecure deserialization can lead to arbitrary code execution.",
         fix="Use pickle only with trusted data. For YAML, use yaml.safe_load()."),
    # Debug/Console left in
    dict(id="SAST-008", title="Debug Code Left in Production", severity="LOW",
         pattern=r'(console\.log\(|debugger;|print\s*\(.*?password|pdb\.set_trace|breakpoint\(\))',
         desc="Debug statements or breakpoints found that may expose sensitive data.",
         fix="Remove all debug statements before deploying to production."),
    # SSRF
    dict(id="SAST-009", title="Server-Side Request Forgery (SSRF)", severity="HIGH",
         pattern=r'(requests\.get|requests\.post|urllib\.request\.urlopen)\s*\([^)]*request\.|fetch\s*\([^)]*req\.',
         desc="HTTP request made with user-controlled URL could allow SSRF.",
         fix="Validate and allowlist URLs. Block requests to internal/private IP ranges."),
    # Open Redirect
    dict(id="SAST-010", title="Open Redirect", severity="MEDIUM",
         pattern=r'(redirect|location)\s*[=\(]\s*[^)]*request\.(args|form|params|GET|POST)',
         desc="Redirect target derived from user input enables phishing attacks.",
         fix="Validate redirect URLs against an allowlist of trusted domains."),
    # Eval injection
    dict(id="SAST-011", title="Code Injection via eval()", severity="CRITICAL",
         pattern=r'\beval\s*\([^)]*(?:request|input|params|args)',
         desc="eval() called with user-controlled input allows arbitrary code execution.",
         fix="Never use eval(). Use ast.literal_eval() for safe expression parsing."),
    # Insecure random
    dict(id="SAST-012", title="Insecure Randomness", severity="MEDIUM",
         pattern=r'\brandom\.(random|randint|choice|shuffle)\b',
         desc="Using non-cryptographic random for security-sensitive operations.",
         fix="Use secrets module or os.urandom() for cryptographic randomness."),
]

def run_sast(code_dir: str) -> ScanResult:
    start = time.time()
    vulns = []
    files_scanned = 0
    extensions = {'.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c'}

    for root, _, files in os.walk(code_dir):
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in extensions:
                continue
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, code_dir)
            files_scanned += 1
            try:
                lines = open(fpath, encoding='utf-8', errors='ignore').readlines()
            except Exception:
                continue
            for rule in SAST_RULES:
                for i, line in enumerate(lines, 1):
                    if re.search(rule['pattern'], line):
                        snippet = line.strip()[:120]
                        vulns.append(Vulnerability(
                            scan_type="SAST", severity=rule['severity'],
                            title=rule['title'], description=rule['desc'],
                            file_path=rel, line_number=i,
                            code_snippet=snippet, remediation=rule['fix'],
                            rule_id=rule['id']
                        ))
    return ScanResult("SAST", "CodeShield SAST Engine", round(time.time()-start,2),
                      files_scanned, vulns)

# ─── SCA / Dependency Scanner ─────────────────────────────────────────────────

KNOWN_VULN_PACKAGES = {
    # (package, version_range_max, CVE, CVSS, title, fix_version)
    ("django",         "3.2.0",  "CVE-2021-44420", 9.8, "SQL injection via QuerySet.order_by()",       "3.2.1"),
    ("flask",          "1.0.0",  "CVE-2018-1000656",7.5, "Denial of service via large JSON payload",   "1.0.1"),
    ("requests",       "2.19.1", "CVE-2018-18074",  9.8, "Redirect to arbitrary URL leaks credentials","2.20.0"),
    ("pyyaml",         "5.3.1",  "CVE-2020-14343",  9.8, "Arbitrary code execution via yaml.load()",   "5.4"),
    ("pillow",         "8.2.0",  "CVE-2021-25290",  9.8, "Buffer overflow in TIFF image parsing",      "8.2.1"),
    ("cryptography",   "3.3.1",  "CVE-2020-36242",  9.1, "Buffer overflow in symmetric crypto",        "3.3.2"),
    ("sqlalchemy",     "1.4.0",  "CVE-2019-7164",   9.8, "SQL injection via order_by parameter",       "1.4.1"),
    ("urllib3",        "1.26.4", "CVE-2021-33503",  7.5, "ReDoS via malformed URL",                    "1.26.5"),
    ("numpy",          "1.21.0", "CVE-2021-33430",  7.5, "Buffer overflow in array construction",      "1.21.1"),
    ("lxml",           "4.6.2",  "CVE-2021-28957",  6.1, "XSS in HTML serialisation",                  "4.6.3"),
    ("paramiko",       "2.7.1",  "CVE-2022-24302",  5.9, "Race condition in private key file creation", "2.7.2"),
    ("jinja2",         "2.11.2", "CVE-2020-28493",  7.5, "ReDoS via malicious input",                  "2.11.3"),
    ("werkzeug",       "1.0.1",  "CVE-2023-25577",  7.5, "Multipart form-data DoS",                    "2.2.3"),
    ("setuptools",     "57.0.0", "CVE-2022-40897",  5.9, "ReDoS in package metadata parsing",          "65.5.1"),
    ("certifi",        "2022.5.18","CVE-2022-23491",5.0, "Compromised root CA in bundle",              "2022.12.7"),
}

def parse_requirements(fpath: str) -> List[Tuple[str,str]]:
    deps = []
    for line in open(fpath, encoding='utf-8', errors='ignore'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'([A-Za-z0-9_\-\.]+)\s*[=><!\^~]+\s*([\d\.]+)', line)
        if m:
            deps.append((m.group(1).lower(), m.group(2)))
        else:
            name = re.match(r'([A-Za-z0-9_\-\.]+)', line)
            if name:
                deps.append((name.group(1).lower(), "0.0.0"))
    return deps

def version_lte(v1: str, v2: str) -> bool:
    def parts(v): return [int(x) for x in re.split(r'[.\-]', v) if x.isdigit()]
    try:
        p1, p2 = parts(v1), parts(v2)
        maxlen = max(len(p1), len(p2))
        p1 += [0]*(maxlen-len(p1)); p2 += [0]*(maxlen-len(p2))
        return p1 <= p2
    except Exception:
        return False

def run_sca(code_dir: str) -> ScanResult:
    start = time.time()
    vulns = []
    files_scanned = 0
    req_files = []
    for root, _, files in os.walk(code_dir):
        for f in files:
            if f in ('requirements.txt', 'requirements-dev.txt', 'Pipfile', 'pyproject.toml',
                     'package.json', 'pom.xml', 'build.gradle', 'Gemfile'):
                req_files.append(os.path.join(root, f))

    all_deps = []
    for rf in req_files:
        files_scanned += 1
        rel = os.path.relpath(rf, code_dir)
        if rf.endswith('requirements.txt') or rf.endswith('requirements-dev.txt'):
            all_deps += [(n,v,rel) for n,v in parse_requirements(rf)]

    for pkg, max_ver, cve, cvss, title, fix_ver in KNOWN_VULN_PACKAGES:
        for name, ver, src_file in all_deps:
            if name == pkg and version_lte(ver, max_ver):
                sev = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
                vulns.append(Vulnerability(
                    scan_type="SCA", severity=sev,
                    title=f"Vulnerable dependency: {name}=={ver}",
                    description=f"{title} (CVSS {cvss})",
                    file_path=src_file, line_number=0,
                    code_snippet=f"{name}=={ver}",
                    remediation=f"Upgrade to {name}>={fix_ver}",
                    cve_id=cve, cvss_score=cvss
                ))

    return ScanResult("SCA", "CodeShield SCA Engine", round(time.time()-start,2),
                      files_scanned, vulns)

# ─── SBOM Generator ───────────────────────────────────────────────────────────

def generate_sbom(code_dir: str) -> Tuple[dict, ScanResult]:
    start = time.time()
    components = []
    files_scanned = 0
    for root, _, files in os.walk(code_dir):
        for fname in files:
            if fname in ('requirements.txt', 'requirements-dev.txt'):
                fpath = os.path.join(root, fname)
                files_scanned += 1
                for name, ver in parse_requirements(fpath):
                    purl = f"pkg:pypi/{name}@{ver}"
                    components.append({
                        "type": "library", "name": name, "version": ver,
                        "purl": purl,
                        "supplier": "PyPI",
                        "checksum": hashlib.sha256(f"{name}{ver}".encode()).hexdigest()[:16]
                    })
            elif fname == 'package.json':
                fpath = os.path.join(root, fname)
                files_scanned += 1
                try:
                    data = json.load(open(fpath))
                    for section in ('dependencies', 'devDependencies'):
                        for pkg, ver in data.get(section, {}).items():
                            ver_clean = re.sub(r'[^0-9.]', '', ver)
                            components.append({
                                "type": "library", "name": pkg,
                                "version": ver_clean or ver,
                                "purl": f"pkg:npm/{pkg}@{ver_clean or ver}",
                                "supplier": "npm",
                                "checksum": hashlib.sha256(f"{pkg}{ver}".encode()).hexdigest()[:16]
                            })
                except Exception:
                    pass

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{hashlib.md5(code_dir.encode()).hexdigest()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "tools": [{"name": "CodeShield", "version": "1.0.0"}]
        },
        "components": components
    }
    result = ScanResult("SBOM", "CycloneDX Generator", round(time.time()-start,2),
                        files_scanned, [])
    return sbom, result

# ─── IaC Scanner ──────────────────────────────────────────────────────────────

IAC_RULES = [
    dict(id="IAC-001", title="S3 Bucket Public Access Enabled", severity="CRITICAL",
         pattern=r'(BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)\s*[:=]\s*(false|False|0)',
         desc="S3 bucket has public access enabled, exposing data to the internet.",
         fix="Set all S3 Block Public Access settings to true."),
    dict(id="IAC-002", title="Security Group Allows All Inbound Traffic", severity="CRITICAL",
         pattern=r'(cidr_blocks|CidrIp)\s*[:=]\s*["\']0\.0\.0\.0/0["\']',
         desc="Security group rule allows ingress from any IP address.",
         fix="Restrict CIDR blocks to specific known IP ranges. Never use 0.0.0.0/0 for production."),
    dict(id="IAC-003", title="Hardcoded AWS Credentials", severity="CRITICAL",
         pattern=r'(?i)(access_key|secret_key|aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\'][A-Z0-9]{16,}["\']',
         desc="AWS credentials hardcoded in IaC templates.",
         fix="Use IAM roles, environment variables, or AWS Secrets Manager."),
    dict(id="IAC-004", title="Encryption Disabled on Storage", severity="HIGH",
         pattern=r'(?i)(encrypted\s*[:=]\s*false|server_side_encryption\s*[:=]\s*false|encrypt\s*[:=]\s*false)',
         desc="Storage resource configured without encryption at rest.",
         fix="Enable encryption with KMS or platform-managed keys for all storage resources."),
    dict(id="IAC-005", title="Logging Disabled", severity="MEDIUM",
         pattern=r'(?i)(logging\s*[:=]\s*false|enable_logging\s*[:=]\s*false|access_logs\s*=\s*\[\])',
         desc="Logging is disabled on this resource, hindering incident response.",
         fix="Enable access logging and send logs to a centralised, tamper-proof destination."),
    dict(id="IAC-006", title="Root Account Usage Allowed", severity="HIGH",
         pattern=r'(?i)(allow_root\s*[:=]\s*true|root_access\s*[:=]\s*enabled)',
         desc="Root account access is permitted, violating least-privilege principle.",
         fix="Disable root account access and use IAM roles with minimum required permissions."),
    dict(id="IAC-007", title="MFA Not Required", severity="HIGH",
         pattern=r'(?i)(mfa_delete\s*[:=]\s*["\']?disabled["\']?|require_mfa\s*[:=]\s*false)',
         desc="Multi-factor authentication is not enforced.",
         fix="Enforce MFA for all IAM users and privileged operations."),
    dict(id="IAC-008", title="Publicly Exposed RDS Instance", severity="CRITICAL",
         pattern=r'(?i)(publicly_accessible\s*[:=]\s*true)',
         desc="Database instance is publicly accessible over the internet.",
         fix="Set publicly_accessible to false and use VPC private subnets."),
]

IAC_EXTENSIONS = {'.tf', '.yaml', '.yml', '.json', '.template', '.cf', '.cfn'}
IAC_INDICATORS = {'aws_', 'azurerm_', 'google_', 'AWSTemplateFormatVersion',
                  'apiVersion: ', 'resource "', 'terraform {'}

def is_iac_file(fpath: str, content: str) -> bool:
    ext = Path(fpath).suffix.lower()
    if ext not in IAC_EXTENSIONS:
        return False
    return any(ind in content for ind in IAC_INDICATORS)

def run_iac(code_dir: str) -> ScanResult:
    start = time.time()
    vulns = []
    files_scanned = 0
    for root, _, files in os.walk(code_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, code_dir)
            try:
                content = open(fpath, encoding='utf-8', errors='ignore').read()
            except Exception:
                continue
            if not is_iac_file(fpath, content):
                continue
            files_scanned += 1
            lines = content.splitlines()
            for rule in IAC_RULES:
                for i, line in enumerate(lines, 1):
                    if re.search(rule['pattern'], line):
                        vulns.append(Vulnerability(
                            scan_type="IaC", severity=rule['severity'],
                            title=rule['title'], description=rule['desc'],
                            file_path=rel, line_number=i,
                            code_snippet=line.strip()[:120],
                            remediation=rule['fix'], rule_id=rule['id']
                        ))
    return ScanResult("IaC", "CodeShield IaC Engine", round(time.time()-start,2),
                      files_scanned, vulns)

# ─── Container Scanner ────────────────────────────────────────────────────────

CONTAINER_RULES = [
    dict(id="CNT-001", title="Running as Root", severity="HIGH",
         pattern=r'^USER\s+root\s*$|^USER\s+0\s*$',
         desc="Container runs as root user, maximising blast radius on compromise.",
         fix="Add 'USER nonroot' or create a dedicated low-privilege user."),
    dict(id="CNT-002", title="No USER Directive", severity="MEDIUM",
         pattern=None,  # special handling
         desc="No USER directive found; container defaults to root.",
         fix="Explicitly set a non-root USER in the Dockerfile."),
    dict(id="CNT-003", title="Latest Tag Used", severity="MEDIUM",
         pattern=r'^FROM\s+\S+:latest\b',
         desc="'latest' tag is mutable and may pull a different image unexpectedly.",
         fix="Pin base images to a specific digest: FROM image@sha256:<hash>."),
    dict(id="CNT-004", title="Secrets in ENV Variables", severity="HIGH",
         pattern=r'(?i)ENV\s+(PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET)\s*=\s*\S+',
         desc="Secrets stored as environment variables are visible in image metadata.",
         fix="Use Docker secrets, Vault, or runtime secret injection instead."),
    dict(id="CNT-005", title="ADD Instead of COPY", severity="LOW",
         pattern=r'^ADD\s+',
         desc="ADD command can fetch remote URLs and auto-extract archives, which is risky.",
         fix="Use COPY for local files. Use RUN curl/wget explicitly for remote files."),
    dict(id="CNT-006", title="curl|wget Piped to Shell", severity="CRITICAL",
         pattern=r'(?i)(curl|wget)\s+.*\|\s*(bash|sh)',
         desc="Downloading and executing scripts without verification is very dangerous.",
         fix="Download, verify checksum, then execute in separate RUN steps."),
    dict(id="CNT-007", title="Privileged Mode Enabled", severity="CRITICAL",
         pattern=r'(?i)privileged\s*:\s*true|--privileged',
         desc="Privileged containers have unrestricted host access.",
         fix="Remove privileged flag. Use specific capabilities (cap_add) only when necessary."),
    dict(id="CNT-008", title="Outdated Base Image", severity="MEDIUM",
         pattern=r'^FROM\s+(ubuntu:1[0-9]\.|debian:jessie|debian:stretch|centos:6|centos:7)',
         desc="Base image is an end-of-life OS version with unpatched vulnerabilities.",
         fix="Upgrade to a supported base image (e.g., ubuntu:22.04, debian:bookworm)."),
]

def run_container(code_dir: str) -> ScanResult:
    start = time.time()
    vulns = []
    files_scanned = 0
    for root, _, files in os.walk(code_dir):
        for fname in files:
            if not (fname == 'Dockerfile' or fname.startswith('Dockerfile.') or
                    fname == 'docker-compose.yml' or fname == 'docker-compose.yaml'):
                continue
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, code_dir)
            try:
                lines = open(fpath, encoding='utf-8', errors='ignore').readlines()
            except Exception:
                continue
            files_scanned += 1
            has_user = any(re.match(r'^USER\s+', l) for l in lines)
            if not has_user and fname.startswith('Dockerfile'):
                vulns.append(Vulnerability(
                    scan_type="Container", severity="MEDIUM",
                    title="No USER Directive", description=CONTAINER_RULES[1]['desc'],
                    file_path=rel, line_number=0,
                    code_snippet="(no USER directive found)",
                    remediation=CONTAINER_RULES[1]['fix'], rule_id="CNT-002"
                ))
            for rule in CONTAINER_RULES:
                if rule['pattern'] is None:
                    continue
                for i, line in enumerate(lines, 1):
                    if re.search(rule['pattern'], line.strip()):
                        vulns.append(Vulnerability(
                            scan_type="Container", severity=rule['severity'],
                            title=rule['title'], description=rule['desc'],
                            file_path=rel, line_number=i,
                            code_snippet=line.strip()[:120],
                            remediation=rule['fix'], rule_id=rule['id']
                        ))
    return ScanResult("Container", "CodeShield Container Engine",
                      round(time.time()-start,2), files_scanned, vulns)

# ─── Secrets Scanner ──────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    ("AWS Access Key",      r'AKIA[0-9A-Z]{16}',                        "CRITICAL"),
    ("AWS Secret Key",      r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']', "CRITICAL"),
    ("GitHub Token",        r'ghp_[0-9a-zA-Z]{36}',                    "CRITICAL"),
    ("Google API Key",      r'AIza[0-9A-Za-z\-_]{35}',                 "CRITICAL"),
    ("Private RSA Key",     r'-----BEGIN RSA PRIVATE KEY-----',         "CRITICAL"),
    ("Private EC Key",      r'-----BEGIN EC PRIVATE KEY-----',          "CRITICAL"),
    ("JWT Token",           r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', "HIGH"),
    ("Slack Token",         r'xox[baprs]-[0-9A-Za-z\-]{10,48}',        "HIGH"),
    ("Stripe API Key",      r'(?:r|s)k_(live|test)_[0-9a-zA-Z]{24}',   "HIGH"),
    ("Generic Secret",      r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']', "HIGH"),
    ("Connection String",   r'(?i)(mongodb|postgres|mysql|mssql):\/\/[^"\'>\s]+:[^"\'>\s]+@', "HIGH"),
    ("Bearer Token",        r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*', "MEDIUM"),
]

def run_secrets(code_dir: str) -> ScanResult:
    start = time.time()
    vulns = []
    files_scanned = 0
    skip_ext = {'.pyc', '.png', '.jpg', '.gif', '.ico', '.woff', '.ttf', '.eot',
                '.zip', '.tar', '.gz', '.lock', '.pdf'}
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'vendor', 'dist', 'build'}
    for root, dirs, files in os.walk(code_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if Path(fname).suffix.lower() in skip_ext:
                continue
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, code_dir)
            try:
                lines = open(fpath, encoding='utf-8', errors='ignore').readlines()
            except Exception:
                continue
            files_scanned += 1
            for i, line in enumerate(lines, 1):
                for name, pattern, severity in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        masked = re.sub(r'(["\'])(.{4}).+(.{4})(["\'])', r'\1\2****\3\4', line.strip())
                        vulns.append(Vulnerability(
                            scan_type="Secrets", severity=severity,
                            title=f"Secret Detected: {name}",
                            description=f"A {name} was found exposed in the codebase.",
                            file_path=rel, line_number=i,
                            code_snippet=masked[:120],
                            remediation="Remove the secret immediately. Rotate the credential. "
                                        "Use environment variables or a secrets manager.",
                            rule_id=f"SEC-{abs(hash(name)) % 900 + 100}"
                        ))
    return ScanResult("Secrets", "CodeShield Secrets Engine",
                      round(time.time()-start,2), files_scanned, vulns)

# ─── Main Orchestrator ────────────────────────────────────────────────────────

def extract_zip(zip_path: str, target_dir: str):
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(target_dir)

def run_all_scans(code_dir: str) -> Tuple[List[ScanResult], dict]:
    print("\n  [1/6] Running SAST scan ...", flush=True)
    sast   = run_sast(code_dir)
    print(f"        ✓ {len(sast.vulnerabilities)} issues  ({sast.duration_sec}s)")

    print("  [2/6] Running SCA scan ...", flush=True)
    sca    = run_sca(code_dir)
    print(f"        ✓ {len(sca.vulnerabilities)} issues  ({sca.duration_sec}s)")

    print("  [3/6] Generating SBOM ...", flush=True)
    sbom, sbom_res = generate_sbom(code_dir)
    print(f"        ✓ {len(sbom['components'])} components  ({sbom_res.duration_sec}s)")

    print("  [4/6] Running IaC scan ...", flush=True)
    iac    = run_iac(code_dir)
    print(f"        ✓ {len(iac.vulnerabilities)} issues  ({iac.duration_sec}s)")

    print("  [5/6] Running Container scan ...", flush=True)
    cont   = run_container(code_dir)
    print(f"        ✓ {len(cont.vulnerabilities)} issues  ({cont.duration_sec}s)")

    print("  [6/6] Running Secrets scan ...", flush=True)
    secs   = run_secrets(code_dir)
    print(f"        ✓ {len(secs.vulnerabilities)} issues  ({secs.duration_sec}s)")

    return [sast, sca, sbom_res, iac, cont, secs], sbom

# ─── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Run main.py to perform a full scan and generate reports.")
