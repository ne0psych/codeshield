"""
CodeShield Excel Report Generator
Produces .xlsx reports with all enriched finding fields.
"""
import io
import logging
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

logger = logging.getLogger("codeshield.reports.excel")

SEV_COLORS = {
    "CRITICAL": "FF1744", "HIGH": "FF6D00",
    "MEDIUM": "FFD600", "LOW": "2979FF", "INFO": "90A4AE",
}

FINDING_HEADERS = [
    "ID", "Severity", "Plugin", "Title", "Description",
    "File Path", "Line", "Code Snippet", "Remediation",
    "Rule ID", "CVE ID", "CVSS", "CWE ID", "CWE Label",
    "OWASP Category", "OWASP Label", "MITRE ATT&CK ID", "MITRE Label",
    "PCI-DSS", "HIPAA", "Exploit Available", "False Positive",
    "Confidence", "Fix Effort (hrs)", "Trend",
    "Package", "Version", "Fixed Version", "License",
]

SBOM_HEADERS = ["Name", "Version", "PURL", "License", "Ecosystem"]


def generate_excel(scan: dict, findings: list, sbom: dict) -> bytes:
    """Generate Excel report and return bytes."""
    wb = Workbook()

    # ── Summary Sheet ──
    ws = wb.active
    ws.title = "Summary"
    ws.sheet_properties.tabColor = "1F3864"
    _build_summary(ws, scan, findings)

    # ── Findings Sheet ──
    ws2 = wb.create_sheet("Findings")
    ws2.sheet_properties.tabColor = "C00000"
    _build_findings(ws2, findings)

    # ── SBOM Sheet ──
    if sbom and sbom.get("components"):
        ws3 = wb.create_sheet("SBOM")
        ws3.sheet_properties.tabColor = "00B050"
        _build_sbom(ws3, sbom)

    # ── Remediation Roadmap ──
    ws4 = wb.create_sheet("Remediation Roadmap")
    ws4.sheet_properties.tabColor = "7030A0"
    _build_roadmap(ws4, findings)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _header_style():
    return {
        "font": Font(bold=True, color="FFFFFF", size=11),
        "fill": PatternFill("solid", fgColor="1F3864"),
        "alignment": Alignment(horizontal="center", vertical="center", wrap_text=True),
        "border": Border(
            bottom=Side(style="thin", color="000000"),
            right=Side(style="thin", color="D9D9D9"),
        ),
    }


def _apply_headers(ws, headers, row=1):
    style = _header_style()
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=row, column=col, value=h)
        for k, v in style.items():
            setattr(cell, k, v)
    ws.auto_filter.ref = f"A{row}:{get_column_letter(len(headers))}{row}"


def _build_summary(ws, scan, findings):
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 40
    title = ws.cell(row=1, column=1, value="CodeShield Security Report")
    title.font = Font(bold=True, size=16, color="1F3864")
    ws.merge_cells("A1:B1")

    rows = [
        ("Scan ID", scan.get("scan_id", "")),
        ("Filename", scan.get("filename", "")),
        ("Status", scan.get("status", "")),
        ("Started", scan.get("started_at", "")),
        ("Completed", scan.get("completed_at", "")),
        ("Total Findings", scan.get("total_findings", 0)),
        ("Critical", scan.get("critical_count", 0)),
        ("High", scan.get("high_count", 0)),
        ("Medium", scan.get("medium_count", 0)),
        ("Low", scan.get("low_count", 0)),
        ("Info", scan.get("info_count", 0)),
    ]

    # Trend summary
    new_count = sum(1 for f in findings if f.get("trend_status") == "new")
    rec_count = sum(1 for f in findings if f.get("trend_status") == "recurring")
    rows.append(("New Findings", new_count))
    rows.append(("Recurring Findings", rec_count))
    total_effort = sum(f.get("fix_effort_hours", 0) for f in findings)
    rows.append(("Total Fix Effort (hours)", round(total_effort, 1)))

    for i, (label, value) in enumerate(rows, 3):
        ws.cell(row=i, column=1, value=label).font = Font(bold=True)
        ws.cell(row=i, column=2, value=value)


def _build_findings(ws, findings):
    _apply_headers(ws, FINDING_HEADERS)
    for i, f in enumerate(findings, 2):
        row = [
            i - 1,
            f.get("severity", ""),
            f.get("plugin_name", ""),
            f.get("title", ""),
            f.get("description", "")[:500],
            f.get("file_path", ""),
            f.get("line_number", 0),
            f.get("code_snippet", "")[:300],
            f.get("remediation", "")[:500],
            f.get("rule_id", ""),
            f.get("cve_id", ""),
            f.get("cvss_score", 0),
            f.get("cwe_id", ""),
            f.get("cwe_label", ""),
            f.get("owasp_category", ""),
            f.get("owasp_label", ""),
            f.get("mitre_id", ""),
            f.get("mitre_label", ""),
            f.get("pci_dss", ""),
            f.get("hipaa", ""),
            f.get("exploit_available", "unknown"),
            "Yes" if f.get("false_positive") else "No",
            f.get("confidence", 0.85),
            f.get("fix_effort_hours", 2.0),
            f.get("trend_status", "new"),
            f.get("package_name", ""),
            f.get("package_version", ""),
            f.get("fixed_version", ""),
            f.get("license_id", ""),
        ]
        for col, val in enumerate(row, 1):
            cell = ws.cell(row=i, column=col, value=val)
            if col == 2:  # severity color
                color = SEV_COLORS.get(str(val).upper(), "FFFFFF")
                cell.fill = PatternFill("solid", fgColor=color)
                cell.font = Font(bold=True, color="FFFFFF" if val != "MEDIUM" else "000000")

    # Auto-width
    for col in range(1, len(FINDING_HEADERS) + 1):
        ws.column_dimensions[get_column_letter(col)].width = 18


def _build_sbom(ws, sbom):
    _apply_headers(ws, SBOM_HEADERS)
    for i, c in enumerate(sbom.get("components", []), 2):
        ws.cell(row=i, column=1, value=c.get("name", ""))
        ws.cell(row=i, column=2, value=c.get("version", ""))
        ws.cell(row=i, column=3, value=c.get("purl", ""))
        ws.cell(row=i, column=4, value=c.get("license", ""))
        ws.cell(row=i, column=5, value=c.get("ecosystem", ""))
    for col in range(1, 6):
        ws.column_dimensions[get_column_letter(col)].width = 30


def _build_roadmap(ws, findings):
    headers = ["Phase", "Priority", "Count", "Total Fix Hours", "Actions"]
    _apply_headers(ws, headers)
    phases = [
        ("Phase 1: Critical/High", ["CRITICAL", "HIGH"]),
        ("Phase 2: Medium", ["MEDIUM"]),
        ("Phase 3: Low/Info", ["LOW", "INFO"]),
    ]
    for i, (label, sevs) in enumerate(phases, 2):
        matched = [f for f in findings if f.get("severity", "") in sevs]
        hours = sum(f.get("fix_effort_hours", 0) for f in matched)
        ws.cell(row=i, column=1, value=label)
        ws.cell(row=i, column=2, value=", ".join(sevs))
        ws.cell(row=i, column=3, value=len(matched))
        ws.cell(row=i, column=4, value=round(hours, 1))
        ws.cell(row=i, column=5, value="Fix immediately" if "CRITICAL" in sevs else "Schedule fix")
    for col in range(1, 6):
        ws.column_dimensions[get_column_letter(col)].width = 25
