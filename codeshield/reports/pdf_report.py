"""
CodeShield PDF Report Generator
Produces .pdf reports matching Excel content exactly, using fpdf2.
"""
import io
import logging
from fpdf import FPDF

logger = logging.getLogger("codeshield.reports.pdf")

SEV_COLORS = {
    "CRITICAL": (255, 23, 68), "HIGH": (255, 109, 0),
    "MEDIUM": (255, 214, 0), "LOW": (41, 121, 255), "INFO": (144, 164, 174),
}


class _ReportPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(31, 56, 100)
        self.cell(0, 8, "CodeShield Security Report", align="L")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def generate_pdf(scan: dict, findings: list, sbom: dict) -> bytes:
    """Generate PDF report and return bytes."""
    pdf = _ReportPDF()
    pdf.alias_nb_pages()

    # ── Summary Page ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(31, 56, 100)
    pdf.cell(0, 15, "Security Scan Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(0)

    summary_rows = [
        ("Scan ID", scan.get("scan_id", "")),
        ("Filename", scan.get("filename", "")),
        ("Status", scan.get("status", "")),
        ("Started", scan.get("started_at", "")),
        ("Completed", scan.get("completed_at", "")),
        ("Total Findings", str(scan.get("total_findings", 0))),
        ("Critical", str(scan.get("critical_count", 0))),
        ("High", str(scan.get("high_count", 0))),
        ("Medium", str(scan.get("medium_count", 0))),
        ("Low", str(scan.get("low_count", 0))),
        ("Info", str(scan.get("info_count", 0))),
    ]
    new_count = sum(1 for f in findings if f.get("trend_status") == "new")
    rec_count = sum(1 for f in findings if f.get("trend_status") == "recurring")
    total_effort = sum(f.get("fix_effort_hours", 0) for f in findings)
    summary_rows += [
        ("New Findings", str(new_count)),
        ("Recurring Findings", str(rec_count)),
        ("Total Fix Effort (hours)", str(round(total_effort, 1))),
    ]

    for label, value in summary_rows:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(60, 7, label + ":", border=0)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(value), ln=True)

    # ── Findings Table ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(31, 56, 100)
    pdf.cell(0, 12, "Findings Detail", ln=True)

    col_widths = [12, 18, 16, 55, 45, 10, 18, 18, 22, 22, 18, 18, 12]
    headers = ["#", "Sev", "Plugin", "Title", "File", "Ln",
               "CWE", "OWASP", "MITRE", "Exploit", "Trend", "Effort", "FP"]

    # Header row
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_fill_color(31, 56, 100)
    pdf.set_text_color(255)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, border=1, fill=True, align="C")
    pdf.ln()

    # Data rows
    pdf.set_font("Helvetica", "", 6)
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "")
        color = SEV_COLORS.get(sev, (200, 200, 200))
        pdf.set_fill_color(*color)
        pdf.set_text_color(255 if sev != "MEDIUM" else 0)

        row = [
            str(idx), sev, f.get("plugin_name", "")[:8],
            f.get("title", "")[:40], f.get("file_path", "")[:30],
            str(f.get("line_number", "")),
            f.get("cwe_id", ""), f.get("owasp_category", "")[:8],
            f.get("mitre_id", ""), f.get("exploit_available", ""),
            f.get("trend_status", ""),
            str(f.get("fix_effort_hours", "")),
            "Y" if f.get("false_positive") else "N",
        ]

        for i, val in enumerate(row):
            fill = i == 1  # only severity cell filled
            pdf.cell(col_widths[i], 6, val, border=1, fill=fill, align="C" if i < 3 else "L")
        pdf.set_text_color(0)
        pdf.ln()

        if pdf.get_y() > 180:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_fill_color(31, 56, 100)
            pdf.set_text_color(255)
            for i, h in enumerate(headers):
                pdf.cell(col_widths[i], 7, h, border=1, fill=True, align="C")
            pdf.ln()
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(0)

    # ── SBOM Page ──
    if sbom and sbom.get("components"):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(31, 56, 100)
        pdf.cell(0, 12, "Software Bill of Materials (SBOM)", ln=True)

        sbom_widths = [60, 30, 100, 40, 30]
        sbom_headers = ["Name", "Version", "PURL", "License", "Ecosystem"]
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(0, 176, 80)
        pdf.set_text_color(255)
        for i, h in enumerate(sbom_headers):
            pdf.cell(sbom_widths[i], 7, h, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(0)
        for c in sbom["components"]:
            row = [
                c.get("name", "")[:35], c.get("version", ""),
                c.get("purl", "")[:60], c.get("license", ""),
                c.get("ecosystem", ""),
            ]
            for i, val in enumerate(row):
                pdf.cell(sbom_widths[i], 6, val, border=1)
            pdf.ln()

    # ── Remediation Roadmap ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(31, 56, 100)
    pdf.cell(0, 12, "Remediation Roadmap", ln=True)
    phases = [
        ("Phase 1: Critical & High", ["CRITICAL", "HIGH"], "Fix immediately"),
        ("Phase 2: Medium", ["MEDIUM"], "Schedule within sprint"),
        ("Phase 3: Low & Info", ["LOW", "INFO"], "Backlog / tech debt"),
    ]
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0)
    for label, sevs, action in phases:
        matched = [f for f in findings if f.get("severity", "") in sevs]
        hours = sum(f.get("fix_effort_hours", 0) for f in matched)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, label, ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, f"  Count: {len(matched)}  |  Est. Effort: {round(hours,1)}h  |  Action: {action}", ln=True)
        pdf.ln(2)

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()
