"""
CodeShield PDF Report Generator
Produces .pdf reports with proper severity sections, filled cells,
summary dashboard, and consistent data population using fpdf2.
"""
import io
import logging
from fpdf import FPDF

logger = logging.getLogger("codeshield.reports.pdf")

SEV_COLORS = {
    "CRITICAL": (220, 20, 60),
    "HIGH":     (255, 109, 0),
    "MEDIUM":   (230, 180, 0),
    "LOW":      (41, 121, 255),
    "INFO":     (120, 144, 156),
}
SEV_LIGHT = {
    "CRITICAL": (255, 230, 230),
    "HIGH":     (255, 240, 220),
    "MEDIUM":   (255, 250, 220),
    "LOW":      (220, 235, 255),
    "INFO":     (235, 240, 245),
}


class _ReportPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(31, 56, 100)
        self.cell(0, 6, "CodeShield Security Report", align="L")
        self.set_draw_color(31, 56, 100)
        self.line(10, 14, self.w - 10, 14)
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(128)
        self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title, color=(31, 56, 100)):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*color)
        self.cell(0, 10, title, ln=True)
        self.set_text_color(0)
        self.ln(2)


def generate_pdf(scan: dict, findings: list, sbom: dict, project: dict = None) -> bytes:
    """Generate PDF report and return bytes."""
    pdf = _ReportPDF()
    pdf.alias_nb_pages()

    # ── Page 1: Executive Summary ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(31, 56, 100)
    pdf.cell(0, 14, "Security Scan Report", ln=True)
    pdf.set_draw_color(31, 56, 100)
    pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
    pdf.ln(6)

    # Summary table with borders
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0)

    # Build summary including project context
    summary = []
    if project:
        summary.append(("Project", str(project.get("name", ""))))
        summary.append(("Project ID", str(project.get("project_id", ""))[:12]))
    summary.extend([
        ("Scan ID",       str(scan.get("scan_id", ""))),
        ("Filename",      str(scan.get("filename", ""))),
        ("Status",        str(scan.get("status", ""))),
        ("Scan Date",     str(scan.get("started_at", ""))),
        ("Completed",     str(scan.get("completed_at", ""))),
    ])
    for label, value in summary:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(240, 240, 250)
        pdf.cell(55, 7, label, border=1, fill=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(200, 7, _safe(value), border=1, ln=True)

    pdf.ln(4)

    # Severity distribution boxes
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, "Severity Distribution", ln=True)
    sev_data = [
        ("CRITICAL", scan.get("critical_count", 0)),
        ("HIGH",     scan.get("high_count", 0)),
        ("MEDIUM",   scan.get("medium_count", 0)),
        ("LOW",      scan.get("low_count", 0)),
        ("INFO",     scan.get("info_count", 0)),
    ]
    box_w = 48
    for sev, count in sev_data:
        color = SEV_COLORS.get(sev, (128, 128, 128))
        pdf.set_fill_color(*color)
        pdf.set_text_color(255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(box_w, 8, f"{sev}: {count}", border=1, fill=True, align="C")
    pdf.ln(10)
    pdf.set_text_color(0)

    # Trend + effort summary
    new_count = sum(1 for f in findings if f.get("trend_status") == "new")
    rec_count = sum(1 for f in findings if f.get("trend_status") == "recurring")
    total_effort = sum(_safe_float(f.get("fix_effort_hours", 0)) for f in findings)

    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"Total Findings: {scan.get('total_findings', len(findings))}    |    "
                    f"New: {new_count}    |    Recurring: {rec_count}    |    "
                    f"Est. Remediation: {round(total_effort, 1)} hours", ln=True)

    # ── Findings by severity section ──
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for sev in sev_order:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue

        pdf.add_page()
        color = SEV_COLORS.get(sev, (0, 0, 0))
        pdf.section_title(f"{sev} Findings ({len(sev_findings)})", color)

        # Table header
        col_w = [10, 18, 50, 52, 12, 20, 22, 22, 20, 18, 16]
        hdrs = ["#", "Plugin", "Title", "File", "Ln", "CWE", "OWASP",
                "CVE", "CVSS", "Exploit", "Trend"]

        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(*color)
        pdf.set_text_color(255)
        for i, h in enumerate(hdrs):
            pdf.cell(col_w[i], 7, h, border=1, fill=True, align="C")
        pdf.ln()
        pdf.set_text_color(0)

        # Data rows
        bg = SEV_LIGHT.get(sev, (255, 255, 255))
        pdf.set_font("Helvetica", "", 6)
        for idx, f in enumerate(sev_findings, 1):
            pdf.set_fill_color(*bg)
            row_data = [
                str(idx),
                _safe(f.get("plugin_name", ""))[:10],
                _safe(f.get("title", ""))[:38],
                _safe(f.get("file_path", ""))[:35],
                str(f.get("line_number", "") or ""),
                _safe(f.get("cwe_id", "")),
                _safe(f.get("owasp_category", ""))[:8],
                _safe(f.get("cve_id", "")),
                str(f.get("cvss_score", "") or ""),
                _safe(f.get("exploit_available", "")) or "unknown",
                _safe(f.get("trend_status", "")) or "new",
            ]
            for i, val in enumerate(row_data):
                pdf.cell(col_w[i], 5.5, val, border=1, fill=True,
                         align="C" if i in (0, 4, 9, 10) else "L")
            pdf.ln()

            # Page overflow check
            if pdf.get_y() > 180:
                pdf.add_page()
                pdf.section_title(f"{sev} Findings (continued)", color)
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_fill_color(*color)
                pdf.set_text_color(255)
                for i, h in enumerate(hdrs):
                    pdf.cell(col_w[i], 7, h, border=1, fill=True, align="C")
                pdf.ln()
                pdf.set_text_color(0)
                pdf.set_font("Helvetica", "", 6)

    # ── SBOM Page ──
    if sbom and sbom.get("components"):
        pdf.add_page()
        pdf.section_title("Software Bill of Materials (SBOM)")

        s_w = [55, 25, 95, 45, 30]
        s_hdrs = ["Name", "Version", "PURL", "License", "Ecosystem"]
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(0, 140, 70)
        pdf.set_text_color(255)
        for i, h in enumerate(s_hdrs):
            pdf.cell(s_w[i], 7, h, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(0)
        for c in sbom["components"]:
            pdf.set_fill_color(245, 250, 245)
            vals = [
                _safe(c.get("name", ""))[:32],
                _safe(c.get("version", "")),
                _safe(c.get("purl", ""))[:55],
                _safe(c.get("license", "")),
                _safe(c.get("ecosystem", "")),
            ]
            for i, v in enumerate(vals):
                pdf.cell(s_w[i], 5.5, v, border=1, fill=True)
            pdf.ln()
            if pdf.get_y() > 180:
                pdf.add_page()
                pdf.section_title("SBOM (continued)")
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(0, 140, 70)
                pdf.set_text_color(255)
                for i, h in enumerate(s_hdrs):
                    pdf.cell(s_w[i], 7, h, border=1, fill=True, align="C")
                pdf.ln()
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(0)

    # ── Remediation Roadmap ──
    pdf.add_page()
    pdf.section_title("Remediation Roadmap")
    phases = [
        ("Phase 1: Critical & High", ["CRITICAL", "HIGH"],
         "Fix immediately - these represent active exploit risk."),
        ("Phase 2: Medium", ["MEDIUM"],
         "Schedule within current sprint or iteration."),
        ("Phase 3: Low & Info", ["LOW", "INFO"],
         "Add to backlog as technical debt items."),
    ]
    for label, sevs, action in phases:
        matched = [f for f in findings if f.get("severity", "") in sevs]
        hours = sum(_safe_float(f.get("fix_effort_hours", 0)) for f in matched)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(240, 240, 250)
        pdf.cell(0, 8, label, border=1, fill=True, ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, f"  Findings: {len(matched)}    |    "
                       f"Est. Effort: {round(hours, 1)} hours", ln=True)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(80)
        pdf.cell(0, 5, f"  {action}", ln=True)
        pdf.set_text_color(0)
        pdf.ln(3)

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def _safe(val) -> str:
    """Convert value to safe latin-1 string for Helvetica font compatibility."""
    if val is None:
        return ""
    s = str(val)
    # Replace common Unicode chars that break latin-1 encoding
    s = s.replace('\u2014', '-').replace('\u2013', '-')  # em/en dash
    s = s.replace('\u2018', "'").replace('\u2019', "'")  # smart quotes
    s = s.replace('\u201c', '"').replace('\u201d', '"')
    s = s.replace('\u2026', '...')  # ellipsis
    # Strip any remaining non-latin-1 characters
    return s.encode('latin-1', errors='replace').decode('latin-1')


def _safe_float(val) -> float:
    """Convert value to float safely."""
    try:
        return float(val) if val else 0.0
    except (ValueError, TypeError):
        return 0.0
