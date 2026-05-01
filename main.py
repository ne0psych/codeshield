#!/usr/bin/env python3
"""
CodeShield — Main Entry Point
Usage:
    python main.py <path_to_code.zip> [--output-dir ./reports]
"""

import os
import sys
import json
import shutil
import argparse
import tempfile
import datetime

def main():
    parser = argparse.ArgumentParser(
        description="CodeShield: Comprehensive Code Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py myapp.zip
  python main.py myapp.zip --output-dir ./reports
  python main.py myapp.zip --output-dir ./reports --no-pdf
  python main.py myapp.zip --output-dir ./reports --no-excel
        """
    )
    parser.add_argument("zip_file",     help="Path to the ZIP file containing source code")
    parser.add_argument("--output-dir", default="./reports", help="Output directory for reports")
    parser.add_argument("--no-pdf",     action="store_true", help="Skip PDF report generation")
    parser.add_argument("--no-excel",   action="store_true", help="Skip Excel report generation")
    args = parser.parse_args()

    zip_path = os.path.abspath(args.zip_file)
    if not os.path.exists(zip_path):
        print(f"[ERROR] File not found: {zip_path}")
        sys.exit(1)
    if not zip_path.endswith(".zip"):
        print(f"[ERROR] Expected a .zip file, got: {zip_path}")
        sys.exit(1)

    zip_name  = os.path.basename(zip_path)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir   = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 60)
    print("  CodeShield — Code Security Scanner v1.0")
    print("=" * 60)
    print(f"  Target : {zip_name}")
    print(f"  Output : {out_dir}")
    print("=" * 60)

    # Extract ZIP to temp dir
    tmp_dir = tempfile.mkdtemp(prefix="codeshield_")
    try:
        print(f"\n  Extracting {zip_name} ...")
        from scanner import extract_zip, run_all_scans
        extract_zip(zip_path, tmp_dir)
        print(f"  Extraction complete.")

        # Run all scans
        print("\n  Starting security scans:")
        scan_results, sbom = run_all_scans(tmp_dir)

        # Save SBOM JSON
        sbom_path = os.path.join(out_dir, f"sbom_{timestamp}.json")
        with open(sbom_path, "w") as f:
            json.dump(sbom, f, indent=2)
        print(f"  SBOM JSON saved: {sbom_path}")

        # Generate reports
        print("\n  Generating reports ...")
        from report_generator import generate_pdf_report, generate_excel_report

        if not args.no_pdf:
            pdf_path = os.path.join(out_dir, f"security_report_{timestamp}.pdf")
            generate_pdf_report(scan_results, sbom, pdf_path, zip_name)

        if not args.no_excel:
            xlsx_path = os.path.join(out_dir, f"security_report_{timestamp}.xlsx")
            generate_excel_report(scan_results, sbom, xlsx_path, zip_name)

        # Summary
        all_vulns = [v for r in scan_results for v in r.vulnerabilities]
        from collections import defaultdict
        sev_counts = defaultdict(int)
        for v in all_vulns:
            sev_counts[v.severity] += 1

        print("\n" + "=" * 60)
        print("  SCAN COMPLETE — Summary")
        print("=" * 60)
        print(f"  Total Vulnerabilities : {len(all_vulns)}")
        print(f"  CRITICAL              : {sev_counts['CRITICAL']}")
        print(f"  HIGH                  : {sev_counts['HIGH']}")
        print(f"  MEDIUM                : {sev_counts['MEDIUM']}")
        print(f"  LOW                   : {sev_counts['LOW']}")
        print(f"  INFO                  : {sev_counts['INFO']}")
        print(f"  SBOM Components       : {len(sbom['components'])}")
        print("=" * 60)
        print(f"\n  Reports saved to: {out_dir}")
        print("  Done.")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
