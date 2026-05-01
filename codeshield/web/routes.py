"""
CodeShield Web Routes
Flask routes for upload, scan, results, history, and SSE progress.
All user input is validated. All HTML output is escaped via Jinja2 autoescape.
"""

import os
import json
import uuid
import shutil
import logging
import tempfile
import threading
from pathlib import Path
from flask import (
    Flask, request, jsonify, render_template, Response,
    send_from_directory, abort
)
from werkzeug.utils import secure_filename

from ..config import AppConfig
from ..engine import ScanEngine
from ..database.connection import get_db
from ..plugins.registry import PluginRegistry
from .sse import event_bus, ScanEvent

logger = logging.getLogger("codeshield.web")

# Maximum filename length after sanitization
MAX_FILENAME_LENGTH = 200


def create_routes(app: Flask, config: AppConfig,
                  engine: ScanEngine, registry: PluginRegistry):
    """Register all routes on the Flask app."""

    @app.route("/")
    def index():
        """Main dashboard page."""
        return render_template("index.html")

    @app.route("/api/upload", methods=["POST"])
    def upload_scan():
        """
        Handle ZIP file upload and trigger scan.
        Validates file type, size, and name before processing.
        Returns scan_id for progress tracking.
        """
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "No file selected"}), 400

        # Sanitize filename — prevent path traversal
        original_name = secure_filename(file.filename)
        if not original_name:
            original_name = "upload.zip"
        if len(original_name) > MAX_FILENAME_LENGTH:
            original_name = original_name[:MAX_FILENAME_LENGTH]

        # Validate file extension
        if not original_name.lower().endswith(".zip"):
            return jsonify({"error": "Only ZIP files are accepted"}), 400

        # Check Content-Length header
        content_length = request.content_length or 0
        if content_length > config.scan.max_zip_size:
            return jsonify({
                "error": f"File too large. Maximum size: "
                         f"{config.scan.max_zip_size // (1024*1024)}MB"
            }), 413

        # Save to temp file
        temp_dir = config.scan.temp_directory or tempfile.gettempdir()
        temp_path = os.path.join(
            temp_dir,
            f"codeshield_upload_{uuid.uuid4().hex}.zip"
        )

        try:
            file.save(temp_path)
            file_size = os.path.getsize(temp_path)

            # Validate the ZIP file
            error = engine.validate_zip(temp_path, file_size)
            if error:
                os.unlink(temp_path)
                return jsonify({"error": error}), 400

            # Start scan in background thread
            def run_scan():
                try:
                    engine.start_scan(
                        temp_path, original_name,
                        progress_callback=_progress_callback
                    )
                finally:
                    # Clean up uploaded file after scan
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

            scan_thread = threading.Thread(
                target=run_scan,
                daemon=True,
                name=f"scan-{original_name}"
            )
            scan_thread.start()

            # Get scan_id from the first event
            # The engine creates it synchronously before starting
            db = get_db()
            row = db.fetchone(
                "SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 1"
            )
            scan_id = row["scan_id"] if row else str(uuid.uuid4())

            return jsonify({
                "scan_id": scan_id,
                "filename": original_name,
                "status": "started"
            })

        except Exception as exc:
            logger.error("Upload failed: %s", exc)
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            return jsonify({"error": "Upload failed. Please try again."}), 500

    @app.route("/api/scan/<scan_id>/events")
    def scan_events(scan_id: str):
        """SSE endpoint for real-time scan progress."""
        # Validate scan_id format (UUID)
        try:
            uuid.UUID(scan_id)
        except ValueError:
            abort(400)

        return Response(
            event_bus.subscribe(scan_id),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
        )

    @app.route("/api/scan/<scan_id>/results")
    def scan_results(scan_id: str):
        """Get full scan results."""
        try:
            uuid.UUID(scan_id)
        except ValueError:
            abort(400)

        db = get_db()
        scan = db.fetchone(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        )
        if not scan:
            return jsonify({"error": "Scan not found"}), 404

        findings = db.fetchall(
            "SELECT * FROM findings WHERE scan_id = ? "
            "ORDER BY CASE severity "
            "WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
            "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 "
            "ELSE 5 END",
            (scan_id,)
        )

        # Parse SBOM JSON
        sbom = {}
        if scan["sbom_json"]:
            try:
                sbom = json.loads(scan["sbom_json"])
            except json.JSONDecodeError:
                sbom = {}

        return jsonify({
            "scan": {
                "scan_id": scan["scan_id"],
                "filename": scan["filename"],
                "status": scan["status"],
                "started_at": scan["started_at"],
                "completed_at": scan["completed_at"],
                "total_findings": scan["total_findings"],
                "critical_count": scan["critical_count"],
                "high_count": scan["high_count"],
                "medium_count": scan["medium_count"],
                "low_count": scan["low_count"],
                "info_count": scan["info_count"],
            },
            "findings": [dict(f) for f in findings],
            "sbom": sbom,
        })

    @app.route("/api/scans")
    def scan_history():
        """Get list of past scans."""
        db = get_db()
        scans = db.fetchall(
            "SELECT scan_id, filename, status, started_at, completed_at, "
            "total_findings, critical_count, high_count, medium_count, "
            "low_count, info_count FROM scans "
            "ORDER BY created_at DESC LIMIT 50"
        )
        return jsonify({
            "scans": [dict(s) for s in scans]
        })

    @app.route("/api/health")
    def health():
        """Health check endpoint."""
        return jsonify({
            "status": "ok",
            "plugins": registry.plugin_names,
            "plugin_count": registry.count,
        })

    @app.route("/api/scan/<scan_id>/report/excel")
    def download_excel(scan_id: str):
        """Download Excel report for a scan."""
        try:
            uuid.UUID(scan_id)
        except ValueError:
            abort(400)
        from ..reports.excel_report import generate_excel
        scan, findings, sbom = _load_report_data(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        data = generate_excel(scan, findings, sbom)
        return Response(
            data, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename=codeshield_{scan_id[:8]}.xlsx"}
        )

    @app.route("/api/scan/<scan_id>/report/pdf")
    def download_pdf(scan_id: str):
        """Download PDF report for a scan."""
        try:
            uuid.UUID(scan_id)
        except ValueError:
            abort(400)
        from ..reports.pdf_report import generate_pdf
        scan, findings, sbom = _load_report_data(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        data = generate_pdf(scan, findings, sbom)
        return Response(
            data, mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=codeshield_{scan_id[:8]}.pdf"}
        )

    @app.route("/api/scan/<scan_id>/risk-score")
    def risk_score(scan_id: str):
        """Get computed risk score for a scan."""
        try:
            uuid.UUID(scan_id)
        except ValueError:
            abort(400)
        from ..mappings import compute_risk_score
        db = get_db()
        scan = db.fetchone("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        score = compute_risk_score(dict(scan))
        return jsonify({"scan_id": scan_id, "risk_score": score})

    @app.route("/api/scan/<scan_id>/trends")
    def scan_trends(scan_id: str):
        """Get trend analysis vs previous scan."""
        try:
            uuid.UUID(scan_id)
        except ValueError:
            abort(400)
        db = get_db()
        findings = db.fetchall("SELECT trend_status, severity FROM findings WHERE scan_id = ?", (scan_id,))
        trends = {"new": 0, "recurring": 0, "fixed": 0}
        for f in findings:
            ts = f["trend_status"] or "new"
            if ts in trends:
                trends[ts] += 1
        return jsonify({"scan_id": scan_id, "trends": trends})

    @app.route("/api/finding/<int:finding_id>/false-positive", methods=["POST"])
    def toggle_false_positive(finding_id: int):
        """Toggle false positive flag on a finding."""
        db = get_db()
        row = db.fetchone("SELECT false_positive FROM findings WHERE id = ?", (finding_id,))
        if not row:
            return jsonify({"error": "Finding not found"}), 404
        new_val = 0 if row["false_positive"] else 1
        with db.transaction() as conn:
            conn.execute("UPDATE findings SET false_positive = ? WHERE id = ?", (new_val, finding_id))
        return jsonify({"id": finding_id, "false_positive": bool(new_val)})

    # Error handlers — never expose internal details
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": "File too large"}), 413

    @app.errorhandler(500)
    def internal_error(e):
        logger.error("Internal server error: %s", e)
        return jsonify({"error": "An internal error occurred"}), 500


def _load_report_data(scan_id: str):
    """Load scan, findings, and SBOM for report generation."""
    db = get_db()
    scan = db.fetchone("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    if not scan:
        return None, [], {}
    findings = db.fetchall(
        "SELECT * FROM findings WHERE scan_id = ? "
        "ORDER BY CASE severity "
        "WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
        "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END",
        (scan_id,)
    )
    sbom = {}
    if scan["sbom_json"]:
        try:
            sbom = json.loads(scan["sbom_json"])
        except json.JSONDecodeError:
            pass
    return dict(scan), [dict(f) for f in findings], sbom


def _progress_callback(scan_id: str, plugin_name: str,
                       status: str, detail: str = ""):
    """Push scan progress events to the SSE event bus."""
    event_bus.publish(ScanEvent(
        scan_id=scan_id,
        plugin_name=plugin_name,
        status=status,
        detail=detail,
    ))
