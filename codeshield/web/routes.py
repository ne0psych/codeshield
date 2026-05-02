"""
CodeShield Web Routes
Flask routes for projects, upload, scan, results, reports, and SSE progress.
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
from datetime import datetime, timezone
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

    # ─── Project CRUD ─────────────────────────────────────────

    @app.route("/api/projects", methods=["GET"])
    def list_projects():
        """List all projects with aggregated stats."""
        db = get_db()
        projects = db.fetchall(
            "SELECT p.project_id, p.name, p.description, p.created_at, "
            "p.last_scan_at, p.total_scans, "
            "COALESCE(SUM(s.total_findings), 0) as total_findings, "
            "COALESCE(SUM(s.critical_count), 0) as critical_count, "
            "COALESCE(SUM(s.high_count), 0) as high_count, "
            "COALESCE(SUM(s.medium_count), 0) as medium_count, "
            "COALESCE(SUM(s.low_count), 0) as low_count "
            "FROM projects p "
            "LEFT JOIN scans s ON s.project_id = p.project_id AND s.status = 'complete' "
            "GROUP BY p.project_id "
            "ORDER BY p.last_scan_at DESC NULLS LAST"
        )
        return jsonify({"projects": [dict(p) for p in projects]})

    @app.route("/api/projects", methods=["POST"])
    def create_project():
        """Create a new project."""
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name or len(name) > 200:
            return jsonify({"error": "Project name required (max 200 chars)"}), 400

        description = (data.get("description") or "").strip()[:1000]
        project_id = str(uuid.uuid4())

        db = get_db()
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO projects (project_id, name, description) "
                "VALUES (?, ?, ?)",
                (project_id, name, description)
            )
        logger.info("Created project '%s' (id=%s)", name, project_id)
        return jsonify({
            "project_id": project_id, "name": name,
            "description": description
        }), 201

    @app.route("/api/projects/<project_id>")
    def get_project(project_id: str):
        """Get project detail with scan history."""
        try:
            uuid.UUID(project_id)
        except ValueError:
            abort(400)

        db = get_db()
        project = db.fetchone(
            "SELECT * FROM projects WHERE project_id = ?", (project_id,)
        )
        if not project:
            return jsonify({"error": "Project not found"}), 404

        scans = db.fetchall(
            "SELECT scan_id, filename, status, started_at, completed_at, "
            "total_findings, critical_count, high_count, medium_count, "
            "low_count, info_count FROM scans "
            "WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,)
        )
        return jsonify({
            "project": dict(project),
            "scans": [dict(s) for s in scans]
        })

    @app.route("/api/projects/<project_id>", methods=["PUT"])
    def update_project(project_id: str):
        """Update project name/description."""
        try:
            uuid.UUID(project_id)
        except ValueError:
            abort(400)

        data = request.get_json(silent=True) or {}
        db = get_db()
        project = db.fetchone(
            "SELECT * FROM projects WHERE project_id = ?", (project_id,)
        )
        if not project:
            return jsonify({"error": "Project not found"}), 404

        name = (data.get("name") or project["name"]).strip()[:200]
        description = (data.get("description") or project["description"]).strip()[:1000]

        with db.transaction() as conn:
            conn.execute(
                "UPDATE projects SET name = ?, description = ? WHERE project_id = ?",
                (name, description, project_id)
            )
        return jsonify({"project_id": project_id, "name": name, "description": description})

    @app.route("/api/projects/<project_id>", methods=["DELETE"])
    def delete_project(project_id: str):
        """Delete project and all its scans."""
        try:
            uuid.UUID(project_id)
        except ValueError:
            abort(400)

        db = get_db()
        project = db.fetchone(
            "SELECT * FROM projects WHERE project_id = ?", (project_id,)
        )
        if not project:
            return jsonify({"error": "Project not found"}), 404

        with db.transaction() as conn:
            # Delete findings for all scans in this project
            conn.execute(
                "DELETE FROM findings WHERE scan_id IN "
                "(SELECT scan_id FROM scans WHERE project_id = ?)",
                (project_id,)
            )
            conn.execute("DELETE FROM scans WHERE project_id = ?", (project_id,))
            conn.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))

        logger.info("Deleted project '%s' and all scans", project["name"])
        return jsonify({"deleted": project_id})

    # ─── Upload & Scan ────────────────────────────────────────

    @app.route("/api/upload", methods=["POST"])
    def upload_scan():
        """
        Handle ZIP file upload and trigger scan.
        Accepts optional project_id or project_name to assign scan.
        """
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "No file selected"}), 400

        # Sanitize filename
        original_name = secure_filename(file.filename)
        if not original_name:
            original_name = "upload.zip"
        if len(original_name) > MAX_FILENAME_LENGTH:
            original_name = original_name[:MAX_FILENAME_LENGTH]

        if not original_name.lower().endswith(".zip"):
            return jsonify({"error": "Only ZIP files are accepted"}), 400

        content_length = request.content_length or 0
        if content_length > config.scan.max_zip_size:
            return jsonify({
                "error": f"File too large. Maximum size: "
                         f"{config.scan.max_zip_size // (1024*1024)}MB"
            }), 413

        # Resolve project
        project_id = request.form.get("project_id", "").strip()
        project_name = request.form.get("project_name", "").strip()

        db = get_db()

        if project_id:
            # Validate existing project
            try:
                uuid.UUID(project_id)
            except ValueError:
                return jsonify({"error": "Invalid project_id format"}), 400
            proj = db.fetchone(
                "SELECT project_id FROM projects WHERE project_id = ?",
                (project_id,)
            )
            if not proj:
                return jsonify({"error": "Project not found"}), 404
        elif project_name:
            # Create new project
            project_id = str(uuid.uuid4())
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO projects (project_id, name, description) "
                    "VALUES (?, ?, ?)",
                    (project_id, project_name[:200], "")
                )
            logger.info("Auto-created project '%s' from upload", project_name)
        else:
            # Auto-create from filename
            auto_name = original_name.replace('.zip', '').replace('_', ' ').replace('-', ' ').title()
            # Check if project with this name already exists
            existing = db.fetchone(
                "SELECT project_id FROM projects WHERE name = ?", (auto_name,)
            )
            if existing:
                project_id = existing["project_id"]
            else:
                project_id = str(uuid.uuid4())
                with db.transaction() as conn:
                    conn.execute(
                        "INSERT INTO projects (project_id, name, description) "
                        "VALUES (?, ?, ?)",
                        (project_id, auto_name, f"Auto-created from {original_name}")
                    )
                logger.info("Auto-created project '%s' from filename", auto_name)

        # Save to temp file
        temp_dir = config.scan.temp_directory or tempfile.gettempdir()
        temp_path = os.path.join(
            temp_dir,
            f"codeshield_upload_{uuid.uuid4().hex}.zip"
        )

        try:
            file.save(temp_path)
            file_size = os.path.getsize(temp_path)

            error = engine.validate_zip(temp_path, file_size)
            if error:
                os.unlink(temp_path)
                return jsonify({"error": error}), 400

            def run_scan():
                try:
                    engine.start_scan(
                        temp_path, original_name,
                        project_id=project_id,
                        progress_callback=_progress_callback
                    )
                finally:
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

            # Get scan_id
            row = db.fetchone(
                "SELECT scan_id FROM scans WHERE project_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (project_id,)
            )
            scan_id = row["scan_id"] if row else str(uuid.uuid4())

            return jsonify({
                "scan_id": scan_id,
                "project_id": project_id,
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

    # ─── Scan Events & Results ────────────────────────────────

    @app.route("/api/scan/<scan_id>/events")
    def scan_events(scan_id: str):
        """SSE endpoint for real-time scan progress."""
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
        """Get full scan results with project context."""
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

        # Get project info
        project = None
        if scan["project_id"]:
            project = db.fetchone(
                "SELECT project_id, name, description FROM projects WHERE project_id = ?",
                (scan["project_id"],)
            )

        findings = db.fetchall(
            "SELECT * FROM findings WHERE scan_id = ? "
            "ORDER BY CASE severity "
            "WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
            "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 "
            "ELSE 5 END",
            (scan_id,)
        )

        sbom = {}
        if scan["sbom_json"]:
            try:
                sbom = json.loads(scan["sbom_json"])
            except json.JSONDecodeError:
                sbom = {}

        return jsonify({
            "project": dict(project) if project else None,
            "scan": {
                "scan_id": scan["scan_id"],
                "project_id": scan["project_id"],
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
        """Get list of past scans with project names."""
        db = get_db()
        scans = db.fetchall(
            "SELECT s.scan_id, s.project_id, s.filename, s.status, "
            "s.started_at, s.completed_at, "
            "s.total_findings, s.critical_count, s.high_count, "
            "s.medium_count, s.low_count, s.info_count, "
            "COALESCE(p.name, s.filename) as project_name "
            "FROM scans s "
            "LEFT JOIN projects p ON p.project_id = s.project_id "
            "ORDER BY s.created_at DESC LIMIT 50"
        )
        return jsonify({"scans": [dict(s) for s in scans]})

    @app.route("/api/health")
    def health():
        """Health check endpoint."""
        return jsonify({
            "status": "ok",
            "plugins": registry.plugin_names,
            "plugin_count": registry.count,
        })

    # ─── Reports ──────────────────────────────────────────────

    @app.route("/api/scan/<scan_id>/report/excel")
    def download_excel(scan_id: str):
        """Download Excel report for a scan."""
        try:
            uuid.UUID(scan_id)
        except ValueError:
            abort(400)
        from ..reports.excel_report import generate_excel
        scan, findings, sbom, project = _load_report_data(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        data = generate_excel(scan, findings, sbom, project=project)
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
        scan, findings, sbom, project = _load_report_data(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        data = generate_pdf(scan, findings, sbom, project=project)
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
        findings = db.fetchall(
            "SELECT trend_status, severity FROM findings WHERE scan_id = ?",
            (scan_id,)
        )
        trends = {"new": 0, "recurring": 0, "fixed": 0}
        for f in findings:
            ts = f["trend_status"] or "new"
            if ts in trends:
                trends[ts] += 1
        return jsonify({
            "scan_id": scan_id, "trends": trends,
            "new_count": trends["new"],
            "recurring_count": trends["recurring"],
        })

    @app.route("/api/finding/<int:finding_id>/false-positive", methods=["POST"])
    def toggle_false_positive(finding_id: int):
        """Toggle false positive flag on a finding."""
        db = get_db()
        row = db.fetchone(
            "SELECT false_positive FROM findings WHERE id = ?", (finding_id,)
        )
        if not row:
            return jsonify({"error": "Finding not found"}), 404
        new_val = 0 if row["false_positive"] else 1
        with db.transaction() as conn:
            conn.execute(
                "UPDATE findings SET false_positive = ? WHERE id = ?",
                (new_val, finding_id)
            )
        return jsonify({"id": finding_id, "false_positive": bool(new_val)})

    @app.route("/api/sync/<source_name>")
    def sync_status(source_name: str):
        """Get sync status for a specific data source."""
        allowed_sources = {
            "osv_vulnerabilities", "spdx_licenses", "nvd_vulnerabilities",
            "github_advisories", "ossindex", "remote_sast_rules",
            "remote_secrets_patterns",
        }
        if source_name not in allowed_sources:
            return jsonify({"error": "Unknown source"}), 404
        db = get_db()
        row = db.fetchone(
            "SELECT * FROM sync_metadata WHERE source_name = ?",
            (source_name,)
        )
        if not row:
            return jsonify({"source": source_name, "status": "not_synced"}), 200
        return jsonify({
            "source": source_name,
            "status": row["status"] or "unknown",
            "records_count": row["records_count"] or 0,
            "last_sync_at": row["last_sync_at"] or "",
            "content_hash": row["content_hash"][:12] if row["content_hash"] else "",
        })

    # ─── Error handlers ───────────────────────────────────────

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
    """Load scan, findings, SBOM, and project for report generation."""
    db = get_db()
    scan = db.fetchone("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    if not scan:
        return None, [], {}, None

    # Load project context
    project = None
    if scan["project_id"]:
        proj_row = db.fetchone(
            "SELECT project_id, name, description FROM projects WHERE project_id = ?",
            (scan["project_id"],)
        )
        if proj_row:
            project = dict(proj_row)

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
    return dict(scan), [dict(f) for f in findings], sbom, project


def _progress_callback(scan_id: str, plugin_name: str,
                       status: str, detail: str = ""):
    """Push scan progress events to the SSE event bus."""
    event_bus.publish(ScanEvent(
        scan_id=scan_id,
        plugin_name=plugin_name,
        status=status,
        detail=detail,
    ))
