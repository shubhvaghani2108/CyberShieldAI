import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from flask import Flask

# Database & Data Helper Imports
from database.db_helpers import (
    get_db_connection,
    init_db,
    get_latest_ip,
    get_latest_host_status,
    get_latest_url_scan,
    get_latest_technology,
    get_latest_url_intelligence,
    get_url_scan_dashboard_context,
    get_dashboard_data,
    get_recent_activity,
    get_risk_trend,
    get_ip_scan_context,
)

# Background Scan Jobs & Task State Imports
from dashboard.scan_jobs import (
    SCAN_JOBS,
    SCAN_JOBS_LOCK,
    _new_job,
    _job_log,
    _job_done,
    _job_error,
    _run_ip_scan_job,
    _run_url_scan_job,
)

# PDF Generator Imports
from dashboard.pdf_generator import (
    _build_ip_scan_pdf,
    _build_url_scan_pdf,
    _build_empty_state_pdf,
)

# Route Handler & Auth Imports
from dashboard.routes import register_routes
from dashboard.auth import setup_auth_middleware
from database.user_helpers import init_users_table

# Instantiate Flask application
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "cybershield-monitoring-secret-key-soc")

# Initialize database tables and user authentication tables
init_db()
init_users_table()

# Configure authentication middleware and session security
setup_auth_middleware(app)

# Register dashboard routes
register_routes(app)

# Inject safe csrf_token helper into Jinja context
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=lambda: os.environ.get("CSRF_TOKEN", "cybershield-csrf-token"))

# Security Headers Middleware
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' "
        "https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com "
        "https://api.dicebear.com https://lh3.googleusercontent.com https://accounts.google.com data: blob:; "
        "img-src 'self' data: https: blob:;"
    )
    return response


# Safe Error Handlers (No stack traces or internal secrets exposed)
from flask import render_template, jsonify, request

@app.errorhandler(400)
def handle_400(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"status": "error", "error": 400, "message": "Bad Request"}), 400
    return render_template("base.html", error_message="400 - Bad Request"), 400

@app.errorhandler(403)
def handle_403(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"status": "error", "error": 403, "message": "Access Denied: Administrator privileges required."}), 403
    return render_template("base.html", error_message="403 - Forbidden: Administrator Privileges Required"), 403

@app.errorhandler(404)
def handle_404(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"status": "error", "error": 404, "message": "Resource Not Found"}), 404
    return render_template("base.html", error_message="404 - Page Not Found"), 404

@app.errorhandler(500)
def handle_500(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"status": "error", "error": 500, "message": "Internal Server Error"}), 500
    return render_template("base.html", error_message="500 - Internal Server Error"), 500


# Start background monitoring daemon
from scheduler.monitor import start_background_scheduler
start_background_scheduler(check_interval_seconds=60)

if __name__ == "__main__":
    app.run(debug=True)