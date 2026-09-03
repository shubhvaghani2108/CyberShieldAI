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

from database.db_engine import register_db_teardown

# Instantiate Flask application
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "cybershield-monitoring-secret-key-soc")

# Register connection pooling teardown
register_db_teardown(app)

# Safe database initialization (never crashes boot if Supabase connection is establishing)
try:
    init_db()
    init_users_table()
except Exception as e:
    print(f"[STARTUP] Notice: Initial database sync deferred ({e})")

# Configure authentication middleware and session security
setup_auth_middleware(app)

# Register dashboard routes
register_routes(app)

import hashlib
import urllib.parse

# Inject safe csrf_token and universal email avatar helper into Jinja context
@app.context_processor
def inject_template_helpers():
    def get_user_avatar(user_or_dict=None, email="", username="", full_name=""):
        if isinstance(user_or_dict, dict):
            if user_or_dict.get("avatar_url"):
                return user_or_dict["avatar_url"]
            email = user_or_dict.get("email", "")
            username = user_or_dict.get("username", "")
            full_name = user_or_dict.get("full_name", "")
        elif isinstance(user_or_dict, str) and user_or_dict.strip():
            if user_or_dict.startswith("http") or user_or_dict.startswith("/static"):
                return user_or_dict
            if "@" in user_or_dict:
                email = user_or_dict
            else:
                username = user_or_dict

        clean_email = (email or "").strip().lower()
        name = (full_name or (clean_email.split("@")[0] if clean_email else username) or "User").strip()
        encoded_name = urllib.parse.quote(name)
        fallback = urllib.parse.quote(f"https://ui-avatars.com/api/?name={encoded_name}&background=0284c7&color=ffffff&bold=true&rounded=true&size=256")

        if clean_email:
            email_hash = hashlib.md5(clean_email.encode("utf-8")).hexdigest()
            return f"https://www.gravatar.com/avatar/{email_hash}?s=256&d={fallback}"

        return f"https://ui-avatars.com/api/?name={encoded_name}&background=0284c7&color=ffffff&bold=true&rounded=true&size=256"

    return dict(
        csrf_token=lambda: os.environ.get("CSRF_TOKEN", "cybershield-csrf-token"),
        get_user_avatar=get_user_avatar,
    )

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


# Start background monitoring daemon safely (avoid duplicate instances in test runs or worker reloads)
if os.environ.get("ENABLE_BACKGROUND_SCHEDULER", "1") == "1":
    if os.environ.get("WERKZEUG_RUN_MAIN") in (None, "true"):
        try:
            from scheduler.monitor import start_background_scheduler
            start_background_scheduler(check_interval_seconds=60)
        except Exception as e:
            print(f"[STARTUP] Notice: background monitoring scheduler initialization: {e}")

if __name__ == "__main__":
    app.run(debug=True)