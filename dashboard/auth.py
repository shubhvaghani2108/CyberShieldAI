import functools
import os
import sys
from urllib.parse import urlparse, urljoin
from flask import request, redirect, url_for, session, current_app, jsonify, has_request_context

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.user_helpers import verify_user_credentials, get_user_by_id


def is_safe_url(target, host_url=None):
    """
    Validates that a redirect target is a safe, relative application path
    and not an open redirect attack.
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if not target.startswith("/"):
        return False
    if target.startswith("//") or target.startswith("/\\"):
        return False
    if "\\" in target:
        return False

    if has_request_context():
        try:
            base = host_url or request.host_url
            ref_url = urlparse(base)
            test_url = urlparse(urljoin(base, target))
            return test_url.scheme in ("http", "https") and (not test_url.netloc or ref_url.netloc == test_url.netloc)
        except Exception:
            return False
    else:
        try:
            parsed = urlparse(target)
            return not parsed.netloc and not parsed.scheme and target.startswith("/")
        except Exception:
            return False


def is_authenticated():
    """Returns True if the current request has an active authenticated user session."""
    return bool(session.get("user_id"))


def get_current_user():
    """Returns the current logged-in user details from session or None."""
    if not is_authenticated():
        return None
    return {
        "id": session.get("user_id"),
        "username": session.get("username", "Operator"),
        "role": session.get("role", "ANALYST"),
        "email": session.get("email", ""),
    }


def login_user(user):
    """Initializes user session on successful login."""
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["email"] = user.get("email", "")
    session["role"] = user.get("role", "ANALYST")
    session["avatar_url"] = user.get("avatar_url", "")
    session.permanent = True


def logout_user():
    """Clears the authentication session."""
    session.clear()


def login_required(view_func):
    """Decorator to require login for a specific route."""
    @functools.wraps(view_func)
    def decorated_view(*args, **kwargs):
        if not is_authenticated():
            next_url = request.full_path if (request.query_string and request.path != request.full_path) else request.path
            return redirect(url_for("login", next=next_url if is_safe_url(next_url) else "/"))
        return view_func(*args, **kwargs)
    return decorated_view


from database.user_helpers import verify_user_credentials, get_user_by_id, has_users

# Public endpoints and path prefixes that bypass authentication
PUBLIC_ENDPOINTS = {
    "login",
    "logout",
    "register",
    "verify_otp",
    "resend_otp",
    "forgot_password",
    "verify_forgot_password_otp",
    "resend_forgot_password_otp",
    "reset_password",
    "setup",
    "health",
    "readiness",
    "static",
    "google_login",
    "google_callback",
}
PUBLIC_PATH_PREFIXES = (
    "/static/",
    "/health",
    "/readiness",
    "/login",
    "/register",
    "/verify-otp",
    "/resend-otp",
    "/forgot-password",
    "/reset-password",
    "/setup",
    "/auth/google",
    "/api/agent/",
)


def setup_auth_middleware(app):
    """
    Configures session security, global before_request authentication gate,
    first-time setup wizard flow, and Jinja template context helpers.
    """
    # 1. Session Security Configuration
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Allow secure cookies if HTTPS is configured, default False for local dev
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0").lower() in ("1", "true")

    # 2. Context Processor for Templates
    @app.context_processor
    def inject_auth_context():
        return {
            "current_user": get_current_user(),
            "is_authenticated": is_authenticated(),
        }

    # 3. Global Authentication Gatekeeper
    @app.before_request
    def require_login_gatekeeper():
        # Fast path: static assets, health, and readiness bypass all checks immediately
        if request.endpoint in ("health", "readiness", "static") or request.path.startswith("/static/"):
            return None

        # If user is already authenticated, the system clearly has users
        if is_authenticated():
            if request.endpoint == "setup" or request.path == "/setup":
                return redirect(url_for("dashboard"))
        else:
            # First-time setup wizard check: if database has 0 users, force /setup
            if not has_users():
                if request.endpoint == "setup":
                    return None
                return redirect(url_for("setup"))

            # If system is already set up and user tries to access /setup, redirect to /login
            if request.endpoint == "setup" or request.path == "/setup":
                return redirect(url_for("login"))

        # Allow static files and public routes
        if request.endpoint in PUBLIC_ENDPOINTS:
            return None

        # Check path-based exclusions
        path = request.path
        if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
            return None

        # If user is not authenticated, redirect to /login
        if not is_authenticated():
            next_target = request.full_path if request.query_string else request.path
            if not is_safe_url(next_target) or next_target.startswith("/login") or next_target.startswith("/logout") or next_target.startswith("/setup") or next_target.startswith("/register"):
                next_target = "/"
            return redirect(url_for("login", next=next_target))

        # Throttled user activity ping (at most once every 60 seconds per session)
        import time
        now_ts = int(time.time())
        user_id = session.get("user_id")
        if user_id and (now_ts - session.get("_last_seen_ping", 0) > 60):
            session["_last_seen_ping"] = now_ts
            from database.user_helpers import update_user_last_seen
            update_user_last_seen(user_id)

        return None
