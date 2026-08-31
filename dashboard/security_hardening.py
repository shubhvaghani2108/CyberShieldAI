import hmac
import logging
import os
import secrets
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from flask import has_request_context, request, session

logger = logging.getLogger("cybershield.security")

# Thread-safe in-memory stores for rate limiting
_RATE_LIMIT_LOCK = threading.Lock()
_FAILED_LOGINS = defaultdict(list)        # key -> list of timestamp floats
_OTP_REQUESTS = defaultdict(list)         # key -> list of timestamp floats
_RESEND_TIMESTAMPS = {}                   # key -> last resend timestamp float

# Configurable constants
LOGIN_MAX_FAILED_ATTEMPTS = int(os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS", 5))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", 900))        # 15 minutes

OTP_MAX_REQUESTS = int(os.environ.get("OTP_MAX_REQUESTS", 5))
OTP_REQUEST_WINDOW_SECONDS = int(os.environ.get("OTP_REQUEST_WINDOW_SECONDS", 900)) # 15 minutes
OTP_RESEND_COOLDOWN_SECONDS = int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", 60)) # 60 seconds

PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", 8))


def get_client_ip_address() -> str:
    """Safely extracts client IP address from X-Forwarded-For or remote_addr."""
    if has_request_context():
        try:
            xff = request.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
            return request.remote_addr or "127.0.0.1"
        except Exception:
            return "127.0.0.1"
    return "127.0.0.1"


# =============================================================================
# 1. LOGIN RATE LIMITING
# =============================================================================

def check_login_rate_limit(identity: str, ip: str = None) -> tuple[bool, int]:
    """
    Checks if login attempts are within rate limits.
    Returns: (is_allowed: bool, time_remaining_seconds: int)
    """
    now = time.time()
    ip_addr = ip or get_client_ip_address()
    clean_identity = (identity or "").strip().lower()

    keys = []
    if clean_identity:
        keys.append(f"user:{clean_identity}")
    if ip_addr:
        keys.append(f"ip:{ip_addr}")

    with _RATE_LIMIT_LOCK:
        for key in keys:
            # Filter timestamps within lockout window
            attempts = [t for t in _FAILED_LOGINS[key] if (now - t) < LOGIN_LOCKOUT_SECONDS]
            _FAILED_LOGINS[key] = attempts

            if len(attempts) >= LOGIN_MAX_FAILED_ATTEMPTS:
                earliest = min(attempts)
                remaining = int(LOGIN_LOCKOUT_SECONDS - (now - earliest))
                return False, max(1, remaining)

    return True, 0


def record_failed_login(identity: str, ip: str = None):
    """Records a failed login attempt for the given identity and IP."""
    now = time.time()
    ip_addr = ip or get_client_ip_address()
    clean_identity = (identity or "").strip().lower()

    with _RATE_LIMIT_LOCK:
        if clean_identity:
            _FAILED_LOGINS[f"user:{clean_identity}"].append(now)
        if ip_addr:
            _FAILED_LOGINS[f"ip:{ip_addr}"].append(now)


def record_successful_login(identity: str, ip: str = None):
    """Clears failed login attempt counters upon successful authentication."""
    ip_addr = ip or get_client_ip_address()
    clean_identity = (identity or "").strip().lower()

    with _RATE_LIMIT_LOCK:
        if clean_identity:
            _FAILED_LOGINS.pop(f"user:{clean_identity}", None)
        if ip_addr:
            _FAILED_LOGINS.pop(f"ip:{ip_addr}", None)


# =============================================================================
# 2. OTP RATE LIMITING & COOLDOWNS
# =============================================================================

def check_otp_request_rate_limit(target: str, action: str = "request") -> tuple[bool, int]:
    """
    Checks whether OTP generation requests are within allowed thresholds.
    Returns: (is_allowed: bool, wait_seconds: int)
    """
    now = time.time()
    ip_addr = get_client_ip_address()
    clean_target = (target or "").strip().lower()

    keys = [f"otp_req:{action}:{clean_target}", f"otp_req_ip:{ip_addr}"]

    with _RATE_LIMIT_LOCK:
        for key in keys:
            attempts = [t for t in _OTP_REQUESTS[key] if (now - t) < OTP_REQUEST_WINDOW_SECONDS]
            _OTP_REQUESTS[key] = attempts

            if len(attempts) >= OTP_MAX_REQUESTS:
                earliest = min(attempts)
                remaining = int(OTP_REQUEST_WINDOW_SECONDS - (now - earliest))
                return False, max(1, remaining)

    return True, 0


def record_otp_request(target: str, action: str = "request"):
    """Records an OTP request timestamp."""
    now = time.time()
    ip_addr = get_client_ip_address()
    clean_target = (target or "").strip().lower()

    with _RATE_LIMIT_LOCK:
        if clean_target:
            _OTP_REQUESTS[f"otp_req:{action}:{clean_target}"].append(now)
        if ip_addr:
            _OTP_REQUESTS[f"otp_req_ip:{ip_addr}"].append(now)


def check_otp_resend_cooldown(session_key: str, cooldown_seconds: int = None) -> tuple[bool, int]:
    """
    Verifies that the mandatory cooldown between OTP resends has elapsed.
    Returns: (is_allowed: bool, remaining_seconds: int)
    """
    cooldown = cooldown_seconds or OTP_RESEND_COOLDOWN_SECONDS
    now = time.time()

    with _RATE_LIMIT_LOCK:
        last_sent = _RESEND_TIMESTAMPS.get(session_key, 0)
        elapsed = now - last_sent
        if elapsed < cooldown:
            remaining = int(cooldown - elapsed)
            return False, max(1, remaining)

    return True, 0


def record_otp_resend(session_key: str):
    """Records the timestamp of an OTP resend."""
    now = time.time()
    with _RATE_LIMIT_LOCK:
        _RESEND_TIMESTAMPS[session_key] = now


# =============================================================================
# 3. PASSWORD SECURITY & VALIDATION
# =============================================================================

def validate_password_strength(password: str, min_length: int = None) -> tuple[bool, str]:
    """
    Enforces password policies:
    - Minimum length (default 8 chars)
    - Non-empty
    """
    min_len = min_length or PASSWORD_MIN_LENGTH
    if not password or not isinstance(password, str):
        return False, "Password cannot be empty."

    if len(password) < min_len:
        return False, f"Password must be at least {min_len} characters long."

    return True, ""


# =============================================================================
# 4. CSRF TOKEN MANAGEMENT
# =============================================================================

def get_or_create_csrf_token() -> str:
    """
    Returns or creates a cryptographically strong session-bound CSRF token.
    """
    if not has_request_context():
        return "cybershield-csrf-token"

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
        session.modified = True

    return session["_csrf_token"]


def validate_csrf_token(provided_token: str) -> bool:
    """
    Validates a submitted CSRF token against the active session token
    using constant-time string comparison.
    """
    if not has_request_context():
        return True

    expected = session.get("_csrf_token")
    if not expected:
        # If no session token was set, initialize one and accept fallback if configured
        return True

    if not provided_token:
        return False

    return hmac.compare_digest(str(provided_token).strip(), str(expected).strip())
