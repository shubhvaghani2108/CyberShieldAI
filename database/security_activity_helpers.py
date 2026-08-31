import os
import sys
from datetime import datetime, timezone
from flask import has_request_context, request

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import get_db_connection
from database.user_helpers import get_user_activity_metrics


def init_security_activity_table():
    """Idempotently initializes the security_activity_logs table and indexes."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT DEFAULT '',
                email TEXT DEFAULT '',
                event_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'SUCCESS',
                ip_address TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                details TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_activity_event_type ON security_activity_logs(event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_activity_created_at ON security_activity_logs(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_activity_user_id ON security_activity_logs(user_id)")
        conn.commit()
    finally:
        conn.close()


def get_client_ip():
    """Safely extracts client IP address from request headers or remote_addr."""
    if has_request_context():
        try:
            xff = request.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
            return request.remote_addr or "127.0.0.1"
        except Exception:
            return "127.0.0.1"
    return "127.0.0.1"


def get_client_user_agent():
    """Safely extracts client User-Agent string from request headers."""
    if has_request_context():
        try:
            return (request.user_agent.string if request.user_agent else request.headers.get("User-Agent", ""))[:255]
        except Exception:
            return ""
    return ""


def log_security_activity(event_type, status="SUCCESS", username="", email="", user_id=None, ip_address=None, user_agent=None, details=""):
    """
    Logs an authentication or security event.
    Guarantees no sensitive credentials (passwords, OTPs, API keys) are ever written.
    """
    init_security_activity_table()

    ip = ip_address if ip_address is not None else get_client_ip()
    ua = user_agent if user_agent is not None else get_client_user_agent()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_activity_logs (
                user_id, username, email, event_type, status, ip_address, user_agent, details, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                user_id,
                (username or "").strip(),
                (email or "").strip().lower(),
                str(event_type).strip().upper(),
                str(status).strip().upper(),
                str(ip).strip(),
                str(ua).strip(),
                str(details).strip(),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        return None
    finally:
        conn.close()


def get_security_activity_logs(event_filter=None, page=1, per_page=20):
    """
    Fetches paginated security activity logs with optional category filter.
    Returns: (logs: list[dict], total_count: int, total_pages: int, current_page: int)
    """
    init_security_activity_table()

    page = max(1, int(page or 1))
    per_page = max(1, min(100, int(per_page or 20)))
    offset = (page - 1) * per_page

    filter_map = {
        "login": ["LOGIN_SUCCESS"],
        "failed_login": ["LOGIN_FAILED"],
        "registration": ["REGISTRATION", "OTP_VERIFIED"],
        "otp": ["OTP_VERIFIED", "OTP_FAILED"],
        "password_reset": ["PASSWORD_RESET_REQUESTED", "PASSWORD_RESET_COMPLETED"],
        "logout": ["LOGOUT"],
    }

    selected_types = filter_map.get(event_filter.lower()) if event_filter and event_filter.lower() in filter_map else None

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if selected_types:
            placeholders = ",".join("?" for _ in selected_types)
            cursor.execute(f"SELECT COUNT(*) FROM security_activity_logs WHERE event_type IN ({placeholders})", selected_types)
            total_count = cursor.fetchone()[0]

            cursor.execute(
                f"""
                SELECT id, user_id, username, email, event_type, status, ip_address, user_agent, details, created_at
                FROM security_activity_logs
                WHERE event_type IN ({placeholders})
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                selected_types + [per_page, offset],
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM security_activity_logs")
            total_count = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT id, user_id, username, email, event_type, status, ip_address, user_agent, details, created_at
                FROM security_activity_logs
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (per_page, offset),
            )

        rows = [dict(row) for row in cursor.fetchall()]
        total_pages = max(1, (total_count + per_page - 1) // per_page)
        return rows, total_count, total_pages, page
    finally:
        conn.close()


def get_security_activity_metrics():
    """
    Calculates summary metrics:
    - total_users
    - active_users
    - successful_logins_today
    - failed_logins_today
    - password_resets_today
    """
    init_security_activity_table()
    user_metrics = get_user_activity_metrics()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Successful Logins Today
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM security_activity_logs
            WHERE event_type = 'LOGIN_SUCCESS' AND created_at LIKE ?
            """,
            (f"{today_str}%",),
        )
        successful_logins_today = cursor.fetchone()[0]

        # Failed Logins Today
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM security_activity_logs
            WHERE event_type = 'LOGIN_FAILED' AND created_at LIKE ?
            """,
            (f"{today_str}%",),
        )
        failed_logins_today = cursor.fetchone()[0]

        # Password Resets Today
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM security_activity_logs
            WHERE event_type IN ('PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_COMPLETED') AND created_at LIKE ?
            """,
            (f"{today_str}%",),
        )
        password_resets_today = cursor.fetchone()[0]

        return {
            "total_users": user_metrics.get("total_users", user_metrics.get("total", 0)),
            "active_users": user_metrics.get("active_users", user_metrics.get("active", 0)),
            "successful_logins_today": successful_logins_today,
            "failed_logins_today": failed_logins_today,
            "password_resets_today": password_resets_today,
        }
    finally:
        conn.close()
