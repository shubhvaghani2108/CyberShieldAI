import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone, timedelta
from werkzeug.security import check_password_hash

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import get_db_connection


_PASSWORD_RESET_TABLE_INITIALIZED = False

def init_password_reset_table():
    """
    Idempotently creates the password_resets table in cybershield.db.
    """
    global _PASSWORD_RESET_TABLE_INITIALIZED
    if _PASSWORD_RESET_TABLE_INITIALIZED:
        return
    try:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS password_resets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reset_id TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    email TEXT NOT NULL,
                    otp_hash TEXT NOT NULL,
                    reset_token_hash TEXT DEFAULT NULL,
                    attempts INTEGER DEFAULT 0,
                    max_attempts INTEGER DEFAULT 5,
                    expires_at TIMESTAMP NOT NULL,
                    last_resend_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_used INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_reset_id ON password_resets(reset_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_reset_email ON password_resets(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_reset_user_id ON password_resets(user_id)")
            conn.commit()
            _PASSWORD_RESET_TABLE_INITIALIZED = True
        finally:
            conn.close()
    except Exception as e:
        print(f"[AUTH] Notice: init_password_reset_table deferred ({e})")


def create_password_reset_request(user_id, email, otp_hash, expires_in_minutes=10, max_attempts=5):
    """
    Creates or replaces an active password reset record for a user.
    Returns reset_id (UUID string).
    """
    init_password_reset_table()
    clean_email = (email or "").strip().lower()
    reset_id = str(uuid.uuid4())
    
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=int(expires_in_minutes or 10))).isoformat()
    now_iso = now.isoformat()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Invalidate / remove previous unused reset requests for this email or user_id
        cursor.execute(
            "DELETE FROM password_resets WHERE user_id = ? OR LOWER(email) = LOWER(?)",
            (user_id, clean_email)
        )
        
        cursor.execute("""
            INSERT INTO password_resets (
                reset_id, user_id, email, otp_hash,
                attempts, max_attempts, expires_at, last_resend_at, is_used, created_at
            )
            VALUES (?, ?, ?, ?, 0, ?, ?, ?, 0, ?)
        """, (
            reset_id, int(user_id), clean_email, otp_hash,
            int(max_attempts or 5), expires_at, now_iso, now_iso
        ))
        conn.commit()
        return reset_id
    finally:
        conn.close()


def get_password_reset_by_id(reset_id):
    """
    Retrieves an active password reset record by reset_id.
    """
    if not reset_id:
        return None
    init_password_reset_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM password_resets WHERE reset_id = ? LIMIT 1", (str(reset_id).strip(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def increment_password_reset_attempts(reset_id):
    """
    Increments the verification attempt counter for a password reset request.
    Returns updated attempt count.
    """
    if not reset_id:
        return 0
    init_password_reset_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE password_resets SET attempts = attempts + 1 WHERE reset_id = ?",
            (str(reset_id).strip(),)
        )
        conn.commit()
        cursor.execute("SELECT attempts FROM password_resets WHERE reset_id = ? LIMIT 1", (str(reset_id).strip(),))
        row = cursor.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def update_password_reset_otp(reset_id, new_otp_hash, expires_in_minutes=10):
    """
    Updates the OTP hash and resets expiration timer during resend.
    """
    if not reset_id or not new_otp_hash:
        return False
    init_password_reset_table()
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=int(expires_in_minutes or 10))).isoformat()
    now_iso = now.isoformat()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE password_resets
            SET otp_hash = ?, expires_at = ?, last_resend_at = ?, attempts = 0
            WHERE reset_id = ? AND is_used = 0
        """, (new_otp_hash, expires_at, now_iso, str(reset_id).strip()))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def authorize_password_reset_token(reset_id, reset_token_hash):
    """
    Stores the authorization token hash after successful OTP verification,
    allowing the user to access the /reset-password screen.
    """
    if not reset_id or not reset_token_hash:
        return False
    init_password_reset_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE password_resets
            SET reset_token_hash = ?
            WHERE reset_id = ? AND is_used = 0
        """, (reset_token_hash, str(reset_id).strip()))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def verify_and_consume_reset_token(reset_id, raw_token):
    """
    Verifies that the provided raw_token matches reset_token_hash and marks the request as used.
    Returns (success: bool, user_id: int or None)
    """
    if not reset_id or not raw_token:
        return False, None
    init_password_reset_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM password_resets WHERE reset_id = ? AND is_used = 0 LIMIT 1", (str(reset_id).strip(),))
        row = cursor.fetchone()
        if not row:
            return False, None
        
        record = dict(row)
        token_hash = record.get("reset_token_hash")
        if not token_hash or not check_password_hash(token_hash, str(raw_token).strip()):
            return False, None

        # Check expiration
        try:
            exp_time = datetime.fromisoformat(record["expires_at"])
            if exp_time.tzinfo is None:
                exp_time = exp_time.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_time:
                return False, None
        except Exception:
            return False, None

        # Mark as consumed / used (single-use)
        cursor.execute("UPDATE password_resets SET is_used = 1 WHERE reset_id = ?", (str(reset_id).strip(),))
        conn.commit()
        return True, record.get("user_id")
    finally:
        conn.close()


def delete_password_reset(reset_id):
    """
    Permanently deletes a password reset record.
    """
    if not reset_id:
        return False
    init_password_reset_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM password_resets WHERE reset_id = ?", (str(reset_id).strip(),))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


