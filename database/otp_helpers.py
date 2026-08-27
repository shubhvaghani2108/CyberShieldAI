import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone, timedelta

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import get_db_connection


def init_otp_table():
    """
    Idempotently creates the pending_registrations table if not exists.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                registration_id TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 5,
                expires_at TIMESTAMP NOT NULL,
                last_resend_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_reg_id ON pending_registrations(registration_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_email ON pending_registrations(email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_username ON pending_registrations(username)")
        conn.commit()
    finally:
        conn.close()


def create_pending_registration(username, email, password_hash, otp_hash, expires_in_minutes=10, max_attempts=5):
    """
    Creates or replaces a pending registration record for the user.
    Returns registration_id (UUID string).
    """
    init_otp_table()
    username = (username or "").strip()
    email = (email or "").strip().lower()
    registration_id = str(uuid.uuid4())
    
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=int(expires_in_minutes or 10))).isoformat()
    now_iso = now.isoformat()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Invalidate any previous pending registrations for this username or email
        cursor.execute("DELETE FROM pending_registrations WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (username, email))
        
        cursor.execute("""
            INSERT INTO pending_registrations (
                registration_id, username, email, password_hash, otp_hash,
                attempts, max_attempts, expires_at, last_resend_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        """, (
            registration_id, username, email, password_hash, otp_hash,
            int(max_attempts or 5), expires_at, now_iso, now_iso
        ))
        conn.commit()
        return registration_id
    finally:
        conn.close()


def get_pending_registration(registration_id):
    """
    Retrieves a pending registration record by registration_id.
    """
    if not registration_id:
        return None
    init_otp_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_registrations WHERE registration_id = ? LIMIT 1", (str(registration_id).strip(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def get_pending_registration_by_email(email):
    """
    Retrieves a pending registration by email.
    """
    if not email:
        return None
    init_otp_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_registrations WHERE LOWER(email) = LOWER(?) LIMIT 1", (str(email).strip(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def get_pending_registration_by_username(username):
    """
    Retrieves a pending registration by username.
    """
    if not username:
        return None
    init_otp_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_registrations WHERE LOWER(username) = LOWER(?) LIMIT 1", (str(username).strip(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def increment_pending_attempts(registration_id):
    """
    Increments attempt counter for a pending registration.
    Returns the new attempt count.
    """
    if not registration_id:
        return 0
    init_otp_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE pending_registrations
            SET attempts = attempts + 1
            WHERE registration_id = ?
        """, (str(registration_id).strip(),))
        conn.commit()

        cursor.execute("SELECT attempts FROM pending_registrations WHERE registration_id = ?", (str(registration_id).strip(),))
        row = cursor.fetchone()
        return row["attempts"] if row else 0
    finally:
        conn.close()


def update_pending_otp(registration_id, new_otp_hash, expires_in_minutes=10):
    """
    Updates the OTP hash, resets attempts, and updates expiration and resend timestamps.
    """
    if not registration_id:
        return False
    init_otp_table()
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=int(expires_in_minutes or 10))).isoformat()
    now_iso = now.isoformat()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE pending_registrations
            SET otp_hash = ?,
                attempts = 0,
                expires_at = ?,
                last_resend_at = ?
            WHERE registration_id = ?
        """, (new_otp_hash, expires_at, now_iso, str(registration_id).strip()))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def delete_pending_registration(registration_id):
    """
    Deletes a pending registration upon successful verification or invalidation.
    """
    if not registration_id:
        return False
    init_otp_table()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM pending_registrations WHERE registration_id = ?", (str(registration_id).strip(),))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def cleanup_expired_registrations():
    """
    Deletes expired pending registrations older than 24 hours.
    """
    init_otp_table()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM pending_registrations WHERE expires_at < ?", (cutoff,))
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()
