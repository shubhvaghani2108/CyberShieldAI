import os
import sqlite3
import sys
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import get_db_connection


def init_users_table():
    """Idempotently creates the users table if not exists, and migrates missing columns."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'ANALYST',
            email TEXT DEFAULT '',
            full_name TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            department TEXT DEFAULT '',
            timezone TEXT DEFAULT 'Asia/Kolkata',
            bio TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            google_sub TEXT UNIQUE,
            auth_provider TEXT DEFAULT 'local',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """
    )
    conn.commit()

    # Automatic schema migration for existing databases
    cursor.execute("PRAGMA table_info(users)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    new_cols = [
        ("full_name", "TEXT DEFAULT ''"),
        ("phone", "TEXT DEFAULT ''"),
        ("department", "TEXT DEFAULT ''"),
        ("timezone", "TEXT DEFAULT 'Asia/Kolkata'"),
        ("bio", "TEXT DEFAULT ''"),
        ("avatar_url", "TEXT DEFAULT ''"),
        ("google_sub", "TEXT"),
        ("auth_provider", "TEXT DEFAULT 'local'"),
        ("last_seen", "TIMESTAMP"),
    ]
    for col_name, col_type in new_cols:
        if col_name not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass
    try:
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL AND google_sub != ''")
    except Exception:
        pass
    conn.commit()
    conn.close()


def get_user_by_username(username):
    """Fetches a single user record by username (case-insensitive search)."""
    if not username:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(username) = LOWER(?)
            LIMIT 1
            """,
            (username.strip(),),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def get_user_by_id(user_id):
    """Fetches a single user record by user_id."""
    if not user_id:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def get_user_by_email(email):
    """Fetches a single user record by email (case-insensitive search)."""
    if not email:
        return None
    clean_email = str(email).strip()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(TRIM(COALESCE(email, ''))) = LOWER(?)
            LIMIT 1
            """,
            (clean_email,),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def get_user_by_google_sub(google_sub):
    """Fetches a single user record by their verified Google Subject ID (sub)."""
    if not google_sub:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE google_sub = ?
            LIMIT 1
            """,
            (str(google_sub).strip(),),
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def generate_unique_username(base_name):
    """
    Generates a clean, unique local username from a base string.
    Example: 'operator' -> 'operator', 'operator2', 'operator3'
    """
    import re
    # Clean base name to alphanumeric and underscore
    clean_base = re.sub(r"[^a-zA-Z0-9_]", "_", (base_name or "user").strip().lower())
    clean_base = clean_base.strip("_") or "user"

    candidate = clean_base
    counter = 1
    while get_user_by_username(candidate) is not None:
        counter += 1
        candidate = f"{clean_base}{counter}"
    return candidate


def create_google_user(email, google_sub, full_name="", avatar_url="", role="USER"):
    """
    Creates a new user authenticated via Google OAuth.
    Sets auth_provider='google', securely generates random password hash (no plaintext password),
    and assigns the default USER role (non-admin).
    """
    import secrets
    email = (email or "").strip()
    if not email or not google_sub:
        raise ValueError("Google email and verified google_sub are required.")

    base_name = email.split("@")[0]
    username = generate_unique_username(base_name)
    dummy_password_hash = generate_password_hash(secrets.token_urlsafe(32))
    role = (role or "USER").strip().upper()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role, email, full_name, avatar_url, google_sub, auth_provider, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'google', 1, CURRENT_TIMESTAMP)
            """,
            (username, dummy_password_hash, role, email, full_name or "", avatar_url or "", str(google_sub).strip()),
        )
        conn.commit()
        return get_user_by_id(cursor.lastrowid)
    finally:
        conn.close()


def link_google_identity(user_id, google_sub, avatar_url=None):
    """Links an existing local user with verified Google Subject ID."""
    if not user_id or not google_sub:
        return False
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if avatar_url:
            cursor.execute(
                """
                UPDATE users
                SET google_sub = ?, auth_provider = 'google', avatar_url = ?
                WHERE id = ?
                """,
                (str(google_sub).strip(), avatar_url, user_id),
            )
        else:
            cursor.execute(
                """
                UPDATE users
                SET google_sub = ?
                WHERE id = ?
                """,
                (str(google_sub).strip(), user_id),
            )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def create_user(username, password, role="ANALYST", email="", is_active=1, full_name="", phone="", department="", timezone="Asia/Kolkata", bio="", avatar_url="", google_sub=None, auth_provider="local"):
    """
    Creates a new local user with a securely hashed password.
    Returns user ID on success or raises an exception/returns None if existing.
    """
    username = (username or "").strip()
    if not username or not password:
        raise ValueError("Username and password are required.")

    password_hash = generate_password_hash(password)
    return create_user_with_hash(
        username=username,
        password_hash=password_hash,
        role=role,
        email=email,
        is_active=is_active,
        full_name=full_name,
        phone=phone,
        department=department,
        timezone=timezone,
        bio=bio,
        avatar_url=avatar_url,
        google_sub=google_sub,
        auth_provider=auth_provider,
    )


def create_user_with_hash(username, password_hash, role="USER", email="", is_active=1, full_name="", phone="", department="", timezone="Asia/Kolkata", bio="", avatar_url="", google_sub=None, auth_provider="local"):
    """
    Creates a new local user with an already securely hashed password (e.g. from OTP verification).
    """
    username = (username or "").strip()
    if not username or not password_hash:
        raise ValueError("Username and password_hash are required.")

    role = (role or "USER").strip().upper()
    email = (email or "").strip()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role, email, full_name, phone, department, timezone, bio, avatar_url, google_sub, auth_provider, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (username, password_hash, role, email, full_name, phone, department, timezone, bio, avatar_url, google_sub, auth_provider or "local", 1 if is_active else 0),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def update_user_password(username, new_password):
    """Updates an existing user's password hash."""
    username = (username or "").strip()
    if not username or not new_password:
        raise ValueError("Username and new password are required.")

    password_hash = generate_password_hash(new_password)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE LOWER(username) = LOWER(?)
            """,
            (password_hash, username),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def update_user_profile(user_id, username=None, email=None, full_name=None, phone=None, department=None, timezone=None, bio=None, avatar_url=None):
    """
    Updates profile fields (username, email, full_name, phone, department, timezone, bio, avatar_url) for a user.
    Returns (success: bool, error_message: str or None)
    """
    if not user_id:
        return False, "Invalid user ID."

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # If username is provided, ensure uniqueness
        if username is not None:
            clean_username = username.strip()
            if not clean_username:
                return False, "Username cannot be empty."
            cursor.execute(
                "SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?",
                (clean_username, user_id),
            )
            existing = cursor.fetchone()
            if existing:
                return False, "This username is already taken by another account."

            cursor.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (clean_username, user_id),
            )

        updates = []
        params = []
        if email is not None:
            updates.append("email = ?")
            params.append(email.strip())
        if full_name is not None:
            updates.append("full_name = ?")
            params.append(full_name.strip())
        if phone is not None:
            updates.append("phone = ?")
            params.append(phone.strip())
        if department is not None:
            updates.append("department = ?")
            params.append(department.strip())
        if timezone is not None:
            updates.append("timezone = ?")
            params.append(timezone.strip())
        if bio is not None:
            updates.append("bio = ?")
            params.append(bio.strip())
        if avatar_url is not None:
            updates.append("avatar_url = ?")
            params.append(avatar_url.strip())

        if updates:
            params.append(user_id)
            cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)

        conn.commit()
        return True, None
    except Exception as e:
        return False, f"Failed to update profile: {str(e)}"
    finally:
        conn.close()


def change_password_with_verification(user_id, current_password, new_password):
    """
    Verifies current password and updates to new password.
    Returns (success: bool, error_message: str or None)
    """
    user = get_user_by_id(user_id)
    if not user:
        return False, "User not found."

    if not check_password_hash(user["password_hash"], current_password):
        return False, "Current password is incorrect."

    if len(new_password) < 4:
        return False, "New password must be at least 4 characters long."

    new_hash = generate_password_hash(new_password)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (new_hash, user_id),
        )
        conn.commit()
        return True, None
    finally:
        conn.close()


def update_last_login(user_id):
    """Updates the last_login timestamp for a user."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()


def verify_user_credentials(username_or_email, password):
    """
    Verifies user credentials securely by Username OR Email address.
    Returns the user dict if valid and active, else None.
    """
    if not username_or_email or not password:
        return None

    identifier = str(username_or_email).strip()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE (LOWER(TRIM(username)) = LOWER(?) OR LOWER(TRIM(COALESCE(email, ''))) = LOWER(?))
            LIMIT 1
            """,
            (identifier, identifier),
        )
        row = cursor.fetchone()
        if not row:
            return None

        user = dict(row)
        if not user.get("is_active"):
            return None

        stored_hash = user.get("password_hash")
        if not stored_hash or not check_password_hash(stored_hash, password):
            return None

        # Update last login timestamp
        try:
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
            conn.commit()
        except Exception:
            pass

        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "is_active": user["is_active"],
        }
    finally:
        conn.close()


def update_user_last_seen(user_id):
    """Updates last_seen timestamp for user with parameterized query."""
    if not user_id:
        return
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def is_user_online(last_seen, last_login=None, threshold_seconds=300):
    """
    Calculates if a user is ONLINE based on activity timestamp within threshold_seconds (default 5 min).
    Returns True if online (active within 5 min), else False.
    """
    ts = last_seen or last_login
    if not ts:
        return False
    try:
        if isinstance(ts, str):
            try:
                dt = datetime.strptime(ts.split(".")[0], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        elif isinstance(ts, datetime):
            dt = ts.replace(tzinfo=None)
        else:
            return False

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        delta = (now_utc - dt).total_seconds()
        return -5 <= delta <= threshold_seconds
    except Exception:
        return False


def get_user_activity_metrics():
    """
    Returns aggregate user activity statistics:
    - total / total_users: Total accounts
    - active / active_users: Active accounts (is_active == 1)
    - inactive / inactive_users: Disabled accounts (is_active == 0)
    - online / online_users: Currently online accounts (active & last_seen within 5 minutes)
    - offline / offline_users: Offline accounts
    """
    users = list_users()
    total = len(users)
    active = sum(1 for u in users if u.get("is_active"))
    inactive = total - active
    online = sum(1 for u in users if u.get("is_active") and u.get("is_online"))
    offline = total - online
    return {
        "total": total,
        "total_users": total,
        "active": active,
        "active_users": active,
        "inactive": inactive,
        "inactive_users": inactive,
        "online": online,
        "online_users": online,
        "offline": offline,
        "offline_users": offline,
    }


def list_users():
    """Lists all local users (excluding password hashes) for administration and auditing."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, email, full_name, role, is_active, auth_provider, avatar_url, created_at, last_login, last_seen
            FROM users
            ORDER BY id ASC
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        for u in rows:
            u["is_online"] = is_user_online(u.get("last_seen"), u.get("last_login"))
        return rows
    finally:
        conn.close()


def admin_update_user(user_id, username, email="", role="USER", is_active=1, new_password=None, full_name=None):
    """
    Updates user details by an administrator.
    If new_password is provided and non-empty, updates the securely hashed password.
    Returns (success: bool, error_message: str or None)
    """
    if not user_id:
        return False, "Invalid user ID."

    username = (username or "").strip()
    if not username:
        return False, "Username is required."

    role = (role or "USER").strip().upper()
    if role not in ("ADMIN", "ANALYST", "USER"):
        role = "USER"

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Check if username is already taken by another user
        cursor.execute(
            "SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?",
            (username, user_id),
        )
        if cursor.fetchone():
            return False, f"Username '{username}' is already taken by another user."

        # Check if email is already taken by another user if provided
        clean_email = (email or "").strip().lower()
        if clean_email:
            cursor.execute(
                "SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND id != ?",
                (clean_email, user_id),
            )
            if cursor.fetchone():
                return False, f"Email '{clean_email}' is already taken by another account."

        updates = ["username = ?", "email = ?", "role = ?", "is_active = ?"]
        params = [username, clean_email, role, 1 if is_active else 0]

        if full_name is not None:
            updates.append("full_name = ?")
            params.append(full_name.strip())

        if new_password and str(new_password).strip():
            updates.append("password_hash = ?")
            params.append(generate_password_hash(str(new_password).strip()))

        params.append(user_id)
        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
        return True, None
    except Exception as e:
        return False, f"Failed to update user: {str(e)}"
    finally:
        conn.close()


def delete_user(user_id):
    """
    Permanently deletes a user from the database using parameterized SQL.
    Returns (success: bool, error_message: str or None)
    """
    if not user_id:
        return False, "Invalid user ID."

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        if cursor.rowcount > 0:
            return True, None
        return False, "User not found."
    except Exception as e:
        return False, f"Failed to delete user: {str(e)}"
    finally:
        conn.close()


def get_user_count():
    """Returns the total number of registered local users."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        row = cursor.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def has_users():
    """Returns True if there is at least one local user in the database."""
    return get_user_count() > 0
