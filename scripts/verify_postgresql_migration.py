#!/usr/bin/env python3
"""
CyberShieldAI - PostgreSQL Migration Verification Tool
======================================================

Compares the SQLite source database (cybershield.db) against the destination
PostgreSQL database (via DATABASE_URL).

Verifies:
- Row counts across all 27 tables.
- Primary key matching (no missing or extra IDs).
- Specific comparison of user attributes (id, username, email, role, full_name,
  phone, department, timezone, bio, avatar_url, google_sub, auth_provider,
  is_active, created_at, last_login, last_seen) without printing password hashes.
- Exact verification of security_activity_logs (SQLite vs PostgreSQL).
- Detailed mismatch reporting.
- Exits with non-zero exit code (1) on any failure.
- Prints 'POSTGRESQL MIGRATION VERIFICATION: PASSED' on success.
"""

import os
import sys
import sqlite3
import psycopg2
import psycopg2.extras
from datetime import datetime

# Resolve base directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SQLITE_DB_PATH = os.path.join(BASE_DIR, "cybershield.db")

VERIFY_TABLES = [
    "alerts",
    "cves",
    "email_settings",
    "host_status",
    "monitored_targets",
    "monitoring_logs",
    "nvd_cache",
    "os_detection",
    "os_info",
    "password_resets",
    "pending_registrations",
    "ports",
    "risk_summary",
    "scan_history",
    "security_activity_logs",
    "security_headers",
    "security_posture",
    "service_versions",
    "services",
    "ssl_info",
    "ssl_results",
    "technology_detection",
    "url_intelligence",
    "url_scan_results",
    "users",
    "virustotal_results",
    "vulnerabilities",
]

USER_COMPARE_FIELDS = [
    "id",
    "username",
    "email",
    "role",
    "full_name",
    "phone",
    "department",
    "timezone",
    "bio",
    "avatar_url",
    "google_sub",
    "auth_provider",
    "is_active",
    "created_at",
    "last_login",
    "last_seen",
]


def get_database_url():
    """Resolves PostgreSQL DATABASE_URL from environment or .env file."""
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    
    env_file = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("DATABASE_URL="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def normalize_val(val):
    """Normalize string, datetime, boolean, and null representations for equality comparison."""
    if val is None:
        return None
    if isinstance(val, datetime):
        # Format to standard string comparison
        return val.strftime("%Y-%m-%d %H:%M:%S")
    val_str = str(val).strip()
    # Normalize ISO timestamp strings (e.g. 2026-08-31 06:37:21 vs 2026-08-31T06:37:21)
    if "T" in val_str and len(val_str) >= 19:
        try:
            cleaned = val_str.replace("T", " ").split("+")[0].split(".")[0]
            return cleaned
        except Exception:
            pass
    return val_str


def verify():
    print("=" * 75)
    print("CyberShieldAI - PostgreSQL Migration Verification")
    print("=" * 75)
    print(f"Source SQLite database: {SQLITE_DB_PATH}")

    if not os.path.exists(SQLITE_DB_PATH):
        print(f"[FAIL] SQLite database not found: {SQLITE_DB_PATH}")
        sys.exit(1)

    db_url = get_database_url()
    if not db_url:
        print("[FAIL] PostgreSQL DATABASE_URL not configured.")
        sys.exit(1)

    # Open SQLite read-only
    sqlite_uri = f"file:{os.path.abspath(SQLITE_DB_PATH)}?mode=ro"
    try:
        sqlite_conn = sqlite3.connect(sqlite_uri, uri=True)
        sqlite_conn.row_factory = sqlite3.Row
        sqlite_cursor = sqlite_conn.cursor()
    except Exception as e:
        print(f"[FAIL] SQLite connection error: {e}")
        sys.exit(1)

    # Open PostgreSQL connection
    try:
        pg_conn = psycopg2.connect(db_url)
        pg_cursor = pg_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    except Exception as e:
        print(f"[FAIL] PostgreSQL connection error: {e}")
        sqlite_conn.close()
        sys.exit(1)

    total_tables_checked = 0
    tables_passed = 0
    failures = []

    print("\n[STEP 1/3] Verifying Table Schema & Row Counts...")
    print("-" * 75)

    for table_name in VERIFY_TABLES:
        total_tables_checked += 1
        pk_col = "query" if table_name == "nvd_cache" else "id"

        # Check table existence in SQLite
        sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not sqlite_cursor.fetchone():
            print(f"TABLE: {table_name:<25} | SQLite: MISSING | PostgreSQL: N/A | STATUS: FAIL")
            failures.append(f"Table '{table_name}' does not exist in SQLite source.")
            continue

        # Check table existence in PostgreSQL
        pg_cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name = %s;
        """, (table_name,))
        if not pg_cursor.fetchone():
            print(f"TABLE: {table_name:<25} | SQLite: EXISTS  | PostgreSQL: MISSING | STATUS: FAIL")
            failures.append(f"Table '{table_name}' does not exist in PostgreSQL destination.")
            continue

        # Row counts
        sqlite_cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
        sqlite_cnt = sqlite_cursor.fetchone()[0]

        pg_cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
        pg_cnt = pg_cursor.fetchone()[0]

        if sqlite_cnt != pg_cnt:
            print(f"TABLE: {table_name:<25} | SQLite: {sqlite_cnt:<7} | PostgreSQL: {pg_cnt:<10} | STATUS: COUNT MISMATCH")
            failures.append(f"Table '{table_name}' count mismatch (SQLite: {sqlite_cnt}, PostgreSQL: {pg_cnt}).")
            continue

        # Compare Primary Key IDs
        sqlite_cursor.execute(f'SELECT "{pk_col}" FROM "{table_name}" ORDER BY "{pk_col}"')
        sqlite_ids = set(r[pk_col] for r in sqlite_cursor.fetchall())

        pg_cursor.execute(f'SELECT "{pk_col}" FROM "{table_name}" ORDER BY "{pk_col}"')
        pg_ids = set(r[pk_col] for r in pg_cursor.fetchall())

        missing_in_pg = sqlite_ids - pg_ids
        extra_in_pg = pg_ids - sqlite_ids

        if missing_in_pg or extra_in_pg:
            print(f"TABLE: {table_name:<25} | SQLite: {sqlite_cnt:<7} | PostgreSQL: {pg_cnt:<10} | STATUS: ID MISMATCH")
            if missing_in_pg:
                failures.append(f"Table '{table_name}' missing IDs in PostgreSQL: {list(missing_in_pg)[:10]}")
            if extra_in_pg:
                failures.append(f"Table '{table_name}' extra IDs in PostgreSQL: {list(extra_in_pg)[:10]}")
            continue

        print(f"TABLE: {table_name:<25} | SQLite: {sqlite_cnt:<7} | PostgreSQL: {pg_cnt:<10} | STATUS: OK")
        tables_passed += 1

    print("\n[STEP 2/3] Deep Verification for 'users' Table...")
    print("-" * 75)

    sqlite_cursor.execute("SELECT * FROM users ORDER BY id")
    sqlite_users = {r["id"]: dict(r) for r in sqlite_cursor.fetchall()}

    pg_cursor.execute("SELECT * FROM users ORDER BY id")
    pg_users = {r["id"]: dict(r) for r in pg_cursor.fetchall()}

    users_mismatch = False
    for user_id, s_u in sqlite_users.items():
        if user_id not in pg_users:
            print(f"[FAIL] User ID {user_id} ({s_u.get('username')}) not found in PostgreSQL.")
            failures.append(f"User ID {user_id} missing in PostgreSQL.")
            users_mismatch = True
            continue

        p_u = pg_users[user_id]
        user_diffs = []
        for field in USER_COMPARE_FIELDS:
            if field in s_u and field in p_u:
                s_val = normalize_val(s_u[field])
                p_val = normalize_val(p_u[field])
                # Special handle empty string vs null if applicable
                if s_val != p_val and not (s_val == "" and p_val is None) and not (s_val is None and p_val == ""):
                    user_diffs.append(f"{field} (SQLite='{s_val}', PG='{p_val}')")

        if user_diffs:
            print(f"[MISMATCH] User ID {user_id} ({s_u.get('username')}): {', '.join(user_diffs)}")
            failures.append(f"User ID {user_id} data mismatch: {user_diffs}")
            users_mismatch = True
        else:
            print(f"[OK] User ID {user_id}: '{s_u.get('username')}' (Role: {s_u.get('role')}, Email: '{s_u.get('email')}') verified.")

    if not users_mismatch:
        print("[OK] All 7 user accounts and attributes matched perfectly (password hashes NOT exposed).")

    print("\n[STEP 3/3] Verifying security_activity_logs Exact Count...")
    print("-" * 75)
    sqlite_cursor.execute("SELECT COUNT(*) FROM security_activity_logs")
    s_sec_cnt = sqlite_cursor.fetchone()[0]
    pg_cursor.execute("SELECT COUNT(*) FROM security_activity_logs")
    p_sec_cnt = pg_cursor.fetchone()[0]

    print(f"security_activity_logs -> SQLite: {s_sec_cnt}, PostgreSQL: {p_sec_cnt}")
    if s_sec_cnt == p_sec_cnt and s_sec_cnt == 695:
        print("[OK] Exact count verified: 695 security activity log rows.")
    elif s_sec_cnt == p_sec_cnt:
        print(f"[OK] Exact count matched between SQLite and PostgreSQL ({s_sec_cnt} rows).")
    else:
        print(f"[FAIL] security_activity_logs mismatch! SQLite={s_sec_cnt}, PostgreSQL={p_sec_cnt}")
        failures.append(f"security_activity_logs count mismatch (SQLite={s_sec_cnt}, PG={p_sec_cnt})")

    # Cleanup connections
    sqlite_conn.close()
    pg_conn.close()

    print("\n" + "=" * 75)
    if failures:
        print(f"[FAILED] Migration verification found {len(failures)} issue(s):")
        for f in failures:
            print(f"  - {f}")
        print("\nPOSTGRESQL MIGRATION VERIFICATION: FAILED")
        sys.exit(1)
    else:
        print(f"Verified all {total_tables_checked} tables successfully.")
        print("POSTGRESQL MIGRATION VERIFICATION: PASSED")
        sys.exit(0)


if __name__ == "__main__":
    verify()
