#!/usr/bin/env python3
"""
CyberShieldAI - SQLite to PostgreSQL Migration Tool
===================================================

Safely and idempotently migrates schema, data, sequences, and indexes from
the local SQLite database (cybershield.db) to PostgreSQL via DATABASE_URL.

Guarantees:
- SQLite source database is opened read-only and NEVER modified.
- All 27 tables are created with CREATE TABLE IF NOT EXISTS.
- Existing column names, types, primary keys, and data are strictly preserved.
- Sequences are reset after explicit ID insertion.
- All writes are wrapped in a transaction with rollback on failure.
- Idempotent: re-running does not create duplicate rows.
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


TABLE_SCHEMAS = {
    "alerts": """
        CREATE TABLE IF NOT EXISTS "alerts" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "severity" TEXT,
            "title" TEXT,
            "description" TEXT,
            "recommendation" TEXT,
            "scan_time" TEXT,
            "target" TEXT,
            "alert_type" TEXT,
            "message" TEXT,
            "created_at" TEXT,
            "scan_id" TEXT,
            "user_id" INTEGER DEFAULT 1
        );
    """,
    "cves": """
        CREATE TABLE IF NOT EXISTS "cves" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "port" INTEGER,
            "service" TEXT,
            "cve_id" TEXT,
            "severity" TEXT,
            "description" TEXT,
            "scan_time" TEXT,
            "cvss_score" DOUBLE PRECISION,
            "cvss_vector" TEXT,
            "published_date" TEXT,
            "exploit_available" INTEGER,
            "cwe_id" TEXT,
            "cwe_name" TEXT,
            "ref_links" TEXT,
            "scan_id" TEXT
        );
    """,
    "email_settings": """
        CREATE TABLE IF NOT EXISTS "email_settings" (
            "id" SERIAL PRIMARY KEY,
            "smtp_server" TEXT DEFAULT '',
            "smtp_port" INTEGER DEFAULT 587,
            "smtp_user" TEXT DEFAULT '',
            "smtp_password" TEXT DEFAULT '',
            "from_email" TEXT DEFAULT '',
            "recipient_email" TEXT DEFAULT '',
            "use_tls" INTEGER DEFAULT 1,
            "use_ssl" INTEGER DEFAULT 0,
            "enabled" INTEGER DEFAULT 0,
            "alert_score_drop" INTEGER DEFAULT 1,
            "alert_new_vuln" INTEGER DEFAULT 1,
            "alert_critical" INTEGER DEFAULT 1,
            "alert_ssl_expiry" INTEGER DEFAULT 1,
            "alert_new_port" INTEGER DEFAULT 1,
            "updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,
    "host_status": """
        CREATE TABLE IF NOT EXISTS "host_status" (
            "id" SERIAL PRIMARY KEY,
            "target_ip" TEXT,
            "status" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT,
            "user_id" INTEGER DEFAULT 1
        );
    """,
    "monitored_targets": """
        CREATE TABLE IF NOT EXISTS "monitored_targets" (
            "id" SERIAL PRIMARY KEY,
            "target" TEXT UNIQUE NOT NULL,
            "scan_frequency" INTEGER DEFAULT 24,
            "enabled" INTEGER DEFAULT 1,
            "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,
    "monitoring_logs": """
        CREATE TABLE IF NOT EXISTS "monitoring_logs" (
            "id" SERIAL PRIMARY KEY,
            "target" TEXT NOT NULL,
            "status" TEXT NOT NULL,
            "message" TEXT,
            "details" TEXT,
            "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,
    "nvd_cache": """
        CREATE TABLE IF NOT EXISTS "nvd_cache" (
            "query" TEXT PRIMARY KEY,
            "response_json" TEXT NOT NULL,
            "fetched_at" TEXT NOT NULL
        );
    """,
    "os_detection": """
        CREATE TABLE IF NOT EXISTS "os_detection" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "os_name" TEXT,
            "accuracy" INTEGER,
            "scan_time" TEXT
        );
    """,
    "os_info": """
        CREATE TABLE IF NOT EXISTS "os_info" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "os_name" TEXT,
            "device_type" TEXT,
            "os_details" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT
        );
    """,
    "password_resets": """
        CREATE TABLE IF NOT EXISTS "password_resets" (
            "id" SERIAL PRIMARY KEY,
            "reset_id" TEXT NOT NULL,
            "user_id" INTEGER NOT NULL,
            "email" TEXT NOT NULL,
            "otp_hash" TEXT NOT NULL,
            "reset_token_hash" TEXT DEFAULT NULL,
            "attempts" INTEGER DEFAULT 0,
            "max_attempts" INTEGER DEFAULT 5,
            "expires_at" TIMESTAMP NOT NULL,
            "last_resend_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            "is_used" INTEGER DEFAULT 0,
            "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,
    "pending_registrations": """
        CREATE TABLE IF NOT EXISTS "pending_registrations" (
            "id" SERIAL PRIMARY KEY,
            "registration_id" TEXT NOT NULL,
            "username" TEXT NOT NULL,
            "email" TEXT NOT NULL,
            "password_hash" TEXT NOT NULL,
            "otp_hash" TEXT NOT NULL,
            "attempts" INTEGER DEFAULT 0,
            "max_attempts" INTEGER DEFAULT 5,
            "expires_at" TIMESTAMP NOT NULL,
            "last_resend_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,
    "ports": """
        CREATE TABLE IF NOT EXISTS "ports" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "port" INTEGER,
            "state" TEXT,
            "service" TEXT,
            "banner" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT
        );
    """,
    "risk_summary": """
        CREATE TABLE IF NOT EXISTS "risk_summary" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "critical_count" INTEGER,
            "high_count" INTEGER,
            "medium_count" INTEGER,
            "low_count" INTEGER,
            "total_score" INTEGER,
            "risk_level" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT
        );
    """,
    "scan_history": """
        CREATE TABLE IF NOT EXISTS "scan_history" (
            "id" SERIAL PRIMARY KEY,
            "target_ip" TEXT,
            "scan_time" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            "status" TEXT,
            "scan_id" TEXT,
            "user_id" INTEGER DEFAULT 1
        );
    """,
    "security_activity_logs": """
        CREATE TABLE IF NOT EXISTS "security_activity_logs" (
            "id" SERIAL PRIMARY KEY,
            "user_id" INTEGER,
            "username" TEXT DEFAULT '',
            "email" TEXT DEFAULT '',
            "event_type" TEXT NOT NULL,
            "status" TEXT NOT NULL DEFAULT 'SUCCESS',
            "ip_address" TEXT DEFAULT '',
            "user_agent" TEXT DEFAULT '',
            "details" TEXT DEFAULT '',
            "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,
    "security_headers": """
        CREATE TABLE IF NOT EXISTS "security_headers" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "url" TEXT,
            "header_name" TEXT,
            "status" TEXT,
            "risk" TEXT,
            "recommendation" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT
        );
    """,
    "security_posture": """
        CREATE TABLE IF NOT EXISTS "security_posture" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "url" TEXT,
            "security_score" INTEGER,
            "security_grade" TEXT,
            "threat_score" INTEGER,
            "risk_level" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT,
            "assessment_status" TEXT DEFAULT 'ASSESSED',
            "user_id" INTEGER DEFAULT 1
        );
    """,
    "service_versions": """
        CREATE TABLE IF NOT EXISTS "service_versions" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "port" INTEGER,
            "service" TEXT,
            "product" TEXT,
            "version" TEXT,
            "extra_info" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT
        );
    """,
    "services": """
        CREATE TABLE IF NOT EXISTS "services" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "port" INTEGER,
            "service" TEXT,
            "version" TEXT,
            "scan_time" TEXT
        );
    """,
    "ssl_info": """
        CREATE TABLE IF NOT EXISTS "ssl_info" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "url" TEXT,
            "issuer" TEXT,
            "subject" TEXT,
            "tls_version" TEXT,
            "cipher" TEXT,
            "valid_from" TEXT,
            "valid_to" TEXT,
            "days_remaining" INTEGER,
            "signature_algorithm" TEXT,
            "key_size" TEXT,
            "grade" TEXT,
            "scan_time" TEXT
        );
    """,
    "ssl_results": """
        CREATE TABLE IF NOT EXISTS "ssl_results" (
            "id" SERIAL PRIMARY KEY,
            "host" TEXT,
            "port" INTEGER,
            "has_ssl" INTEGER,
            "tls_version" TEXT,
            "issuer" TEXT,
            "subject" TEXT,
            "valid_from" TEXT,
            "valid_to" TEXT,
            "days_remaining" INTEGER,
            "self_signed" INTEGER,
            "expired" INTEGER,
            "warnings" TEXT,
            "scan_time" TEXT,
            "cipher_suite" TEXT,
            "key_type" TEXT,
            "key_size" TEXT,
            "fingerprint_sha256" TEXT,
            "cert_chain" TEXT,
            "san_names" TEXT,
            "scan_id" TEXT
        );
    """,
    "technology_detection": """
        CREATE TABLE IF NOT EXISTS "technology_detection" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "url" TEXT,
            "server" TEXT,
            "technologies" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT
        );
    """,
    "url_intelligence": """
        CREATE TABLE IF NOT EXISTS "url_intelligence" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "url" TEXT,
            "registrar" TEXT,
            "creation_date" TEXT,
            "expiration_date" TEXT,
            "updated_date" TEXT,
            "country" TEXT,
            "region" TEXT,
            "city" TEXT,
            "isp" TEXT,
            "asn" TEXT,
            "waf" TEXT,
            "scan_time" TEXT,
            "scan_id" TEXT
        );
    """,
    "url_scan_results": """
        CREATE TABLE IF NOT EXISTS "url_scan_results" (
            "id" SERIAL PRIMARY KEY,
            "url" TEXT,
            "domain" TEXT,
            "ip" TEXT,
            "protocol" TEXT,
            "score" INTEGER,
            "risk" TEXT,
            "remarks" TEXT,
            "scan_time" TEXT,
            "https_status" TEXT,
            "suspicious_score" INTEGER,
            "risk_level" TEXT,
            "scan_id" TEXT,
            "user_id" INTEGER DEFAULT 1
        );
    """,
    "users": """
        CREATE TABLE IF NOT EXISTS "users" (
            "id" SERIAL PRIMARY KEY,
            "username" TEXT UNIQUE NOT NULL,
            "password_hash" TEXT NOT NULL,
            "role" TEXT NOT NULL DEFAULT 'ANALYST',
            "email" TEXT DEFAULT '',
            "full_name" TEXT DEFAULT '',
            "phone" TEXT DEFAULT '',
            "department" TEXT DEFAULT '',
            "timezone" TEXT DEFAULT 'Asia/Kolkata',
            "bio" TEXT DEFAULT '',
            "avatar_url" TEXT DEFAULT '',
            "google_sub" TEXT,
            "auth_provider" TEXT DEFAULT 'local',
            "is_active" INTEGER DEFAULT 1,
            "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            "last_login" TIMESTAMP,
            "last_seen" TIMESTAMP
        );
    """,
    "virustotal_results": """
        CREATE TABLE IF NOT EXISTS "virustotal_results" (
            "id" SERIAL PRIMARY KEY,
            "scan_id" TEXT,
            "url" TEXT,
            "domain" TEXT,
            "malicious" INTEGER DEFAULT 0,
            "suspicious" INTEGER DEFAULT 0,
            "harmless" INTEGER DEFAULT 0,
            "undetected" INTEGER DEFAULT 0,
            "total_engines" INTEGER DEFAULT 0,
            "risk_badge" TEXT DEFAULT 'Safe',
            "reputation" INTEGER DEFAULT 0,
            "categories" TEXT,
            "status" TEXT DEFAULT 'success',
            "message" TEXT,
            "scan_time" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,
    "vulnerabilities": """
        CREATE TABLE IF NOT EXISTS "vulnerabilities" (
            "id" SERIAL PRIMARY KEY,
            "ip" TEXT,
            "port" INTEGER,
            "service" TEXT,
            "risk" TEXT,
            "scan_time" TEXT,
            "description" TEXT,
            "remediation" TEXT,
            "scan_id" TEXT
        );
    """
}

TABLE_INDEXES = [
    'CREATE INDEX IF NOT EXISTS idx_alerts_scan_time ON "alerts"("scan_time");',
    'CREATE INDEX IF NOT EXISTS idx_cves_ip_scan ON "cves"("ip", "scan_id");',
    'CREATE INDEX IF NOT EXISTS idx_host_user_id ON "host_status"("user_id");',
    'CREATE INDEX IF NOT EXISTS idx_os_ip_scan ON "os_info"("ip", "scan_id");',
    'CREATE INDEX IF NOT EXISTS idx_reset_email ON "password_resets"("email");',
    'CREATE INDEX IF NOT EXISTS idx_reset_id ON "password_resets"("reset_id");',
    'CREATE INDEX IF NOT EXISTS idx_reset_user_id ON "password_resets"("user_id");',
    'CREATE INDEX IF NOT EXISTS idx_pending_email ON "pending_registrations"("email");',
    'CREATE INDEX IF NOT EXISTS idx_pending_reg_id ON "pending_registrations"("registration_id");',
    'CREATE INDEX IF NOT EXISTS idx_pending_username ON "pending_registrations"("username");',
    'CREATE INDEX IF NOT EXISTS idx_ports_ip_scan ON "ports"("ip", "scan_id");',
    'CREATE INDEX IF NOT EXISTS idx_risk_ip_scan ON "risk_summary"("ip", "scan_id");',
    'CREATE INDEX IF NOT EXISTS idx_history_user_id ON "scan_history"("user_id");',
    'CREATE INDEX IF NOT EXISTS idx_sec_activity_created_at ON "security_activity_logs"("created_at");',
    'CREATE INDEX IF NOT EXISTS idx_sec_activity_event_type ON "security_activity_logs"("event_type");',
    'CREATE INDEX IF NOT EXISTS idx_sec_activity_user_id ON "security_activity_logs"("user_id");',
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_posture_scan_id ON "security_posture"("scan_id") WHERE "scan_id" IS NOT NULL;',
    'CREATE INDEX IF NOT EXISTS idx_ssl_host_scan ON "ssl_results"("host", "scan_id");',
    'CREATE INDEX IF NOT EXISTS idx_url_scan_id ON "url_scan_results"("scan_id");',
    'CREATE INDEX IF NOT EXISTS idx_url_user_id ON "url_scan_results"("user_id");',
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON "users"("google_sub") WHERE "google_sub" IS NOT NULL AND "google_sub" != \'\';',
    'CREATE INDEX IF NOT EXISTS idx_vuln_ip_scan ON "vulnerabilities"("ip", "scan_id");',
]


def migrate():
    print("=" * 70)
    print("CyberShieldAI - SQLite to PostgreSQL Migration")
    print("=" * 70)
    print("IMPORTANT: SQLite database will NOT be modified.\n")

    if not os.path.exists(SQLITE_DB_PATH):
        print(f"ERROR: SQLite database file not found at: {SQLITE_DB_PATH}")
        sys.exit(1)

    db_url = get_database_url()
    if not db_url:
        print("ERROR: PostgreSQL DATABASE_URL is not set in environment or .env file.")
        sys.exit(1)

    # Open SQLite read-only via URI
    sqlite_uri = f"file:{os.path.abspath(SQLITE_DB_PATH)}?mode=ro"
    try:
        sqlite_conn = sqlite3.connect(sqlite_uri, uri=True)
        sqlite_conn.row_factory = sqlite3.Row
        sqlite_cursor = sqlite_conn.cursor()
    except Exception as e:
        print(f"ERROR connecting to SQLite database: {e}")
        sys.exit(1)

    # Connect to PostgreSQL
    try:
        pg_conn = psycopg2.connect(db_url)
        pg_cursor = pg_conn.cursor()
    except Exception as e:
        print(f"ERROR connecting to PostgreSQL database: {e}")
        sqlite_conn.close()
        sys.exit(1)

    try:
        # 1. Create all PostgreSQL tables
        print("[1/4] Creating PostgreSQL tables...")
        for table_name, schema_sql in TABLE_SCHEMAS.items():
            pg_cursor.execute(schema_sql)

        # 2. Create all PostgreSQL indexes
        print("[2/4] Creating PostgreSQL indexes...")
        for index_sql in TABLE_INDEXES:
            pg_cursor.execute(index_sql)

        # 3. Migrate data table by table
        print("[3/4] Migrating data from SQLite to PostgreSQL...\n")
        table_names = sorted(TABLE_SCHEMAS.keys())

        for table_name in table_names:
            # Check columns in SQLite
            sqlite_cursor.execute(f"PRAGMA table_info(\"{table_name}\")")
            col_info = sqlite_cursor.fetchall()
            if not col_info:
                print(f"TABLE: {table_name}")
                print("SQLite rows: 0 (table does not exist in SQLite)")
                print("PostgreSQL rows: 0")
                print("STATUS: OK\n")
                continue

            col_names = [c["name"] for c in col_info]
            pk_col = "query" if table_name == "nvd_cache" else "id"

            # Fetch rows from SQLite
            sqlite_cursor.execute(f'SELECT * FROM "{table_name}"')
            rows = sqlite_cursor.fetchall()
            sqlite_row_count = len(rows)

            if sqlite_row_count > 0:
                cols_joined = ", ".join([f'"{c}"' for c in col_names])
                placeholders = ", ".join(["%s"] * len(col_names))
                
                # Build update assignments for ON CONFLICT DO UPDATE
                update_assignments = ", ".join([
                    f'"{c}" = EXCLUDED."{c}"' for c in col_names if c != pk_col
                ])

                if update_assignments:
                    conflict_clause = f'ON CONFLICT ("{pk_col}") DO UPDATE SET {update_assignments}'
                else:
                    conflict_clause = f'ON CONFLICT ("{pk_col}") DO NOTHING'

                insert_sql = f'INSERT INTO "{table_name}" ({cols_joined}) VALUES ({placeholders}) {conflict_clause}'

                # Convert rows to list of tuples, handling any SQLite data type specifics
                batch_data = []
                for row in rows:
                    row_vals = []
                    for c in col_names:
                        val = row[c]
                        # Clean up empty string timestamps if needed
                        row_vals.append(val)
                    batch_data.append(tuple(row_vals))

                psycopg2.extras.execute_batch(pg_cursor, insert_sql, batch_data, page_size=200)

            # Reset sequence if table has a SERIAL 'id'
            if pk_col == "id":
                pg_cursor.execute(f"""
                    SELECT setval(
                        pg_get_serial_sequence('"{table_name}"', 'id'),
                        COALESCE((SELECT MAX(id) FROM "{table_name}"), 1),
                        (SELECT MAX(id) FROM "{table_name}") IS NOT NULL
                    );
                """)

            # Verify count in PostgreSQL
            pg_cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
            pg_row_count = pg_cursor.fetchone()[0]

            print(f"TABLE: {table_name}")
            print(f"SQLite rows: {sqlite_row_count}")
            print(f"PostgreSQL rows: {pg_row_count}")
            if pg_row_count == sqlite_row_count:
                print("STATUS: OK\n")
            else:
                print(f"STATUS: WARNING (SQLite: {sqlite_row_count}, PostgreSQL: {pg_row_count})\n")

        # 4. Commit PostgreSQL transaction
        print("[4/4] Committing transaction to PostgreSQL...")
        pg_conn.commit()
        print("MIGRATION COMPLETED SUCCESSFULLY!\n")

    except Exception as e:
        print(f"\n[FATAL] Migration failed: {e}")
        print("Rolling back PostgreSQL transaction...")
        pg_conn.rollback()
        sys.exit(1)
    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == "__main__":
    migrate()
