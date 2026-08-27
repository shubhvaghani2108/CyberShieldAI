import sqlite3
import os

# ==========================================================
# Database Path
# ==========================================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

# ==========================================================
# Database Connection
# ==========================================================

def run_init():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS technology_detection(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        url TEXT,
        server TEXT,
        technologies TEXT,
        scan_time TEXT
    )
    """)
    print("[OK] technology_detection table created successfully.")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_headers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        url TEXT,
        header_name TEXT,
        status TEXT,
        risk TEXT,
        recommendation TEXT,
        scan_time TEXT
    )
    """)
    print("[OK] security_headers table created successfully.")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ssl_results (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id            TEXT,
        host               TEXT,
        port               INTEGER,
        has_ssl            INTEGER,
        tls_version        TEXT,
        cipher_suite       TEXT,
        key_type           TEXT,
        key_size           TEXT,
        fingerprint_sha256 TEXT,
        cert_chain         TEXT,
        san_names          TEXT,
        issuer             TEXT,
        subject            TEXT,
        valid_from         TEXT,
        valid_to           TEXT,
        days_remaining     INTEGER,
        self_signed        INTEGER,
        expired            INTEGER,
        warnings           TEXT,
        scan_time          TEXT
    )
    """)
    print("[OK] ssl_results table created successfully.")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_intelligence(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        url TEXT,
        registrar TEXT,
        creation_date TEXT,
        expiration_date TEXT,
        updated_date TEXT,
        country TEXT,
        region TEXT,
        city TEXT,
        isp TEXT,
        asn TEXT,
        waf TEXT,
        scan_time TEXT
    )
    """)
    print("[OK] url_intelligence table created successfully.")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        target TEXT,
        alert_type TEXT,
        severity TEXT,
        message TEXT,
        created_at TEXT,
        ip TEXT,
        title TEXT,
        description TEXT,
        recommendation TEXT,
        scan_time TEXT
    )
    """)
    print("[OK] alerts table created successfully.")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_posture(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        url TEXT,
        security_score INTEGER,
        security_grade TEXT,
        threat_score INTEGER,
        risk_level TEXT,
        assessment_status TEXT DEFAULT 'ASSESSED',
        scan_time TEXT
    )
    """)
    cursor.execute("PRAGMA table_info(security_posture)")
    cols = [r[1] for r in cursor.fetchall()]
    if "assessment_status" not in cols:
        cursor.execute("ALTER TABLE security_posture ADD COLUMN assessment_status TEXT DEFAULT 'ASSESSED'")
    if "scan_id" not in cols:
        cursor.execute("ALTER TABLE security_posture ADD COLUMN scan_id TEXT")
    print("[OK] security_posture table created successfully.")

    conn.commit()
    conn.close()

    try:
        from database.db_helpers import migrate_db_add_scan_id
        migrate_db_add_scan_id()
    except Exception as e:
        print("[MIGRATION NOTICE]", e)

    print("[OK] Database initialized successfully.")

if __name__ == "__main__":
    run_init()