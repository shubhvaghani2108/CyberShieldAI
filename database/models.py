from database.db_engine import get_db_connection

def create_models():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode=WAL")

    # PORTS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        port INTEGER,
        state TEXT,
        service TEXT,
        banner TEXT,
        scan_time TEXT
    )
    """)

    # VULNERABILITIES TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        port INTEGER,
        service TEXT,
        risk TEXT,
        description TEXT,
        remediation TEXT,
        scan_time TEXT
    )
    """)

    # CVES TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        port INTEGER,
        service TEXT,
        cve_id TEXT,
        severity TEXT,
        description TEXT,
        cvss_score REAL,
        cvss_vector TEXT,
        cwe_id TEXT,
        cwe_name TEXT,
        ref_links TEXT,
        published_date TEXT,
        exploit_available INTEGER,
        scan_time TEXT
    )
    """)

    # SCAN HISTORY TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        target_ip TEXT,
        status TEXT,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # RISK SUMMARY TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_summary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        total_score INTEGER DEFAULT 0,
        risk_level TEXT,
        scan_time TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        url TEXT,
        domain TEXT,
        ip TEXT,
        protocol TEXT,
        https_status TEXT,
        suspicious_score INTEGER,
        risk_level TEXT,
        remarks TEXT,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # SERVICE VERSIONS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS service_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        port INTEGER,
        service TEXT,
        product TEXT,
        version TEXT,
        extra_info TEXT,
        scan_time TEXT
    )
    """)

    # OS INFO TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS os_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        os_name TEXT,
        device_type TEXT,
        os_details TEXT,
        scan_time TEXT
    )
    """)

    # HOST STATUS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS host_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        target_ip TEXT,
        status TEXT,
        scan_time TEXT
    )
    """)

    # SSL RESULTS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ssl_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        host TEXT,
        port INTEGER,
        has_ssl INTEGER,
        tls_version TEXT,
        cipher_suite TEXT,
        key_type TEXT,
        key_size TEXT,
        fingerprint_sha256 TEXT,
        cert_chain TEXT,
        san_names TEXT,
        issuer TEXT,
        subject TEXT,
        valid_from TEXT,
        valid_to TEXT,
        days_remaining INTEGER,
        self_signed INTEGER,
        expired INTEGER,
        warnings TEXT,
        scan_time TEXT
    )
    """)

    # SECURITY HEADERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_headers (
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

    # TECHNOLOGY DETECTION TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS technology_detection (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        ip TEXT,
        url TEXT,
        server TEXT,
        technologies TEXT,
        scan_time TEXT
    )
    """)

    # URL INTELLIGENCE TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_intelligence (
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

    # SECURITY POSTURE TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_posture (
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

    # ALERTS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
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

    # VIRUSTOTAL RESULTS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS virustotal_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        target TEXT,
        target_type TEXT,
        malicious INTEGER DEFAULT 0,
        suspicious INTEGER DEFAULT 0,
        harmless INTEGER DEFAULT 0,
        undetected INTEGER DEFAULT 0,
        reputation INTEGER DEFAULT 0,
        risk_score INTEGER DEFAULT 0,
        scan_time TEXT
    )
    """)

    # EMAIL SETTINGS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        smtp_server TEXT DEFAULT '',
        smtp_port INTEGER DEFAULT 587,
        smtp_user TEXT DEFAULT '',
        smtp_password TEXT DEFAULT '',
        from_email TEXT DEFAULT '',
        recipient_email TEXT DEFAULT '',
        use_tls INTEGER DEFAULT 1,
        use_ssl INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 0,
        alert_score_drop INTEGER DEFAULT 1,
        alert_new_vuln INTEGER DEFAULT 1,
        alert_critical INTEGER DEFAULT 1,
        alert_ssl_expiry INTEGER DEFAULT 1,
        alert_new_port INTEGER DEFAULT 1,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # MONITORED TARGETS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS monitored_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT UNIQUE,
        scan_frequency INTEGER DEFAULT 24,
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # USERS TABLE (LOCAL AUTHENTICATION)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'ANALYST',
        email TEXT DEFAULT '',
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

    try:
        from database.db_helpers import migrate_db_add_scan_id
        migrate_db_add_scan_id()
    except Exception as e:
        print("[MIGRATION NOTICE]", e)

    print("[OK] Database Models Initialized Successfully")

if __name__ == "__main__":
    create_models()