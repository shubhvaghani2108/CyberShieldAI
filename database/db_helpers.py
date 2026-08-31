from dns.rdtypes.ANY import ISDN
import json
import os
import sqlite3
import sys
from collections import Counter

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.assets import get_assets
from database.dashboard_stats import get_dashboard_stats
from database.ssl_results import get_latest_ssl
from scanner.recommendation_engine import generate_recommendations

def _resolve_db_path():
    if os.environ.get("CYBERSHIELD_DB_PATH"):
        return os.environ.get("CYBERSHIELD_DB_PATH")
    if os.environ.get("VERCEL"):
        tmp_db = os.path.join("/tmp", "cybershield.db")
        local_db = os.path.join(BASE_DIR, "cybershield.db")
        if not os.path.exists(tmp_db) and os.path.exists(local_db):
            import shutil
            try:
                shutil.copyfile(local_db, tmp_db)
            except Exception:
                pass
        return tmp_db
    return os.path.join(BASE_DIR, "cybershield.db")


DB_PATH = _resolve_db_path()


def get_db_connection():
    conn = sqlite3.connect(_resolve_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # PORTS
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            state TEXT,
            service TEXT,
            banner TEXT,
            scan_time TEXT
        )
    """
    )

    # VULNERABILITIES
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            service TEXT,
            risk TEXT,
            description TEXT,
            remediation TEXT,
            scan_time TEXT
        )
    """
    )

    # CVES
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    """
    )

    # SCHEMA MIGRATION
    migrations = [
        ("scan_history", "status", "TEXT"),
        ("scan_history", "scan_time", "TEXT"),
        ("ports", "banner", "TEXT"),
        ("ports", "scan_time", "TEXT"),
        ("vulnerabilities", "description", "TEXT"),
        ("vulnerabilities", "remediation", "TEXT"),
        ("vulnerabilities", "scan_time", "TEXT"),
        ("cves", "cvss_score", "REAL"),
        ("cves", "cvss_vector", "TEXT"),
        ("cves", "cwe_id", "TEXT"),
        ("cves", "cwe_name", "TEXT"),
        ("cves", "ref_links", "TEXT"),
        ("cves", "published_date", "TEXT"),
        ("cves", "exploit_available", "INTEGER"),
        ("cves", "scan_time", "TEXT"),
        ("url_scan_results", "score", "INTEGER"),
        ("url_scan_results", "risk", "TEXT"),
        ("url_scan_results", "protocol", "TEXT"),
        ("url_scan_results", "https_status", "TEXT"),
        ("url_scan_results", "suspicious_score", "INTEGER"),
        ("url_scan_results", "risk_level", "TEXT"),
    ]
    for table, column, col_type in migrations:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
        except sqlite3.OperationalError:
            pass  # column already exists — fine

    # RISK SUMMARY
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            total_score INTEGER,
            risk_level TEXT,
            scan_time TEXT
        )
    """
    )

    # IP SCAN HISTORY
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            status TEXT,
            scan_time TEXT
        )
    """
    )

    # HOST STATUS
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS host_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            status TEXT,
            scan_time TEXT
        )
    """
    )

    # URL SCAN HISTORY
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS url_scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            ip TEXT,
            protocol TEXT,
            score INTEGER,
            risk TEXT,
            remarks TEXT,
            scan_time TEXT
        )
    """
    )

    # OS INFO
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS os_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            os_name TEXT,
            device_type TEXT,
            os_details TEXT,
            scan_time TEXT
        )
    """
    )

    # SERVICE VERSIONS
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS service_versions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT,
            port       INTEGER,
            service    TEXT,
            product    TEXT,
            version    TEXT,
            extra_info TEXT,
            scan_time  TEXT
        )
    """
    )

    # TECHNOLOGY DETECTION
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS technology_detection (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT,
            url          TEXT,
            server       TEXT,
            technologies TEXT,
            scan_time    TEXT
        )
    """
    )

    # URL INTELLIGENCE
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS url_intelligence (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip              TEXT,
            url             TEXT,
            registrar       TEXT,
            creation_date   TEXT,
            expiration_date TEXT,
            updated_date    TEXT,
            country         TEXT,
            region          TEXT,
            city            TEXT,
            isp             TEXT,
            asn             TEXT,
            waf             TEXT,
            scan_time       TEXT
        )
        """
    )
    # SECURITY POSTURE
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_posture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE,
            ip TEXT,
            url TEXT,
            security_score INTEGER,
            security_grade TEXT,
            threat_score INTEGER,
            risk_level TEXT,
            scan_time TEXT
        )
    """
    )

    # MONITORED TARGETS & MONITORING LOGS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitored_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT UNIQUE,
            scan_frequency INTEGER DEFAULT 24,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitoring_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            status TEXT,
            score INTEGER,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
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

    # USERS TABLE (LOCAL AUTHENTICATION)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'ANALYST',
            email TEXT DEFAULT '',
            full_name TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            google_sub TEXT,
            auth_provider TEXT DEFAULT 'local',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            last_seen TIMESTAMP
        )
    """)

    # Auto-seed authentic user accounts if database is fresh
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        from werkzeug.security import generate_password_hash
        default_pass = generate_password_hash("Admin@1234")
        cursor.executemany("""
            INSERT OR IGNORE INTO users (id, username, password_hash, role, email, full_name, auth_provider, is_active, created_at, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, [
            (1, "admin", default_pass, "ADMIN", "admin@cybershield.ai", "Shubh Vaghani (SOC Admin)", "local"),
            (2, "23se02cb016", default_pass, "ADMIN", "23se02cb016@ppsu.ac.in", "Shubh Vaghani", "google"),
            (3, "defenderr0809", default_pass, "ANALYST", "defenderr0809@gmail.com", "Security Lead Defender", "google"),
            (4, "shubhvaghani21", default_pass, "VIEWER", "shubhvaghani21@gmail.com", "Shubh Vaghani", "google")
        ])

    conn.commit()
    conn.close()

    try:
        from database.otp_helpers import init_otp_table
        init_otp_table()
    except Exception:
        pass

    migrate_db_add_scan_id()


def migrate_db_add_scan_id():
    """
    Ensures scan_id TEXT column exists on all scan output tables.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    tables = [
        "url_scan_results",
        "security_posture",
        "ports",
        "service_versions",
        "security_headers",
        "ssl_results",
        "technology_detection",
        "vulnerabilities",
        "cves",
        "url_intelligence",
        "os_info",
        "risk_summary",
        "scan_history",
        "host_status",
        "virustotal_results",
        "alerts",
    ]

    for table in tables:
        try:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [row[1] for row in cursor.fetchall()]
            if columns and "scan_id" not in columns:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN scan_id TEXT")
                print(f"[MIGRATION] Added scan_id TEXT to {table}")
        except Exception as e:
            print(f"[MIGRATION] Warning migration {table}: {e}")

    indexes = [
        ("idx_posture_scan_id", "security_posture", "scan_id"),
        ("idx_ports_ip_scan", "ports", "ip, scan_id"),
        ("idx_vuln_ip_scan", "vulnerabilities", "ip, scan_id"),
        ("idx_cves_ip_scan", "cves", "ip, scan_id"),
        ("idx_risk_ip_scan", "risk_summary", "ip, scan_id"),
        ("idx_os_ip_scan", "os_info", "ip, scan_id"),
        ("idx_ssl_host_scan", "ssl_results", "host, scan_id"),
        ("idx_url_scan_id", "url_scan_results", "scan_id"),
        ("idx_alerts_scan_time", "alerts", "scan_time"),
    ]
    for idx_name, tbl, cols in indexes:
        try:
            cursor.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {tbl}({cols})")
        except Exception as e:
            print(f"[MIGRATION] Index {idx_name}: {e}")

    conn.commit()
    conn.close()


def get_latest_ip():
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT target_ip
        FROM scan_history
        ORDER BY id DESC
        LIMIT 1
    """
    ).fetchone()
    if not row:
        row = conn.execute(
            """
            SELECT target_ip
            FROM host_status
            ORDER BY id DESC
            LIMIT 1
        """
        ).fetchone()
    conn.close()
    return row["target_ip"] if row else None


def get_latest_host_status():
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT target_ip, status, scan_time
        FROM host_status
        ORDER BY id DESC
        LIMIT 1
    """
    ).fetchone()
    conn.close()
    return row


def get_latest_url_scan():
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT *
        FROM url_scan_results
        ORDER BY id DESC
        LIMIT 1
    """
    ).fetchone()
    conn.close()
    return row


def get_latest_risk(ip, scan_id=None):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    if scan_id:
        row = conn.execute(
            """
            SELECT *
            FROM risk_summary
            WHERE ip=? AND scan_id=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (ip, scan_id),
        ).fetchone()
        if not row:
            row = conn.execute(
                """
                SELECT *
                FROM risk_summary
                WHERE ip=?
                ORDER BY id DESC
                LIMIT 1
                """,
                (ip,),
            ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT *
            FROM risk_summary
            WHERE ip=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()

    conn.close()
    return row


def get_latest_ssl(target):
    from database.ssl_results import get_latest_ssl as _get_latest_ssl
    return _get_latest_ssl(target)


def get_ports(ip, scan_id=None):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM ports WHERE ip=? AND scan_id=? ORDER BY port ASC",
                (ip, scan_id),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM ports 
                WHERE id IN (
                    SELECT MAX(id) FROM ports WHERE ip = ? GROUP BY port
                )
                ORDER BY port ASC
                """,
                (ip,),
            ).fetchall()
        return rows
    finally:
        conn.close()


def get_security_headers(ip, scan_id=None):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM security_headers WHERE ip=? AND scan_id=? ORDER BY id ASC",
                (ip, scan_id),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM security_headers 
                WHERE id IN (
                    SELECT MAX(id) FROM security_headers WHERE ip = ? GROUP BY header_name
                )
                ORDER BY id ASC
                """,
                (ip,),
            ).fetchall()
        return rows
    finally:
        conn.close()


def get_vulnerabilities(ip, scan_id=None):
    """Retrieves vulnerability records for an IP or scan session without duplicates."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM vulnerabilities WHERE (ip=? OR target=?) AND scan_id=? ORDER BY port ASC",
                (ip, ip, scan_id),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM vulnerabilities 
                WHERE id IN (
                    SELECT MAX(id) FROM vulnerabilities WHERE ip = ? GROUP BY port, risk, service
                )
                ORDER BY
                    CASE LOWER(risk)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    port ASC
                """,
                (ip,),
            ).fetchall()
        return rows
    except Exception:
        try:
            return conn.execute("SELECT * FROM vulnerabilities WHERE ip=? ORDER BY id DESC", (ip,)).fetchall()
        except Exception:
            return []
    finally:
        conn.close()


def get_cves(ip, scan_id=None):
    """Retrieves CVE records for an IP or scan session without duplicates."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    try:
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM cves WHERE ip=? AND scan_id=? ORDER BY port ASC",
                (ip, scan_id),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM cves 
                WHERE id IN (
                    SELECT MAX(id) FROM cves WHERE ip = ? GROUP BY cve_id, port
                )
                ORDER BY
                    CASE LOWER(severity)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    port ASC
                """,
                (ip,),
            ).fetchall()
        return rows
    except Exception:
        return []
    finally:
        conn.close()


def get_latest_technology(ip=None, url=None):

    """Latest technology-fingerprint row, preferring an exact URL match."""
    conn = get_db_connection()
    row = None
    if url:
        row = conn.execute(
            "SELECT * FROM technology_detection WHERE url=? ORDER BY id DESC LIMIT 1",
            (url,),
        ).fetchone()
    if not row and ip:
        row = conn.execute(
            "SELECT * FROM technology_detection WHERE ip=? ORDER BY id DESC LIMIT 1",
            (ip,),
        ).fetchone()
    conn.close()
    return row


def get_latest_url_intelligence(ip=None, url=None):
    """Latest WHOIS / GeoIP / WAF intelligence row for a scanned URL."""
    conn = get_db_connection()
    row = None
    if url:
        row = conn.execute(
            "SELECT * FROM url_intelligence WHERE url=? ORDER BY id DESC LIMIT 1",
            (url,),
        ).fetchone()
    if not row and ip:
        row = conn.execute(
            "SELECT * FROM url_intelligence WHERE ip=? ORDER BY id DESC LIMIT 1",
            (ip,),
        ).fetchone()
    conn.close()
    return row


def get_url_scan_dashboard_context():
    """Bundles the latest URL scan together with its SSL, technology and
    WHOIS/GeoIP intelligence so the complete URL scan output can be shown
    directly on the main dashboard."""
    url_scan = get_latest_url_scan()

    if not url_scan:
        return {
            "url_scan": None,
            "url_remarks": [],
            "url_ssl": None,
            "url_tech": None,
            "url_tech_list": [],
            "url_intel": None,
        }

    remarks = []
    if url_scan["remarks"]:
        remarks = [r.strip() for r in str(url_scan["remarks"]).split("|") if r.strip()]

    url_ssl = get_latest_ssl(url_scan["domain"]) if url_scan["domain"] else None
    url_tech = get_latest_technology(ip=url_scan["ip"], url=url_scan["url"])

    tech_list = []
    tech_server = None
    if url_tech and url_tech["technologies"]:
        try:
            parsed = json.loads(url_tech["technologies"])
            if isinstance(parsed, dict):
                tech_list = parsed.get("technologies", []) or []
                tech_server = parsed.get("server")
            elif isinstance(parsed, list):
                tech_list = parsed
        except (TypeError, ValueError):
            tech_list = [
                t.strip() for t in str(url_tech["technologies"]).split(",") if t.strip()
            ]
    if not tech_server and url_tech is not None:
        try:
            tech_server = url_tech["server"]
        except (IndexError, KeyError):
            tech_server = None

    url_intel = get_latest_url_intelligence(ip=url_scan["ip"], url=url_scan["url"])

    return {
        "url_scan": url_scan,
        "url_remarks": remarks,
        "url_ssl": url_ssl,
        "url_tech": url_tech,
        "url_tech_server": tech_server,
        "url_tech_list": tech_list,
        "url_intel": url_intel,
    }


def get_dashboard_data():
    conn = get_db_connection()

    latest_ip = get_latest_ip()
    latest_host = get_latest_host_status()

    ports_count = 0
    vulns_count = 0
    cves_count = 0
    risk_score = 0
    risk_level = "Low"

    host_ip = "-"
    host_status = "No Scan Yet"
    host_scan_time = "-"

    if latest_host:
        host_ip = latest_host["target_ip"]
        host_status = latest_host["status"]
        host_scan_time = latest_host["scan_time"]

    if latest_ip:
        row = conn.execute(
            """
            SELECT COUNT(DISTINCT port) AS cnt
            FROM ports
            WHERE ip = ?
        """,
            (latest_ip,),
        ).fetchone()
        ports_count = row["cnt"] if row else 0

        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM vulnerabilities
            WHERE id IN (
                SELECT MAX(id) FROM vulnerabilities WHERE ip = ? GROUP BY port, risk, service
            )
        """,
            (latest_ip,),
        ).fetchone()
        vulns_count = row["cnt"] if row else 0

        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM cves
            WHERE id IN (
                SELECT MAX(id) FROM cves WHERE ip = ? GROUP BY cve_id, port
            )
        """,
            (latest_ip,),
        ).fetchone()
        cves_count = row["cnt"] if row else 0

        row = conn.execute(
            """
            SELECT total_score, risk_level
            FROM risk_summary
            WHERE ip = ?
            ORDER BY id DESC
            LIMIT 1
        """,
            (latest_ip,),
        ).fetchone()

        if row:
            risk_score = row["total_score"]
            risk_level = row["risk_level"]

    conn.close()

    return {
        "ports": ports_count,
        "vulns": vulns_count,
        "cves": cves_count,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "host_ip": host_ip,
        "host_status": host_status,
        "host_scan_time": host_scan_time,
    }


def get_recent_activity(limit=8, latest_ip=None):
    """Most recently scanned hosts, newest first, for the dashboard feed.
    If latest_ip is specified, scopes activity feed to the current target."""
    conn = get_db_connection()
    if latest_ip:
        rows = conn.execute(
            """
            SELECT target_ip, status, scan_time
            FROM host_status
            WHERE target_ip = ?
            ORDER BY id DESC
            LIMIT ?
        """,
            (latest_ip, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT target_ip, status, scan_time
            FROM host_status
            ORDER BY id DESC
            LIMIT ?
        """,
            (limit,),
        ).fetchall()
    conn.close()
    return rows


def get_risk_trend(limit=8, latest_ip=None):
    """Most recent risk scores from both IP scans and URL scans, oldest -> newest, for the trend chart."""
    conn = get_db_connection()
    combined = []

    # Fetch recent IP scan risk summaries
    try:
        if latest_ip:
            ip_rows = conn.execute(
                """
                SELECT ip AS target, total_score AS score, scan_time
                FROM risk_summary
                WHERE ip = ? AND total_score IS NOT NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (latest_ip, limit),
            ).fetchall()
        else:
            ip_rows = conn.execute(
                """
                SELECT ip AS target, total_score AS score, scan_time
                FROM risk_summary
                WHERE total_score IS NOT NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        for r in ip_rows:
            combined.append({
                "target": r["target"],
                "score": r["score"] if r["score"] is not None else 0,
                "scan_time": str(r["scan_time"]) if r["scan_time"] else ""
            })
    except Exception:
        pass

    # Fetch recent URL scan results
    try:
        url_rows = conn.execute(
            """
            SELECT domain AS target, score, scan_time
            FROM url_scan_results
            WHERE score IS NOT NULL
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        for r in url_rows:
            combined.append({
                "target": r["target"],
                "score": r["score"] if r["score"] is not None else 0,
                "scan_time": str(r["scan_time"]) if r["scan_time"] else ""
            })
    except Exception:
        pass

    conn.close()

    # Sort all entries by scan_time ascending
    combined.sort(key=lambda x: x["scan_time"] if x["scan_time"] else "")

    # Take the latest `limit` entries
    recent_entries = combined[-limit:] if len(combined) > limit else combined

    trend = []
    for r in recent_entries:
        label = r["scan_time"] or r["target"]
        if label and " " in str(label):
            label = str(label).split(" ")[-1]
        trend.append({"label": label, "score": r["score"] if r["score"] is not None else 0})

    return trend


def get_ip_scan_context():
    """Gathers everything about the latest IP/host scan into one dict."""
    data = get_dashboard_data()
    conn = get_db_connection()
    latest_ip = get_latest_ip()

    # Host
    host = conn.execute(
        """
        SELECT *
        FROM host_status
        ORDER BY id DESC
        LIMIT 1
    """
    ).fetchone()

    # Ports
    if latest_ip:
        ports = conn.execute(
            """
            SELECT *
            FROM ports
            WHERE id IN (
                SELECT MAX(id) FROM ports WHERE ip=? GROUP BY port
            )
            ORDER BY port ASC
        """,
            (latest_ip,),
        ).fetchall()
    else:
        ports = []

    # Services
    if latest_ip:
        services = conn.execute(
            """
            SELECT *
            FROM service_versions
            WHERE id IN (
                SELECT MAX(id) FROM service_versions WHERE ip=? GROUP BY port
            )
            ORDER BY port ASC
        """,
            (latest_ip,),
        ).fetchall()
    else:
        services = []

    # Vulnerabilities
    if latest_ip:
        vulnerabilities = conn.execute(
            """
            SELECT *
            FROM vulnerabilities
            WHERE id IN (
                SELECT MAX(id) FROM vulnerabilities WHERE ip=? GROUP BY port, risk, service
            )
            ORDER BY
                CASE LOWER(risk)
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END,
                port ASC
        """,
            (latest_ip,),
        ).fetchall()
    else:
        vulnerabilities = []

    # CVEs
    if latest_ip:
        cves = conn.execute(
            """
            SELECT *
            FROM cves
            WHERE id IN (
                SELECT MAX(id) FROM cves WHERE ip=? GROUP BY cve_id, port
            )
            ORDER BY
                CASE LOWER(severity)
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END,
                port ASC
        """,
            (latest_ip,),
        ).fetchall()
    else:
        cves = []

    # OS
    if latest_ip:
        os_row = conn.execute(
            """
            SELECT *
            FROM os_info
            WHERE ip=?
            ORDER BY id DESC
            LIMIT 1
        """,
            (latest_ip,),
        ).fetchone()
    else:
        os_row = None

    if os_row:
        os_info = {
            "os_name": os_row["os_name"],
            "device_type": os_row["device_type"],
            "os_details": os_row["os_details"],
        }
    else:
        os_info = {"os_name": "Not Scanned", "device_type": "-", "os_details": "-"}

    # Risk
    if latest_ip:
        risk = conn.execute(
            """
            SELECT *
            FROM risk_summary
            WHERE ip=?
            ORDER BY id DESC
            LIMIT 1
        """,
            (latest_ip,),
        ).fetchone()
    else:
        risk = None
    conn.close()

    # Recommendations
    if latest_ip:
        try:
            recommendations = generate_recommendations(
                ports, services, os_info, vulnerabilities
            )
        except Exception:
            recommendations = []
    else:
        recommendations = []

    data["latest_ip"] = latest_ip
    data["host"] = host
    data["ports_data"] = ports
    data["services"] = services
    data["vulnerabilities_data"] = vulnerabilities
    data["cves_data"] = cves
    data["os_info"] = os_info
    data["risk"] = risk
    data["recommendations"] = recommendations

    data["port_count"] = len(ports)
    data["service_count"] = len(services)
    data["vulnerability_count"] = len(vulnerabilities)
    data["cve_count"] = len(cves)

    if risk:
        score = max(0, 100 - risk["total_score"])
        data["security_score"] = score
    else:
        data["security_score"] = 100

    # Dashboard Stats
    stats = get_dashboard_stats(latest_ip)
    assets = get_assets(latest_ip=latest_ip, latest_only=True)
    recent_activity = get_recent_activity(limit=1, latest_ip=latest_ip)

    if risk:
        severity = {
            "critical": risk["critical_count"] or 0,
            "high": risk["high_count"] or 0,
            "medium": risk["medium_count"] or 0,
            "low": risk["low_count"] or 0,
        }
    else:
        severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    service_counts = Counter(
        (p["service"] or "unknown") for p in ports if p["state"] == "open"
    )
    port_distribution = [
        {"label": svc, "count": cnt} for svc, cnt in service_counts.most_common(8)
    ]

    chart_data = {
        "severity": severity,
        "port_distribution": port_distribution,
        "risk_trend": get_risk_trend(limit=8, latest_ip=latest_ip),
    }

    data["stats"] = stats
    data["assets"] = assets
    data["recent_activity"] = recent_activity
    data["chart_data"] = chart_data

    return data
