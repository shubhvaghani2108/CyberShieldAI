import os
import sqlite3
import tempfile
import uuid
import pytest

from database.db_helpers import (
    init_db,
    get_db_connection,
    migrate_db_add_scan_id,
    get_ports,
    get_latest_risk,
)
from database.models import create_models
from database.ssl_results import save_ssl, get_latest_ssl
from analytics.trend_analytics import (
    get_security_score_trend,
    get_alert_trend,
    get_vulnerability_trend,
    get_risk_distribution,
    get_all_trend_analytics,
)


@pytest.fixture(autouse=True)
def cleanup_test_database():
    yield
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = OFF")
    for t in [
        "ports", "vulnerabilities", "cves", "risk_summary", "host_status",
        "url_scan_results", "os_detection", "os_info", "service_versions",
        "services", "technology_detection", "security_headers", "ssl_info",
        "ssl_results", "url_intelligence", "nvd_cache", "alerts",
        "scan_history", "security_posture", "monitored_targets",
        "monitoring_logs", "virustotal_results"
    ]:
        try:
            cur.execute(f"DELETE FROM {t}")
            cur.execute("DELETE FROM sqlite_sequence WHERE name=?", (t,))
        except Exception:
            pass
    conn.commit()
    conn.close()


def test_fresh_database_models_creation(tmp_path):
    """Verify create_models initializes all required tables with scan_id in a fresh database."""
    test_db_file = str(tmp_path / "test_fresh.db")
    
    # Run creation on temporary db
    conn = sqlite3.connect(test_db_file)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    import database.models as models_module
    orig_db_path = models_module.DB_PATH
    try:
        models_module.DB_PATH = test_db_file
        models_module.create_models()
        
        # Verify required tables exist
        required_tables = [
            "ports",
            "service_versions",
            "vulnerabilities",
            "cves",
            "os_info",
            "risk_summary",
            "scan_history",
            "host_status",
            "url_scan_results",
            "ssl_results",
            "security_headers",
            "technology_detection",
            "url_intelligence",
            "security_posture",
            "alerts",
            "virustotal_results",
            "email_settings",
            "monitored_targets",
        ]
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        created_tables = {row["name"] for row in cursor.fetchall()}
        
        for t in required_tables:
            assert t in created_tables, f"Table '{t}' missing from create_models"
            
            # Check scan_id column on scan-related tables
            if t not in ["email_settings", "monitored_targets"]:
                cursor.execute(f"PRAGMA table_info({t})")
                cols = [r["name"] for r in cursor.fetchall()]
                assert "scan_id" in cols, f"scan_id column missing from table '{t}'"
    finally:
        models_module.DB_PATH = orig_db_path
        conn.close()


def test_migration_idempotency_and_safety():
    """Verify that running migrate_db_add_scan_id multiple times is completely idempotent and safe."""
    # 1st run
    migrate_db_add_scan_id()
    
    # Insert test record
    test_scan_id = uuid.uuid4().hex
    test_ip = f"10.210.{uuid.uuid4().hex[:6]}"
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO ports (scan_id, ip, port, state, service, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
        (test_scan_id, test_ip, 8080, "open", "http-proxy", "2026-08-24 12:00:00")
    )
    conn.commit()
    conn.close()

    # 2nd run
    migrate_db_add_scan_id()

    # 3rd run
    migrate_db_add_scan_id()

    # Verify existing record was untouched
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM ports WHERE ip = ? AND scan_id = ?", (test_ip, test_scan_id)).fetchone()
    assert row is not None
    assert row["port"] == 8080
    assert row["scan_id"] == test_scan_id
    conn.close()


def test_ssl_results_table_consistency():
    """Verify ssl_results table saves and retrieves SSL certificates without creating parallel tables."""
    test_host = f"ssl-test-{uuid.uuid4().hex[:6]}.example.com"
    test_scan_id = uuid.uuid4().hex

    ssl_data = {
        "host": test_host,
        "port": 443,
        "has_ssl": True,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "key_type": "RSA",
        "key_size": "2048 bit",
        "fingerprint_sha256": "AA:BB:CC:DD:EE",
        "san_names": [test_host, f"www.{test_host}"],
        "issuer": "DigiCert Inc",
        "subject": test_host,
        "valid_from": "2026-01-01 00:00:00",
        "valid_to": "2027-01-01 00:00:00",
        "days_remaining": 365,
        "self_signed": False,
        "expired": False,
        "warnings": [],
    }

    save_ssl(ssl_data, scan_id=test_scan_id)

    res = get_latest_ssl(test_host)
    assert res is not None
    assert res["host"] == test_host
    assert res["scan_id"] == test_scan_id
    assert res["tls_version"] == "TLSv1.3"
    assert res["days_remaining"] == 365
    assert test_host in res["parsed_san_names"]


def test_os_info_table_consistency():
    """Verify os_info records are saved and queried correctly with scan_id."""
    test_ip = f"10.220.{uuid.uuid4().hex[:6]}"
    test_scan_id = uuid.uuid4().hex

    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO os_info (scan_id, ip, os_name, device_type, os_details, scan_time)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (test_scan_id, test_ip, "Ubuntu 22.04 LTS", "General Purpose", "Linux 5.15 (98%)", "2026-08-24 12:00:00")
    )
    conn.commit()

    row = conn.execute("SELECT * FROM os_info WHERE ip = ? ORDER BY id DESC LIMIT 1", (test_ip,)).fetchone()
    assert row is not None
    assert row["os_name"] == "Ubuntu 22.04 LTS"
    assert row["device_type"] == "General Purpose"
    assert row["scan_id"] == test_scan_id
    conn.close()


def test_trend_analytics_sql_queries():
    """Verify that all trend analytics aggregation queries run successfully without column errors."""
    trends = get_all_trend_analytics(limit=10)
    assert "security_score_trend" in trends
    assert "alert_trend" in trends
    assert "vulnerability_trend" in trends
    assert "risk_distribution" in trends

    assert isinstance(trends["security_score_trend"]["scores"], list)
    assert isinstance(trends["alert_trend"]["critical"], list)
    assert isinstance(trends["vulnerability_trend"]["labels"], list)
    assert isinstance(trends["risk_distribution"]["counts"], list)


def test_risk_summary_supports_multi_scan_history():
    """Verify risk_summary supports multiple scan_id records for the same target IP without collisions."""
    target_ip = f"10.230.{uuid.uuid4().hex[:6]}"
    scan_1 = f"SCAN_1_{uuid.uuid4().hex[:6]}"
    scan_2 = f"SCAN_2_{uuid.uuid4().hex[:6]}"

    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO risk_summary (scan_id, ip, critical_count, high_count, medium_count, low_count, total_score, risk_level, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_1, target_ip, 0, 1, 0, 0, 7, "Medium", "2026-08-24 09:00:00")
    )
    conn.execute(
        """
        INSERT INTO risk_summary (scan_id, ip, critical_count, high_count, medium_count, low_count, total_score, risk_level, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_2, target_ip, 2, 0, 0, 0, 20, "High", "2026-08-24 10:00:00")
    )
    conn.commit()

    rows = conn.execute("SELECT * FROM risk_summary WHERE ip = ? ORDER BY id ASC", (target_ip,)).fetchall()
    assert len(rows) == 2
    assert rows[0]["scan_id"] == scan_1
    assert rows[0]["risk_level"] == "Medium"
    assert rows[1]["scan_id"] == scan_2
    assert rows[1]["risk_level"] == "High"

    # Verify get_latest_risk with and without scan_id
    latest_unspecified = get_latest_risk(target_ip)
    assert latest_unspecified["scan_id"] == scan_2

    latest_specified = get_latest_risk(target_ip, scan_id=scan_1)
    assert latest_specified["scan_id"] == scan_1
    assert latest_specified["total_score"] == 7

    conn.close()
