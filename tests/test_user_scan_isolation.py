import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import pytest
import sqlite3
from dashboard.app import app
from database.db_helpers import (
    get_db_connection,
    get_latest_ip,
    get_latest_url_scan,
    get_ip_scan_context,
    get_url_scan_dashboard_context,
)
from database.security_posture import save_security_posture


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def clean_test_data():
    conn = get_db_connection()
    # Clean up test records
    conn.execute("DELETE FROM scan_history WHERE target_ip IN ('192.168.100.1', '10.200.0.1')")
    conn.execute("DELETE FROM host_status WHERE target_ip IN ('192.168.100.1', '10.200.0.1')")
    conn.execute("DELETE FROM url_scan_results WHERE domain IN ('user-alice-domain.test', 'user-bob-domain.test')")
    conn.execute("DELETE FROM security_posture WHERE url IN ('https://user-alice-domain.test', 'https://user-bob-domain.test')")
    conn.commit()
    conn.close()

    yield

    conn = get_db_connection()
    conn.execute("DELETE FROM scan_history WHERE target_ip IN ('192.168.100.1', '10.200.0.1')")
    conn.execute("DELETE FROM host_status WHERE target_ip IN ('192.168.100.1', '10.200.0.1')")
    conn.execute("DELETE FROM url_scan_results WHERE domain IN ('user-alice-domain.test', 'user-bob-domain.test')")
    conn.execute("DELETE FROM security_posture WHERE url IN ('https://user-alice-domain.test', 'https://user-bob-domain.test')")
    conn.commit()
    conn.close()


def test_db_helpers_user_isolation():
    conn = get_db_connection()

    # User 101 (Alice) scan data
    conn.execute(
        "INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("alice-scan-1", 101, "192.168.100.1", "Alive", "2026-09-01 10:00:00")
    )
    conn.execute(
        "INSERT INTO host_status (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("alice-scan-1", 101, "192.168.100.1", "Alive", "2026-09-01 10:00:00")
    )
    conn.execute(
        """
        INSERT INTO url_scan_results (scan_id, user_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("alice-url-1", 101, "https://user-alice-domain.test", "user-alice-domain.test", "192.168.100.1", "https", 15, "Low", "OK", "2026-09-01 10:05:00")
    )

    # User 202 (Bob) scan data
    conn.execute(
        "INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("bob-scan-1", 202, "10.200.0.1", "Alive", "2026-09-01 11:00:00")
    )
    conn.execute(
        "INSERT INTO host_status (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("bob-scan-1", 202, "10.200.0.1", "Alive", "2026-09-01 11:00:00")
    )
    conn.execute(
        """
        INSERT INTO url_scan_results (scan_id, user_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("bob-url-1", 202, "https://user-bob-domain.test", "user-bob-domain.test", "10.200.0.1", "https", 65, "High", "Critical Issues", "2026-09-01 11:05:00")
    )
    conn.commit()
    conn.close()

    # 1. Test get_latest_ip isolation
    alice_latest_ip = get_latest_ip(user_id=101)
    bob_latest_ip = get_latest_ip(user_id=202)

    assert alice_latest_ip == "192.168.100.1", f"Expected Alice IP to be 192.168.100.1, got {alice_latest_ip}"
    assert bob_latest_ip == "10.200.0.1", f"Expected Bob IP to be 10.200.0.1, got {bob_latest_ip}"

    # 2. Test get_latest_url_scan isolation
    alice_url = get_latest_url_scan(user_id=101)
    bob_url = get_latest_url_scan(user_id=202)

    assert alice_url is not None
    assert alice_url["domain"] == "user-alice-domain.test"
    assert alice_url["score"] == 15

    assert bob_url is not None
    assert bob_url["domain"] == "user-bob-domain.test"
    assert bob_url["score"] == 65

    # 3. Test Dashboard Context Isolation
    alice_ctx = get_url_scan_dashboard_context(user_id=101)
    bob_ctx = get_url_scan_dashboard_context(user_id=202)

    assert alice_ctx["url_scan"]["domain"] == "user-alice-domain.test"
    assert bob_ctx["url_scan"]["domain"] == "user-bob-domain.test"


def test_routes_user_isolation(client):
    conn = get_db_connection()

    # Alice scan
    conn.execute(
        "INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("alice-rt-1", 101, "192.168.100.1", "Alive", "2026-09-01 12:00:00")
    )
    conn.execute(
        "INSERT INTO host_status (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("alice-rt-1", 101, "192.168.100.1", "Alive", "2026-09-01 12:00:00")
    )
    conn.execute(
        """
        INSERT INTO url_scan_results (scan_id, user_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("alice-rt-url", 101, "https://user-alice-domain.test", "user-alice-domain.test", "192.168.100.1", "https", 10, "Low", "Alice remarks", "2026-09-01 12:00:00")
    )

    # Bob scan
    conn.execute(
        "INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("bob-rt-1", 202, "10.200.0.1", "Alive", "2026-09-01 13:00:00")
    )
    conn.execute(
        "INSERT INTO host_status (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("bob-rt-1", 202, "10.200.0.1", "Alive", "2026-09-01 13:00:00")
    )
    conn.execute(
        """
        INSERT INTO url_scan_results (scan_id, user_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("bob-rt-url", 202, "https://user-bob-domain.test", "user-bob-domain.test", "10.200.0.1", "https", 80, "Critical", "Bob remarks", "2026-09-01 13:00:00")
    )
    conn.commit()
    conn.close()

    # Session 1: Alice logged in
    with client.session_transaction() as sess:
        sess["user_id"] = 101
        sess["username"] = "alice"
        sess["role"] = "OPERATOR"

    resp = client.get("/url-scan-result")
    assert resp.status_code == 200
    assert b"user-alice-domain.test" in resp.data
    assert b"user-bob-domain.test" not in resp.data

    resp_hist = client.get("/url-history")
    assert resp_hist.status_code == 200
    assert b"user-alice-domain.test" in resp_hist.data
    assert b"user-bob-domain.test" not in resp_hist.data

    # Session 2: Bob logged in
    with client.session_transaction() as sess:
        sess["user_id"] = 202
        sess["username"] = "bob"
        sess["role"] = "OPERATOR"

    resp2 = client.get("/url-scan-result")
    assert resp2.status_code == 200
    assert b"user-bob-domain.test" in resp2.data
    assert b"user-alice-domain.test" not in resp2.data

    resp2_hist = client.get("/url-history")
    assert resp2_hist.status_code == 200
    assert b"user-bob-domain.test" in resp2_hist.data
    assert b"user-alice-domain.test" not in resp2_hist.data


def test_brand_new_user_gets_populated_baseline_scan(client):
    # Brand new user with ID 999 (Charlie) who has zero previous scans
    with client.session_transaction() as sess:
        sess["user_id"] = 999
        sess["username"] = "charlie"
        sess["role"] = "USER"

    resp = client.get("/url-scan-result")
    assert resp.status_code == 200

    resp_ip = client.get("/ip-scan-result")
    assert resp_ip.status_code == 200

    resp_dash = client.get("/")
    assert resp_dash.status_code == 200
    assert b"Security Operations Dashboard" in resp_dash.data


def test_logout_and_switch_user_complete_isolation(client):
    conn = get_db_connection()
    # Insert User 1 (Alice) distinct data
    conn.execute(
        "INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("alice-sw-1", 301, "192.168.100.1", "Alive", "2026-09-01 14:00:00")
    )
    conn.execute(
        "INSERT INTO host_status (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("alice-sw-1", 301, "192.168.100.1", "Alive", "2026-09-01 14:00:00")
    )
    conn.execute(
        """
        INSERT INTO url_scan_results (scan_id, user_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("alice-sw-1", 301, "https://user-alice-domain.test", "user-alice-domain.test", "192.168.100.1", "https", 10, "Low", "Alice remarks", "2026-09-01 14:00:00")
    )

    # Insert User 2 (Bob) distinct data
    conn.execute(
        "INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("bob-sw-1", 302, "10.200.0.1", "Alive", "2026-09-01 15:00:00")
    )
    conn.execute(
        "INSERT INTO host_status (scan_id, user_id, target_ip, status, scan_time) VALUES (?, ?, ?, ?, ?)",
        ("bob-sw-1", 302, "10.200.0.1", "Alive", "2026-09-01 15:00:00")
    )
    conn.execute(
        """
        INSERT INTO url_scan_results (scan_id, user_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("bob-sw-1", 302, "https://user-bob-domain.test", "user-bob-domain.test", "10.200.0.1", "https", 90, "Critical", "Bob remarks", "2026-09-01 15:00:00")
    )
    conn.commit()
    conn.close()

    # Step 1: User 1 (Alice) logs in
    with client.session_transaction() as sess:
        sess["user_id"] = 301
        sess["username"] = "alice301"
        sess["role"] = "ADMIN"

    resp1_url = client.get("/url-scan-result")
    assert b"user-alice-domain.test" in resp1_url.data
    assert b"user-bob-domain.test" not in resp1_url.data

    resp1_hist = client.get("/history")
    assert b"192.168.100.1" in resp1_hist.data
    assert b"10.200.0.1" not in resp1_hist.data

    # Step 2: User 1 logs out
    client.get("/logout")

    # Step 3: User 2 (Bob) logs in
    with client.session_transaction() as sess:
        sess["user_id"] = 302
        sess["username"] = "bob302"
        sess["role"] = "ADMIN"

    resp2_url = client.get("/url-scan-result")
    assert b"user-bob-domain.test" in resp2_url.data
    assert b"user-alice-domain.test" not in resp2_url.data

    resp2_hist = client.get("/history")
    assert b"10.200.0.1" in resp2_hist.data
    assert b"192.168.100.1" not in resp2_hist.data

    resp2_url_hist = client.get("/url-history")
    assert b"user-bob-domain.test" in resp2_url_hist.data
    assert b"user-alice-domain.test" not in resp2_url_hist.data

    # Step 4: User 2 logs out and User 1 logs back in
    client.get("/logout")

    with client.session_transaction() as sess:
        sess["user_id"] = 301
        sess["username"] = "alice301"
        sess["role"] = "ADMIN"

    resp3_url = client.get("/url-scan-result")
    assert b"user-alice-domain.test" in resp3_url.data
    assert b"user-bob-domain.test" not in resp3_url.data
