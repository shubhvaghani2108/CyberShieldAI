import os
import sys
import pytest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.app import app
from database.user_helpers import create_user, delete_user, get_user_by_username
from database.security_activity_helpers import (
    init_security_activity_table,
    log_security_activity,
    get_security_activity_logs,
    get_security_activity_metrics,
)


@pytest.fixture(autouse=True)
def setup_db():
    init_security_activity_table()
    yield


def test_security_activity_logging():
    # Test logging security events
    log_id = log_security_activity(
        event_type="LOGIN_SUCCESS",
        status="SUCCESS",
        username="admin",
        email="admin@cybershield.ai",
        details="Unit test admin login event",
    )
    assert log_id is not None

    logs, total_count, total_pages, current_page = get_security_activity_logs(page=1, per_page=10)
    assert total_count >= 1
    assert any(l["event_type"] == "LOGIN_SUCCESS" for l in logs)

    metrics = get_security_activity_metrics()
    assert "security_events_today" in metrics
    assert "successful_logins_today" in metrics
    assert "failed_logins_today" in metrics
    assert "password_resets_today" in metrics


def test_admin_dashboard_access_control():
    client = app.test_client()

    # 1. Unauthenticated request -> redirect to profile_page or 403
    resp = client.get("/admin", follow_redirects=False)
    assert resp.status_code in (302, 403)

    # 2. Non-admin user session -> 403 Forbidden
    with client.session_transaction() as sess:
        sess["user_id"] = 999
        sess["username"] = "normal_user"
        sess["role"] = "VIEWER"

    resp = client.get("/admin", follow_redirects=False)
    assert resp.status_code == 403

    # 3. Admin user session -> 200 OK
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "ADMIN"

    resp = client.get("/admin", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Admin SOC" in resp.data or b"Admin Dashboard" in resp.data or b"Command Center" in resp.data


def test_security_activity_page_access_control():
    client = app.test_client()

    # Non-admin -> 403
    with client.session_transaction() as sess:
        sess["user_id"] = 999
        sess["username"] = "analyst_user"
        sess["role"] = "ANALYST"

    resp = client.get("/admin/security-activity", follow_redirects=False)
    assert resp.status_code == 403

    # Admin -> 200
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["role"] = "ADMIN"

    resp = client.get("/admin/security-activity", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Security Activity" in resp.data
