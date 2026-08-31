import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.app import app
from database.db_helpers import get_db_connection
from database.user_helpers import (
    init_users_table,
    create_user,
    get_user_by_username,
)
from database.security_activity_helpers import (
    init_security_activity_table,
    log_security_activity,
    get_security_activity_logs,
    get_security_activity_metrics,
)


class SecurityActivityTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = app
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        with self.client.session_transaction() as sess:
            sess.clear()

        init_users_table()
        init_security_activity_table()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username LIKE 'sec_%'")
        cursor.execute("DELETE FROM security_activity_logs WHERE username LIKE 'sec_%'")
        conn.commit()
        conn.close()

        # Seed admin and standard test users
        create_user(
            username="sec_admin",
            password="AdminPassword123!",
            role="ADMIN",
            email="sec_admin@example.com",
            is_active=1,
        )
        create_user(
            username="sec_user",
            password="UserPassword123!",
            role="USER",
            email="sec_user@example.com",
            is_active=1,
        )

    def tearDown(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username LIKE 'sec_%'")
        cursor.execute("DELETE FROM security_activity_logs WHERE username LIKE 'sec_%'")
        conn.commit()
        conn.close()
        self.app_context.pop()

    def test_01_admin_can_access_security_activity(self):
        """ADMIN user can successfully access /admin/security-activity."""
        admin = get_user_by_username("sec_admin")
        with self.client.session_transaction() as sess:
            sess["user_id"] = admin["id"]
            sess["username"] = admin["username"]
            sess["role"] = "ADMIN"
            sess["email"] = admin["email"]

        resp = self.client.get("/admin/security-activity")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Activity", resp.data)
        self.assertIn(b"Total Users", resp.data)
        self.assertIn(b"Active (", resp.data)
        self.assertIn(b"Logins Today", resp.data)
        self.assertIn(b"Failed Logins Today", resp.data)
        self.assertIn(b"Password Resets", resp.data)

    def test_02_user_cannot_access_security_activity(self):
        """Standard USER role receives 403 / redirect when accessing /admin/security-activity."""
        user = get_user_by_username("sec_user")
        with self.client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess["username"] = user["username"]
            sess["role"] = "USER"
            sess["email"] = user["email"]

        resp = self.client.get("/admin/security-activity")
        self.assertEqual(resp.status_code, 403)

    def test_03_successful_login_creates_activity_record(self):
        """Successful login records LOGIN_SUCCESS event in security_activity_logs."""
        resp = self.client.post("/login", data={
            "username": "sec_user",
            "password": "UserPassword123!",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        logs, total, _, _ = get_security_activity_logs(event_filter="login")
        sec_user_logs = [l for l in logs if l["username"] == "sec_user" and l["event_type"] == "LOGIN_SUCCESS"]
        self.assertGreaterEqual(len(sec_user_logs), 1)
        self.assertEqual(sec_user_logs[0]["status"], "SUCCESS")

    def test_04_failed_login_creates_activity_record(self):
        """Failed login attempts record LOGIN_FAILED event in security_activity_logs."""
        resp = self.client.post("/login", data={
            "username": "sec_user",
            "password": "WrongPassword999!",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        logs, total, _, _ = get_security_activity_logs(event_filter="failed_login")
        sec_user_failed_logs = [l for l in logs if l["username"] == "sec_user" and l["event_type"] == "LOGIN_FAILED"]
        self.assertGreaterEqual(len(sec_user_failed_logs), 1)
        self.assertEqual(sec_user_failed_logs[0]["status"], "FAILED")

    @patch("alerts.otp_service.send_verification_otp_email", return_value=(True, "Sent"))
    def test_05_registration_creates_activity_record(self, mock_send):
        """Registering an account records REGISTRATION event in security_activity_logs."""
        resp = self.client.post("/register", data={
            "username": "sec_newreg",
            "email": "sec_newreg@example.com",
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        logs, total, _, _ = get_security_activity_logs(event_filter="registration")
        reg_logs = [l for l in logs if l["username"] == "sec_newreg" and l["event_type"] == "REGISTRATION"]
        self.assertGreaterEqual(len(reg_logs), 1)
        self.assertEqual(reg_logs[0]["status"], "SUCCESS")

    @patch("alerts.otp_service.send_password_reset_otp_email", return_value=(True, "Sent"))
    def test_06_password_reset_requested_creates_activity_record(self, mock_send):
        """Forgot password request records PASSWORD_RESET_REQUESTED event."""
        resp = self.client.post("/forgot-password", data={
            "email": "sec_user@example.com",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        logs, total, _, _ = get_security_activity_logs(event_filter="password_reset")
        reset_logs = [l for l in logs if l["email"] == "sec_user@example.com" and l["event_type"] == "PASSWORD_RESET_REQUESTED"]
        self.assertGreaterEqual(len(reset_logs), 1)

    def test_07_logout_creates_activity_record(self):
        """Logging out records LOGOUT event in security_activity_logs."""
        user = get_user_by_username("sec_user")
        with self.client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess["username"] = user["username"]
            sess["role"] = "USER"
            sess["email"] = user["email"]

        resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        logs, total, _, _ = get_security_activity_logs(event_filter="logout")
        logout_logs = [l for l in logs if l["username"] == "sec_user" and l["event_type"] == "LOGOUT"]
        self.assertGreaterEqual(len(logout_logs), 1)

    def test_08_sensitive_credentials_never_exposed(self):
        """Logs and dashboard rendering never contain raw passwords, password hashes, or OTP codes."""
        raw_password = "SuperSecretPassword123!"
        log_security_activity(
            event_type="LOGIN_FAILED",
            status="FAILED",
            username="sec_user",
            details="Invalid credentials submitted",
        )

        admin = get_user_by_username("sec_admin")
        with self.client.session_transaction() as sess:
            sess["user_id"] = admin["id"]
            sess["username"] = admin["username"]
            sess["role"] = "ADMIN"
            sess["email"] = admin["email"]

        resp = self.client.get("/admin/security-activity")
        self.assertNotIn(raw_password.encode("utf-8"), resp.data)
        self.assertNotIn(b"scrypt:", resp.data)
        self.assertNotIn(b"pbkdf2:", resp.data)

        # Inspect database table directly
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_activity_logs WHERE username = 'sec_user'")
        columns = [d[0] for d in cursor.description]
        rows = cursor.fetchall()
        conn.close()

        for col in columns:
            self.assertNotIn("password", col.lower())
            self.assertNotIn("hash", col.lower())
            self.assertNotIn("secret", col.lower())
            self.assertNotIn("token", col.lower())

    def test_09_filtering_and_pagination(self):
        """Activity log supports pagination and filtering by category."""
        # Insert test logs
        for i in range(25):
            log_security_activity(
                event_type="LOGIN_SUCCESS" if i % 2 == 0 else "LOGIN_FAILED",
                status="SUCCESS" if i % 2 == 0 else "FAILED",
                username=f"sec_page_{i}",
                details=f"Paging test item {i}",
            )

        # Test page 1 with per_page 10
        logs_p1, total, total_pages, p1 = get_security_activity_logs(page=1, per_page=10)
        self.assertEqual(len(logs_p1), 10)
        self.assertGreaterEqual(total_pages, 3)

        # Test filter = 'failed_login'
        failed_logs, failed_total, _, _ = get_security_activity_logs(event_filter="failed_login", page=1, per_page=50)
        for fl in failed_logs:
            self.assertEqual(fl["event_type"], "LOGIN_FAILED")


if __name__ == "__main__":
    unittest.main()
