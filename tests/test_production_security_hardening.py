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
    verify_user_credentials,
)
from database.security_activity_helpers import (
    init_security_activity_table,
    get_security_activity_logs,
)
from dashboard.security_hardening import (
    check_login_rate_limit,
    record_failed_login,
    record_successful_login,
    check_otp_request_rate_limit,
    record_otp_request,
    check_otp_resend_cooldown,
    record_otp_resend,
    validate_password_strength,
    _FAILED_LOGINS,
    _OTP_REQUESTS,
    _RESEND_TIMESTAMPS,
)


class ProductionSecurityHardeningTestCase(unittest.TestCase):
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

        # Clear rate limiter memory
        _FAILED_LOGINS.clear()
        _OTP_REQUESTS.clear()
        _RESEND_TIMESTAMPS.clear()

        init_users_table()
        init_security_activity_table()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username LIKE 'harden_%'")
        cursor.execute("DELETE FROM security_activity_logs WHERE username LIKE 'harden_%'")
        conn.commit()
        conn.close()

        # Seed test admin and standard user
        create_user(
            username="harden_admin",
            password="AdminPassword123!",
            role="ADMIN",
            email="harden_admin@example.com",
            is_active=1,
        )
        create_user(
            username="harden_user",
            password="UserPassword123!",
            role="USER",
            email="harden_user@example.com",
            is_active=1,
        )

    def tearDown(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username LIKE 'harden_%'")
        cursor.execute("DELETE FROM security_activity_logs WHERE username LIKE 'harden_%'")
        conn.commit()
        conn.close()
        _FAILED_LOGINS.clear()
        _OTP_REQUESTS.clear()
        _RESEND_TIMESTAMPS.clear()
        self.app_context.pop()

    def test_01_login_rate_limiting(self):
        """Repeated failed login attempts trigger rate limiting lockout with a generic message."""
        target_username = "harden_user"

        # Submit 5 failed attempts
        for _ in range(5):
            resp = self.client.post("/login", data={
                "username": target_username,
                "password": "WrongPassword999!",
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)

        # 6th attempt should be blocked by rate limit
        resp_blocked = self.client.post("/login", data={
            "username": target_username,
            "password": "UserPassword123!",  # Even with correct password
        }, follow_redirects=True)
        self.assertIn(b"Too many failed login attempts", resp_blocked.data)

    def test_02_successful_login_resets_rate_limit(self):
        """A successful login clears previous failed attempt records."""
        record_failed_login("harden_user")
        record_failed_login("harden_user")

        # Successful login
        resp = self.client.post("/login", data={
            "username": "harden_user",
            "password": "UserPassword123!",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Rate limit should now allow attempts
        allowed, _ = check_login_rate_limit("harden_user")
        self.assertTrue(allowed)

    @patch("alerts.otp_service.send_verification_otp_email", return_value=(True, "Sent"))
    def test_03_registration_otp_rate_limiting(self, mock_send):
        """Exceeding allowed registration OTP requests triggers rate limiting."""
        email = "harden_spam@example.com"
        for i in range(5):
            record_otp_request(email, action="register")

        resp = self.client.post("/register", data={
            "username": "harden_spam",
            "email": email,
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
        }, follow_redirects=True)
        self.assertIn(b"Too many registration requests", resp.data)

    @patch("alerts.otp_service.send_password_reset_otp_email", return_value=(True, "Sent"))
    def test_04_forgot_password_rate_limiting(self, mock_send):
        """Exceeding password recovery OTP requests triggers rate limiting."""
        target = "harden_user@example.com"
        for i in range(5):
            record_otp_request(target, action="forgot_password")

        resp = self.client.post("/forgot-password", data={
            "email": target,
        }, follow_redirects=True)
        self.assertIn(b"Too many recovery requests", resp.data)

    def test_05_otp_resend_cooldown(self):
        """Requesting an OTP resend before cooldown elapses is rejected."""
        session_key = "test_cooldown_key"
        record_otp_resend(session_key)

        allowed, remaining = check_otp_resend_cooldown(session_key, cooldown_seconds=60)
        self.assertFalse(allowed)
        self.assertGreater(remaining, 0)

    def test_06_password_minimum_length_enforcement(self):
        """Passwords shorter than 8 characters are rejected."""
        valid, err = validate_password_strength("short")
        self.assertFalse(valid)
        self.assertIn("at least 8 characters", err)

        valid_strong, err_none = validate_password_strength("SecurePassword123!")
        self.assertTrue(valid_strong)
        self.assertEqual(err_none, "")

    def test_07_session_security_configuration(self):
        """Session cookies are configured with HttpOnly and SameSite."""
        self.assertTrue(self.app.config.get("SESSION_COOKIE_HTTPONLY"))
        self.assertEqual(self.app.config.get("SESSION_COOKIE_SAMESITE"), "Lax")

    def test_08_security_headers_present(self):
        """Response includes standard security headers."""
        resp = self.client.get("/login")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertIn("default-src", resp.headers.get("Content-Security-Policy"))

    def test_09_admin_authorization_server_side_lockout(self):
        """Standard USER role is strictly blocked (HTTP 403) from all admin routes."""
        user = get_user_by_username("harden_user")
        with self.client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess["username"] = user["username"]
            sess["role"] = "USER"
            sess["email"] = user["email"]

        admin_routes = [
            "/admin",
            "/users",
            "/users/create",
            f"/users/edit/{user['id']}",
            "/admin/security-activity",
        ]

        for route in admin_routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 403, f"User was not blocked from {route}")

        # Test POST admin route
        resp_post = self.client.post(f"/users/delete/{user['id']}")
        self.assertEqual(resp_post.status_code, 403)

    def test_10_no_credentials_leaked_in_errors_or_pages(self):
        """Verify that password hashes, raw OTPs, and API keys are never rendered."""
        admin = get_user_by_username("harden_admin")
        with self.client.session_transaction() as sess:
            sess["user_id"] = admin["id"]
            sess["username"] = admin["username"]
            sess["role"] = "ADMIN"
            sess["email"] = admin["email"]

        pages_to_check = [
            "/admin",
            "/users",
            "/admin/security-activity",
            "/settings/profile",
        ]

        for page in pages_to_check:
            resp = self.client.get(page)
            self.assertEqual(resp.status_code, 200)
            self.assertNotIn(b"scrypt:", resp.data)
            self.assertNotIn(b"pbkdf2:", resp.data)
            self.assertNotIn(b"BREVO_API_KEY", resp.data)


if __name__ == "__main__":
    unittest.main()
