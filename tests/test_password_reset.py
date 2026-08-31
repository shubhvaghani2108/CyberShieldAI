import os
import sys
import unittest
from unittest.mock import patch

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.app import app
from database.db_helpers import get_db_connection
from database.user_helpers import create_user, get_user_by_email, verify_user_credentials
from database.password_reset_helpers import (
    init_password_reset_table,
    get_password_reset_by_id,
    delete_password_reset,
)


class TestPasswordResetFlow(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()
        init_password_reset_table()

        # Clean test user if exists
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = 'reset_test_user' OR email = 'reset_test@example.com'")
            cursor.execute("DELETE FROM password_resets WHERE email = 'reset_test@example.com'")
            conn.commit()
        finally:
            conn.close()

        # Create a fresh test user
        self.user_id = create_user(
            username="reset_test_user",
            password="OldPassword123!",
            email="reset_test@example.com",
            role="ANALYST",
            is_active=1,
        )

    def tearDown(self):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = 'reset_test_user' OR email = 'reset_test@example.com'")
            cursor.execute("DELETE FROM password_resets WHERE email = 'reset_test@example.com'")
            conn.commit()
        finally:
            conn.close()

    def test_anti_enumeration_generic_response(self):
        """Entering an unregistered email returns the exact same generic notice."""
        response = self.client.post(
            "/forgot-password",
            data={"email": "nonexistent_user_99999@example.com"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"If this email address is registered, a password reset code has been sent.", response.data)
        self.assertIn(b"Verify Password Reset Code", response.data)

    @patch("alerts.email_api.send_https_email")
    def test_full_password_reset_lifecycle(self, mock_send_email):
        """End-to-end test: Request OTP -> Verify OTP -> Set New Password -> Login with New Password."""
        mock_send_email.return_value = (True, "Email dispatched successfully")

        # 1. Submit registered email
        resp1 = self.client.post(
            "/forgot-password",
            data={"email": "reset_test@example.com"},
            follow_redirects=True,
        )
        self.assertEqual(resp1.status_code, 200)
        self.assertIn(b"If this email address is registered, a password reset code has been sent.", resp1.data)
        self.assertTrue(mock_send_email.called)

        # Retrieve generated OTP from database
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT reset_id, otp_hash FROM password_resets WHERE email = 'reset_test@example.com'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            reset_id, otp_hash = row[0], row[1]
        finally:
            conn.close()

        # 2. Test invalid OTP entry
        resp_invalid = self.client.post(
            "/forgot-password/verify",
            data={"otp": "000000"},
            follow_redirects=True,
        )
        self.assertIn(b"Invalid recovery code", resp_invalid.data)

        # 3. Verify with correct OTP using verify_otp_hash logic
        from werkzeug.security import check_password_hash
        # To simulate correct OTP, we can test by patching verify_otp_hash or setting known OTP
        with patch("alerts.otp_service.verify_otp_hash", return_value=True):
            resp_valid = self.client.post(
                "/forgot-password/verify",
                data={"otp": "123456"},
                follow_redirects=True,
            )
            self.assertEqual(resp_valid.status_code, 200)
            self.assertIn(b"Set New Password", resp_valid.data)

        # 4. Test password mismatch on /reset-password
        resp_mismatch = self.client.post(
            "/reset-password",
            data={"password": "NewSecretPassword123!", "confirm_password": "DifferentPassword!"},
            follow_redirects=True,
        )
        self.assertIn(b"Passwords do not match", resp_mismatch.data)

        # 5. Submit valid new password
        resp_success = self.client.post(
            "/reset-password",
            data={"password": "NewSecretPassword123!", "confirm_password": "NewSecretPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(resp_success.status_code, 200)
        self.assertIn(b"Password reset successfully. Please sign in with your new password.", resp_success.data)

        # 6. Verify credentials: Old password must fail, new password must succeed
        old_auth = verify_user_credentials("reset_test_user", "OldPassword123!")
        self.assertIsNone(old_auth)

        new_auth = verify_user_credentials("reset_test_user", "NewSecretPassword123!")
        self.assertIsNotNone(new_auth)
        self.assertEqual(new_auth["username"], "reset_test_user")

    def test_rate_limiting_max_attempts_lockout(self):
        """After 5 incorrect OTP attempts, the reset request is destroyed."""
        # Initiate reset
        self.client.post(
            "/forgot-password",
            data={"email": "reset_test@example.com"},
            follow_redirects=True,
        )

        with patch("alerts.otp_service.verify_otp_hash", return_value=False):
            for i in range(5):
                resp = self.client.post(
                    "/forgot-password/verify",
                    data={"otp": "111111"},
                    follow_redirects=True,
                )

            # 5th attempt must trigger lockout message and redirect to /forgot-password
            self.assertIn(b"Maximum verification attempts exceeded", resp.data)


if __name__ == "__main__":
    unittest.main()
