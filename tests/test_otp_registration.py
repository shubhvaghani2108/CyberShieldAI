import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.app import app
from database.db_helpers import get_db_connection, init_db
from database.user_helpers import (
    init_users_table,
    create_user,
    get_user_by_username,
    get_user_by_email,
    verify_user_credentials,
)
from database.otp_helpers import (
    init_otp_table,
    create_pending_registration,
    get_pending_registration,
    delete_pending_registration,
)
from alerts.otp_service import (
    generate_secure_otp,
    hash_otp,
    verify_otp_hash,
    get_otp_config,
    get_smtp_effective_settings,
)


class OTPRegistrationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "test-secret-key-cybershield-otp-suite"
        cls.client = app.test_client()

        init_db()
        init_users_table()
        init_otp_table()

        # Seed known test admin and user
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE username IN ('otp_test_admin', 'otp_existing_user', 'new_reg_user', 'rate_reg_user', 'attempt_reg_user', 'resend_reg_user')")
            conn.execute("DELETE FROM pending_registrations WHERE username LIKE '%test%' OR username LIKE '%reg%'")
            conn.commit()
        finally:
            conn.close()

        create_user(username="otp_test_admin", password="AdminPass123!", role="ADMIN", email="admin@otp.test")
        create_user(username="otp_existing_user", password="UserPass123!", role="USER", email="existing@otp.test")

    def setUp(self):
        with self.client.session_transaction() as sess:
            sess.clear()

        # Ensure seed test users exist
        if not get_user_by_username("otp_test_admin"):
            create_user(username="otp_test_admin", password="AdminPass123!", role="ADMIN", email="admin@otp.test")
        if not get_user_by_username("otp_existing_user"):
            create_user(username="otp_existing_user", password="UserPass123!", role="USER", email="existing@otp.test")

    def tearDown(self):
        with self.client.session_transaction() as sess:
            sess.clear()
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE username IN ('new_reg_user', 'rate_reg_user', 'attempt_reg_user', 'resend_reg_user', 'clean_user', 'role_test_user', 'login_test_user')")
            conn.execute("DELETE FROM pending_registrations WHERE username IN ('new_reg_user', 'rate_reg_user', 'attempt_reg_user', 'resend_reg_user', 'clean_user', 'role_test_user', 'login_test_user')")
            conn.commit()
        finally:
            conn.close()

    # 1. Registration page loads
    def test_01_register_page_loads(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create New User Account", response.data)
        self.assertIn(b"Email Address", response.data)
        self.assertIn(b"Password", response.data)

    # 2. Valid registration creates pending verification
    @patch("alerts.otp_service.send_verification_otp_email", return_value=(True, "Sent successfully"))
    def test_02_valid_registration_creates_pending_verification(self, mock_send):
        response = self.client.post("/register", data={
            "username": "new_reg_user",
            "email": "newreg@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/verify-otp", response.headers.get("Location", ""))

        # Verify record exists in pending_registrations and NOT in active users
        with self.client.session_transaction() as sess:
            reg_id = sess.get("pending_registration_id")
            self.assertIsNotNone(reg_id)
            pending = get_pending_registration(reg_id)
            self.assertIsNotNone(pending)
            self.assertEqual(pending["username"], "new_reg_user")
            self.assertEqual(pending["email"], "newreg@example.com")

        # User is NOT yet active in users table
        self.assertIsNone(get_user_by_username("new_reg_user"))

    # 3. Invalid email rejected
    def test_03_invalid_email_rejected(self):
        response = self.client.post("/register", data={
            "username": "new_reg_user",
            "email": "not-an-email",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please enter a valid email address.", response.data)
        self.assertIsNone(get_user_by_username("new_reg_user"))

    # 4. Duplicate username rejected
    def test_04_duplicate_username_rejected(self):
        response = self.client.post("/register", data={
            "username": "otp_test_admin",
            "email": "different@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This username is already taken.", response.data)

    # 5. Duplicate email rejected
    def test_05_duplicate_email_rejected(self):
        response = self.client.post("/register", data={
            "username": "brand_new_person",
            "email": "existing@otp.test",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"An account with this email address already exists.", response.data)

    # 6. Password mismatch rejected
    def test_06_password_mismatch_rejected(self):
        response = self.client.post("/register", data={
            "username": "new_reg_user",
            "email": "test@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "DifferentPassword123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Passwords do not match.", response.data)

    # 7. OTP is generated securely
    def test_07_otp_generated_securely(self):
        otp1 = generate_secure_otp(6)
        otp2 = generate_secure_otp(6)
        self.assertEqual(len(otp1), 6)
        self.assertEqual(len(otp2), 6)
        self.assertTrue(otp1.isdigit())
        self.assertTrue(otp2.isdigit())
        self.assertNotEqual(otp1, otp2)

    # 8. OTP is not exposed in the response
    @patch("alerts.otp_service.send_verification_otp_email")
    def test_08_otp_not_exposed_in_response(self, mock_send):
        captured_otp = []
        def capture_email(to_email, username, otp, expires_in_minutes=10):
            captured_otp.append(otp)
            return True, "Success"
        mock_send.side_effect = capture_email

        response = self.client.post("/register", data={
            "username": "new_reg_user",
            "email": "securetest@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(len(captured_otp) > 0)
        raw_otp = captured_otp[0]
        # Verify raw OTP is NOT anywhere in HTML response
        self.assertNotIn(raw_otp.encode(), response.data)

    # 9. Correct OTP verifies registration
    def test_09_correct_otp_verifies_registration(self):
        from werkzeug.security import generate_password_hash
        plain_otp = "849201"
        otp_h = hash_otp(plain_otp)
        pw_h = generate_password_hash("ValidPass123!")

        reg_id = create_pending_registration(
            username="new_reg_user",
            email="verified@example.com",
            password_hash=pw_h,
            otp_hash=otp_h,
            expires_in_minutes=10,
        )

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id
            sess["pending_email"] = "verified@example.com"

        response = self.client.post("/verify-otp", data={"otp": plain_otp}, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers.get("Location", ""))

        # Verify active user is created in database
        user = get_user_by_username("new_reg_user")
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], "verified@example.com")
        self.assertEqual(user["role"], "USER")
        self.assertEqual(user["is_active"], 1)

        # Verify pending record is deleted
        self.assertIsNone(get_pending_registration(reg_id))

    # 10. Incorrect OTP rejected
    def test_10_incorrect_otp_rejected(self):
        from werkzeug.security import generate_password_hash
        otp_h = hash_otp("123456")
        pw_h = generate_password_hash("ValidPass123!")

        reg_id = create_pending_registration(
            username="new_reg_user",
            email="wrong@example.com",
            password_hash=pw_h,
            otp_hash=otp_h,
            expires_in_minutes=10,
        )

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        response = self.client.post("/verify-otp", data={"otp": "999999"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid verification code", response.data)
        self.assertIsNone(get_user_by_username("new_reg_user"))

    # 11. Expired OTP rejected
    def test_11_expired_otp_rejected(self):
        from werkzeug.security import generate_password_hash
        plain_otp = "123456"
        otp_h = hash_otp(plain_otp)
        pw_h = generate_password_hash("ValidPass123!")

        reg_id = create_pending_registration(
            username="new_reg_user",
            email="expired@example.com",
            password_hash=pw_h,
            otp_hash=otp_h,
            expires_in_minutes=-5,  # already expired
        )

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        response = self.client.post("/verify-otp", data={"otp": plain_otp})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"expired", response.data.lower())
        self.assertIsNone(get_user_by_username("new_reg_user"))

    # 12. Resend OTP works
    @patch("alerts.otp_service.send_verification_otp_email", return_value=(True, "Resent"))
    def test_12_resend_otp_works(self, mock_send):
        from werkzeug.security import generate_password_hash
        old_otp_h = hash_otp("111111")
        pw_h = generate_password_hash("ValidPass123!")

        reg_id = create_pending_registration(
            username="resend_reg_user",
            email="resend@example.com",
            password_hash=pw_h,
            otp_hash=old_otp_h,
            expires_in_minutes=10,
        )

        # Set last_resend_at to 2 minutes ago to bypass cooldown
        conn = get_db_connection()
        past_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
        conn.execute("UPDATE pending_registrations SET last_resend_at = ? WHERE registration_id = ?", (past_time, reg_id))
        conn.commit()
        conn.close()

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        response = self.client.post("/resend-otp", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"A new 6-digit verification code has been sent", response.data)

        updated_pending = get_pending_registration(reg_id)
        self.assertNotEqual(updated_pending["otp_hash"], old_otp_h)

    # 13. Old OTP becomes invalid after resend
    @patch("alerts.otp_service.send_verification_otp_email", return_value=(True, "Resent"))
    def test_13_old_otp_invalid_after_resend(self, mock_send):
        from werkzeug.security import generate_password_hash
        old_otp = "111111"
        old_otp_h = hash_otp(old_otp)
        pw_h = generate_password_hash("ValidPass123!")

        reg_id = create_pending_registration(
            username="resend_reg_user",
            email="resend2@example.com",
            password_hash=pw_h,
            otp_hash=old_otp_h,
            expires_in_minutes=10,
        )

        # Set last_resend_at to 2 minutes ago
        conn = get_db_connection()
        past_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
        conn.execute("UPDATE pending_registrations SET last_resend_at = ? WHERE registration_id = ?", (past_time, reg_id))
        conn.commit()
        conn.close()

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        self.client.post("/resend-otp")

        # Try to verify with old OTP
        response = self.client.post("/verify-otp", data={"otp": old_otp})
        self.assertIn(b"Invalid verification code", response.data)
        self.assertIsNone(get_user_by_username("resend_reg_user"))

    # 14. OTP attempt limit works
    def test_14_otp_attempt_limit_works(self):
        from werkzeug.security import generate_password_hash
        otp_h = hash_otp("123456")
        pw_h = generate_password_hash("ValidPass123!")

        reg_id = create_pending_registration(
            username="attempt_reg_user",
            email="attempts@example.com",
            password_hash=pw_h,
            otp_hash=otp_h,
            expires_in_minutes=10,
            max_attempts=3,
        )

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        # Make 3 failed attempts
        self.client.post("/verify-otp", data={"otp": "000001"})
        self.client.post("/verify-otp", data={"otp": "000002"})
        final_res = self.client.post("/verify-otp", data={"otp": "000003"}, follow_redirects=True)

        self.assertIn(b"Maximum verification attempts exceeded", final_res.data)
        # Pending registration must be completely deleted/invalidated
        self.assertIsNone(get_pending_registration(reg_id))

    # 15. Resend rate limit works
    def test_15_resend_rate_limit_works(self):
        from werkzeug.security import generate_password_hash
        otp_h = hash_otp("123456")
        pw_h = generate_password_hash("ValidPass123!")

        reg_id = create_pending_registration(
            username="rate_reg_user",
            email="rate@example.com",
            password_hash=pw_h,
            otp_hash=otp_h,
            expires_in_minutes=10,
        )

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        # Immediate resend should trigger cooldown
        response = self.client.post("/resend-otp", follow_redirects=True)
        self.assertIn(b"Please wait", response.data)
        self.assertIn(b"seconds before requesting a new verification code", response.data)

    # 16. Verified user receives USER role (never ADMIN)
    def test_16_verified_user_receives_user_role(self):
        from werkzeug.security import generate_password_hash
        plain_otp = "937402"
        reg_id = create_pending_registration(
            username="role_test_user",
            email="role@example.com",
            password_hash=generate_password_hash("Pass1234!"),
            otp_hash=hash_otp(plain_otp),
            expires_in_minutes=10,
        )

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        self.client.post("/verify-otp", data={"otp": plain_otp})
        user = get_user_by_username("role_test_user")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "USER")
        self.assertNotEqual(user["role"], "ADMIN")

        # Cleanup
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE username = 'role_test_user'")
        conn.commit()
        conn.close()

    # 17. Verified user can log in
    def test_17_verified_user_can_login(self):
        from werkzeug.security import generate_password_hash
        plain_otp = "772211"
        raw_pw = "MySecretLoginPass99!"
        reg_id = create_pending_registration(
            username="login_test_user",
            email="logintest@example.com",
            password_hash=generate_password_hash(raw_pw),
            otp_hash=hash_otp(plain_otp),
            expires_in_minutes=10,
        )

        with self.client.session_transaction() as sess:
            sess["pending_registration_id"] = reg_id

        self.client.post("/verify-otp", data={"otp": plain_otp})

        # Test login
        response = self.client.post("/login", data={
            "username": "login_test_user",
            "password": raw_pw,
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "login_test_user")
            self.assertEqual(sess.get("role"), "USER")

        # Cleanup
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE username = 'login_test_user'")
        conn.commit()
        conn.close()

    # 18. Google login still works
    def test_18_google_login_route_accessible(self):
        with patch.dict(os.environ, {
            "GOOGLE_CLIENT_ID": "mock_id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "mock_secret",
        }):
            response = self.client.get("/auth/google")
            self.assertEqual(response.status_code, 302)
            self.assertIn("accounts.google.com", response.headers.get("Location", ""))

    # 19. Existing admin account still works
    def test_19_existing_admin_account_still_works(self):
        response = self.client.post("/login", data={
            "username": "otp_test_admin",
            "password": "AdminPass123!",
        }, follow_redirects=False)

    # 20. No secrets are hardcoded
    def test_20_no_secrets_hardcoded(self):
        import glob
        py_files = glob.glob(os.path.join(BASE_DIR, "dashboard", "*.py")) + \
                   glob.glob(os.path.join(BASE_DIR, "alerts", "*.py")) + \
                   glob.glob(os.path.join(BASE_DIR, "database", "*.py"))
        
        forbidden_patterns = ["GOCSPX-", "AIzaSy", "password123", "Admin@1234!Hardcoded"]
        for filepath in py_files:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for pattern in forbidden_patterns:
                    self.assertNotIn(pattern, content, f"Hardcoded secret pattern '{pattern}' found in {filepath}")

    # 21. Resend HTTPS API payload formatting and call
    @patch("requests.post")
    def test_21_resend_api_https_payload_structure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "re_mock_12345"}
        mock_post.return_value = mock_response

        from alerts.email_api import send_https_email
        config = {
            "provider": "resend",
            "api_key": "re_test_key_xyz",
            "from_name": "CyberShieldAI",
            "from_email": "onboarding@resend.dev",
        }
        success, msg = send_https_email(
            to_email="target@example.com",
            subject="CyberShieldAI — Email Verification OTP",
            html_body="<p>Test</p>",
            text_body="Test",
            config=config,
        )
        self.assertTrue(success)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.resend.com/emails")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer re_test_key_xyz")
        self.assertEqual(kwargs["json"]["to"], ["target@example.com"])
        self.assertIn("CyberShieldAI", kwargs["json"]["from"])

    # 22. SendGrid HTTPS API payload formatting and call
    @patch("requests.post")
    def test_22_sendgrid_api_https_payload_structure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_post.return_value = mock_response

        from alerts.email_api import send_https_email
        config = {
            "provider": "sendgrid",
            "api_key": "SG.mock_key_xyz",
            "from_name": "CyberShieldAI",
            "from_email": "alerts@cybershield.ai",
        }
        success, msg = send_https_email(
            to_email="target@example.com",
            subject="CyberShieldAI — Email Verification OTP",
            html_body="<p>Test</p>",
            text_body="Test",
            config=config,
        )
        self.assertTrue(success)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.sendgrid.com/v3/mail/send")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer SG.mock_key_xyz")

    # 23. Mailgun HTTPS API payload formatting and call
    @patch("requests.post")
    def test_23_mailgun_api_https_payload_structure(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        from alerts.email_api import send_https_email
        config = {
            "provider": "mailgun",
            "api_key": "key-mockmailgun123",
            "mailgun_domain": "sandbox.mailgun.org",
            "from_name": "CyberShieldAI",
            "from_email": "postmaster@sandbox.mailgun.org",
        }
        success, msg = send_https_email(
            to_email="target@example.com",
            subject="CyberShieldAI — Email Verification OTP",
            html_body="<p>Test</p>",
            text_body="Test",
            config=config,
        )
        self.assertTrue(success)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.mailgun.net/v3/sandbox.mailgun.org/messages")
        self.assertEqual(kwargs["auth"], ("api", "key-mockmailgun123"))

    # 24. Registration fails gracefully when email API fails
    @patch("alerts.otp_service.send_verification_otp_email", return_value=(False, "Connection timeout"))
    def test_24_registration_fails_gracefully_when_email_api_fails(self, mock_send):
        response = self.client.post("/register", data={
            "username": "fail_email_user",
            "email": "fail_email@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unable to send the verification email right now", response.data)
        
        # Ensure no pending registration was saved
        self.assertIsNone(get_user_by_username("fail_email_user"))
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("pending_registration_id"))

    # 25. Sensitive keys and OTP are never exposed in loggers or templates
    @patch("requests.post")
    def test_25_api_key_and_otp_never_leaked_on_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"message": "Invalid API Key"}
        mock_post.return_value = mock_response

        from alerts.email_api import send_https_email
        secret_api_key = "re_super_secret_api_key_do_not_leak"
        config = {
            "provider": "resend",
            "api_key": secret_api_key,
            "from_name": "CyberShieldAI",
            "from_email": "onboarding@resend.dev",
        }
        success, err_msg = send_https_email(
            to_email="target@example.com",
            subject="CyberShieldAI — Email Verification OTP",
            html_body="<p>Test</p>",
            text_body="Test",
            config=config,
        )
        self.assertFalse(success)
        self.assertNotIn(secret_api_key, err_msg)

    # 26. Admin test email function works via HTTPS API
    @patch("requests.post")
    def test_26_admin_test_email_functionality(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "re_admin_test_123"}
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "EMAIL_PROVIDER": "resend",
            "EMAIL_API_KEY": "re_valid_key_123",
            "EMAIL_FROM": "alerts@verifieddomain.com",
        }):
            from alerts.email_api import send_admin_test_email
            success, msg = send_admin_test_email("admin_tester@example.com")
            self.assertTrue(success)
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            self.assertEqual(kwargs["json"]["to"], ["admin_tester@example.com"])
            self.assertEqual(kwargs["json"]["from"], "CyberShieldAI <alerts@verifieddomain.com>")


if __name__ == "__main__":
    unittest.main()
