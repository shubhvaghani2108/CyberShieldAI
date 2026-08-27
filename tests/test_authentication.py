import io
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from flask import session

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.app import app
from database.user_helpers import (
    init_users_table,
    create_user,
    create_google_user,
    get_user_by_username,
    get_user_by_email,
    get_user_by_id,
    get_user_by_google_sub,
    update_user_password,
    get_db_connection,
)
from dashboard.auth import is_safe_url


class AuthenticationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

        # Initialize users table with schema migrations
        init_users_table()

        # Set up test users
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE username IN ('test_admin', 'test_analyst', 'test_viewer', 'existing_local_user', 'google_user', 'new_registered_user')")
            conn.commit()
        finally:
            conn.close()

        create_user(username="test_admin", password="AdminPassword123!", role="ADMIN", email="admin@cybershield.test")
        create_user(username="test_analyst", password="AnalystPassword456!", role="ANALYST", email="analyst@cybershield.test")
        create_user(username="test_viewer", password="ViewerPassword789!", role="VIEWER", email="viewer@cybershield.test")
        create_user(username="existing_local_user", password="LocalPassword123!", role="ANALYST", email="conflict@gmail.com")

    @classmethod
    def tearDownClass(cls):
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE username LIKE 'test_%' OR username LIKE 'managed_operator_%' OR username IN ('existing_local_user', 'new_registered_user', 'new_google_person', 'non_admin_user', 'verified_analyst', 'existing_google_user')")
            max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM users").fetchone()[0]
            conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'users'", (max_id,))
            conn.commit()
        finally:
            conn.close()

    def setUp(self):
        self.client = app.test_client()

    # 1. /login Page Access
    def test_01_login_page_returns_200(self):
        """1. /login returns 200 OK and contains login and Google SSO buttons."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Sign In", response.data)
        self.assertIn(b"Continue with Google", response.data)
        self.assertIn(b"Create Account", response.data)

    # 2. Local Login Valid Credentials
    def test_02_local_login_valid_credentials(self):
        """2. Valid local username/password logs in and redirects to dashboard."""
        response = self.client.post(
            "/login",
            data={"username": "test_admin", "password": "AdminPassword123!"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            self.assertEqual(session.get("username"), "test_admin")
            self.assertEqual(session.get("role"), "ADMIN")
            self.assertIsNotNone(session.get("user_id"))

    def test_02b_local_login_via_email_address(self):
        """2b. User can log in using their email address instead of username."""
        response = self.client.post(
            "/login",
            data={"username": "admin@cybershield.test", "password": "AdminPassword123!"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        with self.client as client:
            client.post("/login", data={"username": "admin@cybershield.test", "password": "AdminPassword123!"})
            self.assertEqual(session.get("username"), "test_admin")
            self.assertEqual(session.get("email"), "admin@cybershield.test")
            self.assertEqual(session.get("role"), "ADMIN")

    # 3. Invalid Local Credentials
    def test_03_invalid_local_credentials_rejected(self):
        """3. Invalid password or non-existent username are rejected."""
        # Wrong password
        res_wrong_pw = self.client.post(
            "/login",
            data={"username": "test_admin", "password": "WrongPassword!"},
            follow_redirects=True,
        )
        self.assertEqual(res_wrong_pw.status_code, 200)
        self.assertIn(b"Invalid username", res_wrong_pw.data)

        # Unknown username
        res_unknown = self.client.post(
            "/login",
            data={"username": "non_existent_operator", "password": "AnyPassword!"},
            follow_redirects=True,
        )
        self.assertEqual(res_unknown.status_code, 200)
        self.assertIn(b"Invalid username", res_unknown.data)

    # 4. /auth/google Initiation & Redirect to Google
    def test_04_auth_google_redirects_to_google(self):
        """4. /auth/google redirects to Google's official authorization endpoint with required params."""
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                res = client.get("/auth/google", follow_redirects=False)
                self.assertEqual(res.status_code, 302)
                location = res.headers["Location"]
                self.assertTrue(location.startswith("https://accounts.google.com/o/oauth2/v2/auth"))
                self.assertIn("client_id=mock_client_id_123", location)
                self.assertIn("response_type=code", location)
                self.assertIn("scope=openid+email+profile", location)
                self.assertIn("state=", location)
                # Session contains state
                self.assertIsNotNone(session.get("oauth_state"))

    # 5. OAuth State Generation & Preservation
    def test_05_oauth_state_generation(self):
        """5. OAuth state is randomly generated, stored in session, and included in the authorization URL."""
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                res1 = client.get("/auth/google?next=/monitoring", follow_redirects=False)
                state1 = session.get("oauth_state")
                self.assertIsNotNone(state1)
                self.assertIn(f"state={state1}", res1.headers["Location"])
                self.assertEqual(session.get("oauth_next"), "/monitoring")

    # 6. Invalid OAuth State Rejected (CSRF Defense)
    def test_06_invalid_oauth_state_rejected(self):
        """6. /auth/google/callback rejects missing or mismatched state parameter."""
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                # Set a session state
                with client.session_transaction() as sess:
                    sess["oauth_state"] = "valid_state_abc"

                # Send wrong state
                res_wrong = client.get("/auth/google/callback?code=mock_code&state=forged_state_xyz", follow_redirects=True)
                self.assertEqual(res_wrong.status_code, 200)
                self.assertIn(b"Invalid or missing OAuth state parameter", res_wrong.data)

                # Send missing state
                res_missing = client.get("/auth/google/callback?code=mock_code", follow_redirects=True)
                self.assertEqual(res_missing.status_code, 200)
                self.assertIn(b"Invalid or missing OAuth state parameter", res_missing.data)

    # 7. Callback Without Code Rejected
    def test_07_callback_without_code_rejected(self):
        """7. /auth/google/callback rejects requests without authorization code or with provider error."""
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                with client.session_transaction() as sess:
                    sess["oauth_state"] = "valid_state_abc"
                res_no_code = client.get("/auth/google/callback?state=valid_state_abc", follow_redirects=True)
                self.assertEqual(res_no_code.status_code, 200)
                self.assertIn(b"Missing authorization code", res_no_code.data)

                with client.session_transaction() as sess:
                    sess["oauth_state"] = "valid_state_def"
                res_error = client.get("/auth/google/callback?error=access_denied&state=valid_state_def", follow_redirects=True)
                self.assertEqual(res_error.status_code, 200)
                self.assertIn(b"Google authentication error", res_error.data)

    # 8. Google Identity Processing & Token Exchange
    @patch("urllib.request.urlopen")
    def test_08_google_identity_processing(self, mock_urlopen):
        """8. Google authorization code is exchanged and identity claims verified."""
        mock_token_bytes = json.dumps({"access_token": "mock_token_xyz_123"}).encode("utf-8")
        mock_userinfo_bytes = json.dumps({
            "sub": "google_sub_888999",
            "email": "verified_analyst@gmail.com",
            "name": "Verified Analyst",
            "picture": "https://lh3.googleusercontent.com/a/mock_avatar",
        }).encode("utf-8")

        mock_token_resp = MagicMock()
        mock_token_resp.read.return_value = mock_token_bytes
        mock_token_resp.__enter__.return_value = mock_token_resp

        mock_user_resp = MagicMock()
        mock_user_resp.read.return_value = mock_userinfo_bytes
        mock_user_resp.__enter__.return_value = mock_user_resp

        mock_urlopen.side_effect = [mock_token_resp, mock_user_resp]

        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                with client.session_transaction() as sess:
                    sess["oauth_state"] = "state_123"

                res = client.get("/auth/google/callback?code=mock_auth_code&state=state_123", follow_redirects=True)
                self.assertEqual(res.status_code, 200)
                self.assertEqual(session.get("username"), "verified_analyst")
                self.assertEqual(session.get("role"), "VIEWER")

    # 9. Existing Google User Login
    @patch("urllib.request.urlopen")
    def test_09_existing_google_user_login(self, mock_urlopen):
        """9. Existing Google user is matched by google_sub and logged in without creating duplicate account."""
        # Pre-create user with google_sub
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE google_sub = 'google_sub_existing_777'")
            conn.commit()
        finally:
            conn.close()

        created_user = create_google_user(
            email="existing_google_user@gmail.com",
            google_sub="google_sub_existing_777",
            full_name="Existing Google Operator",
            role="VIEWER",
        )
        self.assertIsNotNone(created_user)

        mock_token_bytes = json.dumps({"access_token": "mock_token_existing"}).encode("utf-8")
        mock_userinfo_bytes = json.dumps({
            "sub": "google_sub_existing_777",
            "email": "existing_google_user@gmail.com",
            "name": "Existing Google Operator",
        }).encode("utf-8")

        mock_token_resp = MagicMock()
        mock_token_resp.read.return_value = mock_token_bytes
        mock_token_resp.__enter__.return_value = mock_token_resp

        mock_user_resp = MagicMock()
        mock_user_resp.read.return_value = mock_userinfo_bytes
        mock_user_resp.__enter__.return_value = mock_user_resp

        mock_urlopen.side_effect = [mock_token_resp, mock_user_resp]

        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                with client.session_transaction() as sess:
                    sess["oauth_state"] = "state_existing"

                res = client.get("/auth/google/callback?code=mock_code&state=state_existing", follow_redirects=True)
                self.assertEqual(res.status_code, 200)
                self.assertEqual(session.get("user_id"), created_user["id"])
                self.assertEqual(session.get("username"), created_user["username"])

    # 10. First Google Login Creates Local Account
    @patch("urllib.request.urlopen")
    def test_10_first_google_login_creates_local_account(self, mock_urlopen):
        """10. First-time Google user is automatically provisioned in local database."""
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE google_sub = 'google_sub_new_user_111'")
            conn.commit()
        finally:
            conn.close()

        mock_token_bytes = json.dumps({"access_token": "mock_token_new"}).encode("utf-8")
        mock_userinfo_bytes = json.dumps({
            "sub": "google_sub_new_user_111",
            "email": "new_google_person@gmail.com",
            "name": "New Google Person",
            "picture": "https://avatar.url/mock.png",
        }).encode("utf-8")

        mock_token_resp = MagicMock()
        mock_token_resp.read.return_value = mock_token_bytes
        mock_token_resp.__enter__.return_value = mock_token_resp

        mock_user_resp = MagicMock()
        mock_user_resp.read.return_value = mock_userinfo_bytes
        mock_user_resp.__enter__.return_value = mock_user_resp

        mock_urlopen.side_effect = [mock_token_resp, mock_user_resp]

        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                with client.session_transaction() as sess:
                    sess["oauth_state"] = "state_new_user"

                res = client.get("/auth/google/callback?code=mock_code_new&state=state_new_user", follow_redirects=True)
                self.assertEqual(res.status_code, 200)

                # Check database record
                user = get_user_by_google_sub("google_sub_new_user_111")
                self.assertIsNotNone(user)
                self.assertEqual(user["email"], "new_google_person@gmail.com")
                self.assertEqual(user["auth_provider"], "google")

    # 11. Google-Created Account Defaults to Non-Admin Role
    @patch("urllib.request.urlopen")
    def test_11_google_created_account_defaults_to_non_admin_role(self, mock_urlopen):
        """11. New Google users must NOT automatically become ADMIN; defaults to VIEWER."""
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM users WHERE google_sub = 'google_sub_non_admin_222'")
            conn.commit()
        finally:
            conn.close()

        mock_token_bytes = json.dumps({"access_token": "mock_token_non_admin"}).encode("utf-8")
        mock_userinfo_bytes = json.dumps({
            "sub": "google_sub_non_admin_222",
            "email": "non_admin_user@gmail.com",
            "name": "Non Admin User",
        }).encode("utf-8")

        mock_token_resp = MagicMock()
        mock_token_resp.read.return_value = mock_token_bytes
        mock_token_resp.__enter__.return_value = mock_token_resp

        mock_user_resp = MagicMock()
        mock_user_resp.read.return_value = mock_userinfo_bytes
        mock_user_resp.__enter__.return_value = mock_user_resp

        mock_urlopen.side_effect = [mock_token_resp, mock_user_resp]

        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                with client.session_transaction() as sess:
                    sess["oauth_state"] = "state_non_admin"

                client.get("/auth/google/callback?code=mock_code&state=state_non_admin", follow_redirects=True)
                user = get_user_by_google_sub("google_sub_non_admin_222")
                self.assertIsNotNone(user)
                self.assertNotEqual(user["role"], "ADMIN")
                self.assertEqual(user["role"], "VIEWER")

    # 12. Existing Account Links Verified Google Identity
    @patch("urllib.request.urlopen")
    def test_12_existing_account_links_verified_google_identity(self, mock_urlopen):
        """12. If a user exists with the same verified email, Google login links google_sub and logs in."""
        # conflict@gmail.com exists as local account (existing_local_user)
        mock_token_bytes = json.dumps({"access_token": "mock_token_conflict"}).encode("utf-8")
        mock_userinfo_bytes = json.dumps({
            "sub": "google_sub_conflict_333",
            "email": "conflict@gmail.com",
            "name": "Conflict Person",
        }).encode("utf-8")

        mock_token_resp = MagicMock()
        mock_token_resp.read.return_value = mock_token_bytes
        mock_token_resp.__enter__.return_value = mock_token_resp

        mock_user_resp = MagicMock()
        mock_user_resp.read.return_value = mock_userinfo_bytes
        mock_user_resp.__enter__.return_value = mock_user_resp

        mock_urlopen.side_effect = [mock_token_resp, mock_user_resp]

        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "mock_client_id_123", "GOOGLE_CLIENT_SECRET": "mock_secret_456"}):
            with self.client as client:
                with client.session_transaction() as sess:
                    sess["oauth_state"] = "state_conflict"

                res = client.get("/auth/google/callback?code=mock_code&state=state_conflict", follow_redirects=True)
                self.assertEqual(res.status_code, 200)
                self.assertEqual(session.get("username"), "existing_local_user")

    # 13. Logout
    def test_13_logout_clears_session_and_redirects(self):
        """13. Logout clears session and prevents access to dashboard."""
        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            self.assertEqual(session.get("username"), "test_admin")

            res_logout = client.get("/logout", follow_redirects=False)
            self.assertEqual(res_logout.status_code, 302)
            self.assertIn("/login", res_logout.headers["Location"])
            self.assertIsNone(session.get("user_id"))

    # 14. Protected Routes
    def test_14_protected_routes_require_authentication(self):
        """14. Protected endpoints (/monitoring, /settings/profile) require login."""
        res1 = self.client.get("/monitoring", follow_redirects=False)
        self.assertEqual(res1.status_code, 302)
        self.assertIn("/login", res1.headers["Location"])

        res2 = self.client.get("/settings/profile", follow_redirects=False)
        self.assertEqual(res2.status_code, 302)
        self.assertIn("/login", res2.headers["Location"])

    # 15. Health Endpoint Remains Public
    def test_15_health_endpoint_remains_public(self):
        """15. /health is publicly accessible without authentication."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"healthy", res.data)

    # 16. Readiness Endpoint Remains Public
    def test_16_readiness_endpoint_remains_public(self):
        """16. /readiness is publicly accessible without authentication."""
        res = self.client.get("/readiness")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"ready", res.data)

    # 17. Safe Next Parameter Prevents Open Redirects
    def test_17_safe_next_parameter_prevents_open_redirects(self):
        """17. Safe next parameter prevents open redirects."""
        res_open = self.client.post(
            "/login",
            data={"username": "test_admin", "password": "AdminPassword123!", "next": "https://attacker.com"},
            follow_redirects=False,
        )
        self.assertEqual(res_open.status_code, 302)
        self.assertEqual(res_open.headers["Location"], "/")

        self.assertTrue(is_safe_url("/monitoring"))
        self.assertFalse(is_safe_url("https://malicious.com"))
        self.assertFalse(is_safe_url("//malicious.com"))

    # 18. Local Registration Flow
    def test_18_local_registration_flow(self):
        """18. Create account page allows local registration and redirects to OTP verification."""
        with patch("alerts.otp_service.send_verification_otp_email", return_value=(True, "Success")):
            res = self.client.post(
                "/register",
                data={
                    "username": "new_registered_user",
                    "email": "registered@cybershield.ai",
                    "password": "SecurePassword123!",
                    "confirm_password": "SecurePassword123!",
                },
                follow_redirects=True,
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"Email OTP Verification", res.data)
            self.assertIn(b"registered@cybershield.ai", res.data)

    # 19. /users Requires Authentication
    def test_19_users_route_requires_authentication(self):
        """19. Unauthenticated request to /users redirects to /login."""
        res = self.client.get("/users", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

    # 20. /users Forbidden for Non-Admin (VIEWER and ANALYST)
    def test_20_users_route_forbidden_for_viewer_and_analyst(self):
        """20. Non-admin roles (VIEWER and ANALYST) are denied access (403/redirect) to /users."""
        # Test VIEWER
        with self.client as client:
            client.post("/login", data={"username": "test_viewer", "password": "ViewerPassword789!"})
            res_viewer = client.get("/users")
            self.assertEqual(res_viewer.status_code, 403)
            client.get("/logout")

        # Test ANALYST
        with self.client as client:
            client.post("/login", data={"username": "test_analyst", "password": "AnalystPassword456!"})
            res_analyst = client.get("/users")
            self.assertEqual(res_analyst.status_code, 403)
            client.get("/logout")

    # 21. /users Accessible by ADMIN
    def test_21_users_route_accessible_by_admin(self):
        """21. ADMIN role can access /users and view registered accounts list."""
        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res_admin = client.get("/users")
            self.assertEqual(res_admin.status_code, 200)
            self.assertIn(b"User &amp; Access Management", res_admin.data)
            self.assertIn(b"test_admin", res_admin.data)
            client.get("/logout")

    # 22. Admin Can Create User
    def test_22_admin_can_create_user(self):
        """22. ADMIN can create a new user via POST /users/create."""
        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res = client.post(
                "/users/create",
                data={
                    "username": "managed_operator_1",
                    "email": "managed1@cybershield.ai",
                    "full_name": "Managed Operator One",
                    "role": "ANALYST",
                    "password": "ManagedPassword123!",
                    "is_active": "1",
                },
                follow_redirects=True,
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"created successfully", res.data)
            self.assertIn(b"managed_operator_1", res.data)

            # Verify in DB
            user = get_user_by_username("managed_operator_1")
            self.assertIsNotNone(user)
            self.assertEqual(user["email"], "managed1@cybershield.ai")
            self.assertEqual(user["role"], "ANALYST")
            client.get("/logout")

    # 23. Admin Can Edit User
    def test_23_admin_can_edit_user(self):
        """23. ADMIN can update user role, status, email, and password via /users/edit/<id>."""
        target = get_user_by_username("managed_operator_1")
        self.assertIsNotNone(target)

        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res = client.post(
                f"/users/edit/{target['id']}",
                data={
                    "username": "managed_operator_1_renamed",
                    "email": "managed1_updated@cybershield.ai",
                    "full_name": "Managed Operator Renamed",
                    "role": "VIEWER",
                    "password": "",  # Unchanged password
                    "is_active": "1",
                },
                follow_redirects=True,
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"updated successfully", res.data)

            # Verify in DB
            updated = get_user_by_id(target["id"])
            self.assertEqual(updated["username"], "managed_operator_1_renamed")
            self.assertEqual(updated["role"], "VIEWER")
            self.assertEqual(updated["email"], "managed1_updated@cybershield.ai")
            client.get("/logout")

    # 24. Admin Can Delete User
    def test_24_admin_can_delete_user(self):
        """24. ADMIN can delete another user via POST /users/delete/<id>."""
        target = get_user_by_username("managed_operator_1_renamed")
        self.assertIsNotNone(target)

        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res = client.post(f"/users/delete/{target['id']}", follow_redirects=True)
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"deleted successfully", res.data)

            # Verify deleted from DB
            deleted = get_user_by_id(target["id"])
            self.assertIsNone(deleted)
            client.get("/logout")

    # 25. Current Admin Cannot Delete Themselves
    def test_25_admin_cannot_delete_themselves(self):
        """25. Logged-in ADMIN cannot delete their own active account."""
        admin_user = get_user_by_username("test_admin")
        self.assertIsNotNone(admin_user)

        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res = client.post(f"/users/delete/{admin_user['id']}", follow_redirects=True)
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"cannot delete your own active administrator account", res.data)

            # Verify still exists in DB
            still_exists = get_user_by_id(admin_user["id"])
            self.assertIsNotNone(still_exists)
            client.get("/logout")

    # 26. Password Hashes Are Never Rendered in HTML
    def test_26_password_hashes_are_never_rendered(self):
        """26. Password hashes (e.g. scrypt/pbkdf2) are never rendered in HTML templates."""
        admin_user = get_user_by_username("test_admin")
        self.assertIsNotNone(admin_user)

        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res_users = client.get("/users")
            self.assertEqual(res_users.status_code, 200)
            self.assertNotIn(b"scrypt:", res_users.data)
            self.assertNotIn(b"pbkdf2:", res_users.data)

            res_edit = client.get(f"/users/edit/{admin_user['id']}")
            self.assertEqual(res_edit.status_code, 200)
            self.assertNotIn(b"scrypt:", res_edit.data)
            self.assertNotIn(b"pbkdf2:", res_edit.data)
            client.get("/logout")

    # 27. Disabled User Cannot Login
    def test_27_disabled_user_cannot_login(self):
        """27. Deactivated user (is_active=0) cannot authenticate locally or via session."""
        create_user(
            username="test_disabled_user",
            password="DisabledPassword123!",
            role="VIEWER",
            email="disabled@cybershield.test",
            is_active=0,
        )
        with self.client as client:
            res = client.post(
                "/login",
                data={"username": "test_disabled_user", "password": "DisabledPassword123!"},
                follow_redirects=True,
            )
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"disabled", res.data.lower())
            self.assertIsNone(session.get("user_id"))

    # 28. Last Seen & Activity Tracking
    def test_28_last_seen_and_activity_tracking(self):
        """28. User activity updates last_seen timestamp and computes metrics."""
        from database.user_helpers import update_user_last_seen, get_user_activity_metrics, get_user_by_username
        user = get_user_by_username("test_admin")
        self.assertIsNotNone(user)

        update_user_last_seen(user["id"])
        updated_user = get_user_by_id(user["id"])
        self.assertIsNotNone(updated_user.get("last_seen"))

        metrics = get_user_activity_metrics()
        self.assertGreaterEqual(metrics["total"], 1)
        self.assertGreaterEqual(metrics["active"], 1)
        self.assertGreaterEqual(metrics["online"], 1)

    # 29. Online / Offline Calculation
    def test_29_online_offline_calculation(self):
        """29. Activity within 5 min is ONLINE, > 5 min is OFFLINE."""
        from database.user_helpers import is_user_online
        from datetime import datetime, timedelta, timezone

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.assertTrue(is_user_online(now_str))

        ten_mins_ago = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertFalse(is_user_online(ten_mins_ago))
        self.assertFalse(is_user_online(None))

    # 30. Security Headers Present
    def test_30_security_headers_present(self):
        """30. Responses include X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and CSP."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src", res.headers.get("Content-Security-Policy", ""))

    # 31. Safe Error Handling
    def test_31_safe_error_handling(self):
        """31. Error pages (404, 403) do not expose Python stack traces or internal secrets."""
        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res_404 = client.get("/non-existent-random-page-12345")
            self.assertEqual(res_404.status_code, 404)
            self.assertNotIn(b"Traceback (most recent call last):", res_404.data)
            self.assertNotIn(b"sqlite3.OperationalError", res_404.data)
            client.get("/logout")

    # 32. Reports Do Not Expose User Passwords or Secrets
    def test_32_reports_do_not_expose_credentials(self):
        """32. Report generation does not leak user table data or secrets."""
        with self.client as client:
            client.post("/login", data={"username": "test_admin", "password": "AdminPassword123!"})
            res_json = client.get("/download-report-json")
            if res_json.status_code == 200:
                self.assertNotIn(b"password_hash", res_json.data)
                self.assertNotIn(b"scrypt:", res_json.data)
                self.assertNotIn(b"client_secret", res_json.data)
            client.get("/logout")


if __name__ == "__main__":
    unittest.main()
