import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.app import app
from database.db_helpers import get_db_connection
from database.user_helpers import (
    init_users_table,
    create_user,
    get_user_by_username,
    update_user_last_seen,
    update_last_login,
    is_user_online,
    get_user_activity_metrics,
    list_users,
)


class ActiveUserTrackingTestCase(unittest.TestCase):
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

        # Seed test admin and standard user
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username LIKE 'track_%'")
        conn.commit()
        conn.close()

        create_user(
            username="track_admin",
            password="AdminPassword123!",
            role="ADMIN",
            email="admin_track@example.com",
            is_active=1,
        )
        create_user(
            username="track_user",
            password="UserPassword123!",
            role="USER",
            email="user_track@example.com",
            is_active=1,
        )

    def tearDown(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username LIKE 'track_%'")
        conn.commit()
        conn.close()
        self.app_context.pop()

    def test_01_successful_login_updates_last_login(self):
        """Successful login records UTC timestamp in last_login."""
        user_before = get_user_by_username("track_user")
        self.assertIsNone(user_before.get("last_login"))

        resp = self.client.post("/login", data={
            "username": "track_user",
            "password": "UserPassword123!",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        user_after = get_user_by_username("track_user")
        self.assertIsNotNone(user_after.get("last_login"))

    def test_02_successful_login_updates_last_seen(self):
        """Successful login records UTC timestamp in last_seen and sets is_active=1."""
        user_before = get_user_by_username("track_user")
        self.assertIsNone(user_before.get("last_seen"))

        resp = self.client.post("/login", data={
            "username": "track_user",
            "password": "UserPassword123!",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        user_after = get_user_by_username("track_user")
        self.assertIsNotNone(user_after.get("last_seen"))
        self.assertEqual(user_after.get("is_active"), 1)

    def test_03_active_user_detection(self):
        """User with last_seen within 5 minutes is classified as active / online."""
        now_utc = datetime.now(timezone.utc)
        recent_ts = (now_utc - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")

        self.assertTrue(is_user_online(recent_ts))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_seen = ? WHERE username = 'track_user'", (recent_ts,))
        conn.commit()
        conn.close()

        metrics = get_user_activity_metrics()
        self.assertGreaterEqual(metrics["active_users"], 1)

    def test_04_inactive_user_detection(self):
        """User with last_seen older than 5 minutes is classified as inactive / offline."""
        now_utc = datetime.now(timezone.utc)
        old_ts = (now_utc - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

        self.assertFalse(is_user_online(old_ts))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_seen = ? WHERE username = 'track_user'", (old_ts,))
        conn.commit()
        conn.close()

        users = list_users()
        track_user = next((u for u in users if u["username"] == "track_user"), None)
        self.assertIsNotNone(track_user)
        self.assertFalse(track_user["is_online"])

    def test_05_admin_can_view_statistics(self):
        """Admin can access /users and /admin and view user metrics."""
        admin = get_user_by_username("track_admin")
        with self.client.session_transaction() as sess:
            sess["user_id"] = admin["id"]
            sess["username"] = admin["username"]
            sess["role"] = "ADMIN"
            sess["email"] = admin["email"]

        # Access /admin dashboard
        resp_admin = self.client.get("/admin", follow_redirects=True)
        self.assertEqual(resp_admin.status_code, 200)
        self.assertIn(b"Total Users", resp_admin.data)
        self.assertIn(b"Active Users", resp_admin.data)
        self.assertIn(b"Total Scans", resp_admin.data)
        self.assertIn(b"Total Vulnerabilities", resp_admin.data)

        # Access /users directly
        resp_users = self.client.get("/users")
        self.assertEqual(resp_users.status_code, 200)
        self.assertIn(b"Total Users", resp_users.data)
        self.assertIn(b"Active Accounts", resp_users.data)
        self.assertIn(b"Offline Users", resp_users.data)
        self.assertIn(b"Last Seen / Login", resp_users.data)

    def test_06_normal_user_cannot_access_admin(self):
        """Standard USER cannot access /admin route and receives 403 / redirect."""
        user = get_user_by_username("track_user")
        with self.client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess["username"] = user["username"]
            sess["role"] = "USER"
            sess["email"] = user["email"]

        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 403)

    def test_07_normal_user_cannot_access_users_management(self):
        """Standard USER cannot access /users route and receives 403 / redirect."""
        user = get_user_by_username("track_user")
        with self.client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess["username"] = user["username"]
            sess["role"] = "USER"
            sess["email"] = user["email"]

        resp = self.client.get("/users")
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
