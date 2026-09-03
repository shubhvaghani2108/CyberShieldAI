#!/usr/bin/env python3
"""
CyberShieldAI — Administrator Account Management Script

Usage:
  python scripts/create_admin.py
  python scripts/create_admin.py --username admin --role ADMIN --email admin@cybershield.local
  python scripts/create_admin.py --username analyst1 --role ANALYST
"""

import argparse
import getpass
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.user_helpers import (
    init_users_table,
    get_user_by_username,
    create_user,
    update_user_password,
    get_db_connection,
)


def create_or_update_admin(username="admin", password=None, email="", role="ADMIN"):
    init_users_table()

    username = (username or "").strip()
    if not username:
        print("[ERROR] Username cannot be empty.")
        return False

    if not password:
        password = getpass.getpass(f"Enter password for user '{username}': ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[ERROR] Passwords do not match. Aborted.")
            return False

    password = password.strip()
    if len(password) < 4:
        print("[ERROR] Password must be at least 4 characters long.")
        return False

    role = (role or "ADMIN").strip().upper()
    email = (email or f"{username}@cybershield.local").strip()

    existing = get_user_by_username(username)
    if existing:
        update_user_password(username, password)
        # Also ensure role, email, and is_active are updated
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users
                SET role = ?, email = ?, is_active = 1
                WHERE id = ?
                """,
                (role, email, existing["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        print(f"[SUCCESS] User '{username}' updated successfully with role '{role}'.")
        return True
    else:
        create_user(username=username, password=password, role=role, email=email, is_active=1)
        print(f"[SUCCESS] User '{username}' created successfully with role '{role}'.")
        return True


def main():
    parser = argparse.ArgumentParser(description="Create or reset CyberShieldAI local user account.")
    parser.add_argument("--username", "-u", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", "-p", default=None, help="Password (prompted securely if omitted)")
    parser.add_argument("--email", "-e", default="", help="User email address")
    parser.add_argument("--role", "-r", default="ADMIN", choices=["ADMIN", "ANALYST", "OPERATOR", "USER"], help="User role")

    args = parser.parse_args()
    success = create_or_update_admin(
        username=args.username,
        password=args.password,
        email=args.email,
        role=args.role,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
