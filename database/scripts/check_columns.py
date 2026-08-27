import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

tables = [
    "host_status",
    "ports",
    "service_versions",
    "vulnerabilities",
    "cves",
    "risk_summary"
]

for table in tables:
    print("\n" + "=" * 60)
    print(table.upper())
    print("=" * 60)

    cursor.execute(f"PRAGMA table_info({table})")

    for col in cursor.fetchall():
        print(col)

conn.close()