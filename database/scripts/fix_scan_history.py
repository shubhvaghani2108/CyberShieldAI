import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS scan_history")

cursor.execute(
    """
CREATE TABLE scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""
)

conn.commit()
conn.close()

print("scan_history fixed successfully")
