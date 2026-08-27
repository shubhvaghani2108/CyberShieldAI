import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute(
    """
    SELECT * FROM scan_history ORDER BY id DESC
    """
)

rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()