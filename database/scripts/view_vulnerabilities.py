import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute(
    "SELECT * FROM vulnerabilities"
)

for row in cursor.fetchall():
    print(row)

conn.close()