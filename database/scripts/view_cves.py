import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute("SELECT * FROM cves")
rows = cursor.fetchall()

print("=" * 60)
print("CVES")
print("=" * 60)
for row in rows:
    print(row)

conn.close()
