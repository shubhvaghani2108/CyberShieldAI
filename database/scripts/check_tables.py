import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)

cursor = conn.cursor()

cursor.execute("""
SELECT name
FROM sqlite_master
WHERE type='table'
ORDER BY name
""")

tables = cursor.fetchall()

print("\nDATABASE TABLES\n")

for table in tables:
    print(table[0])

conn.close()