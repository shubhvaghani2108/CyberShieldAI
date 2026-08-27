import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)

cur = conn.cursor()

cur.execute("""
SELECT name
FROM sqlite_master
WHERE type='table'
ORDER BY name;
""")

print("\n========== DATABASE TABLES ==========\n")

for table in cur.fetchall():
    print(table[0])

conn.close()