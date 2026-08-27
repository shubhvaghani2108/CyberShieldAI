import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB)
cursor = conn.cursor()

print("="*60)
print("TABLES")
print("="*60)

cursor.execute("""
SELECT name
FROM sqlite_master
WHERE type='table'
ORDER BY name
""")

tables = cursor.fetchall()

for t in tables:
    print(t[0])

print("\n")

for t in tables:

    table = t[0]

    try:

        cursor.execute(f"SELECT COUNT(*) FROM {table}")

        count = cursor.fetchone()[0]

        print(f"{table} : {count}")

    except Exception as e:

        print(table, e)

conn.close()