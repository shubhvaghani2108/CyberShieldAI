import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)

cursor = conn.cursor()

cursor.execute("""

SELECT *

FROM technology_detection

ORDER BY id DESC

LIMIT 10

""")

rows = cursor.fetchall()

print()

print("="*60)

print("TECHNOLOGY DETECTION")

print("="*60)

for row in rows:

    print(row)

conn.close()