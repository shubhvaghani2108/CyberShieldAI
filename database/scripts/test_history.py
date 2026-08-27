import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
)

tables = cursor.fetchall()

for table in tables:
    print(table)

conn.close()