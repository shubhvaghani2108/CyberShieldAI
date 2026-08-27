import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS service_versions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INTEGER,
    service TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    scan_time TEXT
)
""")

conn.commit()
conn.close()

print("Service Version Table Created Successfully")