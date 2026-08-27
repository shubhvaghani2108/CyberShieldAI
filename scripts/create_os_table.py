import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS os_info(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    os_name TEXT,
    device_type TEXT,
    os_details TEXT,
    scan_time TEXT
)
""")

conn.commit()
conn.close()

print("OS Detection Table Created Successfully")