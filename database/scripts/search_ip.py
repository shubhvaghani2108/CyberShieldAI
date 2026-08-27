import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

ip = input("Enter IP: ")

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute(
    "SELECT * FROM ports WHERE ip = ?",
    (ip,)
)

rows = cursor.fetchall()

if rows:
    for row in rows:
        print(row)
else:
    print("No ports found for this IP")

conn.close()