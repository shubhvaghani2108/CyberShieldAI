import sqlite3
conn = sqlite3.connect("cybershield.db")
tables = conn.execute("""
SELECT name
FROM sqlite_master
WHERE type='table'
AND name != 'sqlite_sequence'
ORDER BY name
""").fetchall()
with open("sqlite_schema.txt", "w", encoding="utf-8") as f:
    for (table,) in tables:
        f.write(f"\n\n===== {table} =====\n")
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,)
        ).fetchone()
        if row and row[0]:
            f.write(row[0])
            f.write("\n")
conn.close()
print("Schema exported successfully to sqlite_schema.txt")
