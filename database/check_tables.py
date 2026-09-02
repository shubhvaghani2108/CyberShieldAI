from database.db_engine import get_db_connection

conn = get_db_connection()
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