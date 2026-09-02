from database.db_engine import get_db_connection

def create_monitoring_table():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS monitored_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_frequency INTEGER DEFAULT 24,
        enabled INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()
    print("monitored_targets table created successfully")


if __name__ == "__main__":
    create_monitoring_table()
