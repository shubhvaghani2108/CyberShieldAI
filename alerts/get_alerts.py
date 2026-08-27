import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def get_alerts(ip):

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT *
        FROM alerts
        WHERE ip=?
        ORDER BY id DESC
        """,
        (ip,),
    ).fetchall()

    conn.close()

    return rows