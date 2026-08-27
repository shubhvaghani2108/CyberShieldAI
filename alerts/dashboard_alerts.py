import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def get_recent_alerts(limit=10):

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    conn.close()

    return rows


def get_alert_statistics():

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    stats = {}

    for severity in ["Critical", "High", "Medium", "Low"]:

        row = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM alerts
            WHERE severity=?
            """,
            (severity,),
        ).fetchone()

        stats[severity] = row["total"]

    conn.close()

    return stats