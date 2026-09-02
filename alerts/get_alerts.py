from database.db_engine import get_db_connection


def get_alerts(ip):

    conn = get_db_connection()

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