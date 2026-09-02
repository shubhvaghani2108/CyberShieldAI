from database.db_engine import get_db_connection


def _ensure_user_id_col(conn):
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(alerts)")
        cols = [r[1] for r in cur.fetchall()]
        if cols and "user_id" not in cols:
            cur.execute("ALTER TABLE alerts ADD COLUMN user_id INTEGER DEFAULT 1")
            conn.commit()
    except Exception:
        pass


def get_recent_alerts(limit=10, user_id=None):
    conn = get_db_connection()
    _ensure_user_id_col(conn)
    try:
        if user_id is not None:
            rows = conn.execute(
                """
                SELECT *
                FROM alerts
                WHERE user_id = ? OR user_id IS NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    except Exception:
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


def get_alert_statistics(user_id=None):
    conn = get_db_connection()
    _ensure_user_id_col(conn)
    stats = {}
    for severity in ["Critical", "High", "Medium", "Low"]:
        try:
            if user_id is not None:
                row = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM alerts
                    WHERE severity=? AND (user_id = ? OR user_id IS NULL)
                    """,
                    (severity, user_id),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM alerts
                    WHERE severity=?
                    """,
                    (severity,),
                ).fetchone()
        except Exception:
            row = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM alerts
                WHERE severity=?
                """,
                (severity,),
            ).fetchone()
        stats[severity] = row["total"] if row else 0
    conn.close()
    return stats