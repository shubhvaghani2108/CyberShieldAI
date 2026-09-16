from database.db_engine import get_db_connection


_has_ensured_user_id_col = False

def _ensure_user_id_col(conn):
    global _has_ensured_user_id_col
    if _has_ensured_user_id_col:
        return
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(alerts)")
        cols = [r[1] for r in cur.fetchall()]
        if cols and "user_id" not in cols:
            cur.execute("ALTER TABLE alerts ADD COLUMN user_id INTEGER DEFAULT 1")
            conn.commit()
        _has_ensured_user_id_col = True
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


import time

_ALERT_STATS_CACHE = {}
_ALERT_STATS_CACHE_TTL = 15  # seconds

def get_alert_statistics(user_id=None):
    now = time.time()
    cache_key = f"alert_stats_{user_id}"
    cached = _ALERT_STATS_CACHE.get(cache_key)
    if cached and (now - cached["time"] < _ALERT_STATS_CACHE_TTL):
        return dict(cached["data"])

    conn = get_db_connection()
    _ensure_user_id_col(conn)
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    try:
        if user_id is not None:
            rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS total
                FROM alerts
                WHERE user_id = ? OR user_id IS NULL
                GROUP BY severity
                """,
                (user_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS total
                FROM alerts
                GROUP BY severity
                """
            ).fetchall()

        for r in rows:
            sev = (r["severity"] or "").capitalize()
            if sev in stats:
                stats[sev] = r["total"] or 0
    except Exception:
        pass
    finally:
        conn.close()

    _ALERT_STATS_CACHE[cache_key] = {"time": now, "data": dict(stats)}
    return stats