from database.db_engine import get_db_connection


def get_assets(latest_ip=None, latest_only=False, user_id=None):
    """
    Retrieves the asset inventory.
    Guarantees only the MOST RECENT scan data is returned for each host (deduplicated),
    and optionally filters to only the latest scanned IP target or user if requested.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    if latest_only and not latest_ip:
        try:
            if user_id is not None:
                cur.execute("SELECT target_ip FROM scan_history WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
            else:
                cur.execute("SELECT target_ip FROM scan_history ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if not row:
                if user_id is not None:
                    cur.execute("SELECT target_ip FROM host_status WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
                else:
                    cur.execute("SELECT target_ip FROM host_status ORDER BY id DESC LIMIT 1")
                row = cur.fetchone()
            if row:
                latest_ip = row["target_ip"]
        except Exception:
            pass

    if user_id is not None:
        query = """
        SELECT
            h.target_ip,
            h.status,
            h.scan_time,
            IFNULL(r.risk_level, 'Unknown') AS risk_level,
            IFNULL(r.total_score, 0) AS total_score
        FROM (
            SELECT target_ip, status, scan_time, id
            FROM host_status
            WHERE user_id = ? AND id IN (
                SELECT MAX(id)
                FROM host_status
                WHERE user_id = ?
                GROUP BY target_ip
            )
        ) h
        LEFT JOIN (
            SELECT ip, risk_level, total_score, id
            FROM risk_summary
            WHERE id IN (
                SELECT MAX(id)
                FROM risk_summary
                GROUP BY ip
            )
        ) r ON h.target_ip = r.ip
        """
        params = [user_id, user_id]
    else:
        query = """
        SELECT
            h.target_ip,
            h.status,
            h.scan_time,
            IFNULL(r.risk_level, 'Unknown') AS risk_level,
            IFNULL(r.total_score, 0) AS total_score
        FROM (
            SELECT target_ip, status, scan_time, id
            FROM host_status
            WHERE id IN (
                SELECT MAX(id)
                FROM host_status
                GROUP BY target_ip
            )
        ) h
        LEFT JOIN (
            SELECT ip, risk_level, total_score, id
            FROM risk_summary
            WHERE id IN (
                SELECT MAX(id)
                FROM risk_summary
                GROUP BY ip
            )
        ) r ON h.target_ip = r.ip
        """
        params = []

    if latest_ip:
        query += " WHERE h.target_ip = ? "
        params.append(latest_ip)

    query += " ORDER BY h.id DESC "

    if latest_only:
        query += " LIMIT 1 "

    cur.execute(query, params)
    assets = cur.fetchall()
    conn.close()

    return assets