import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def get_assets(latest_ip=None, latest_only=False):
    """
    Retrieves the asset inventory.
    Guarantees only the MOST RECENT scan data is returned for each host (deduplicated),
    and optionally filters to only the latest scanned IP target if requested.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if latest_only and not latest_ip:
        try:
            cur.execute("SELECT target_ip FROM scan_history ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if not row:
                cur.execute("SELECT target_ip FROM host_status ORDER BY id DESC LIMIT 1")
                row = cur.fetchone()
            if row:
                latest_ip = row["target_ip"]
        except Exception:
            pass

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