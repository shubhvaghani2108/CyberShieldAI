import sqlite3
import os

# ==========================================================
# DATABASE PATH
# ==========================================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


# ==========================================================
# DASHBOARD STATS
# ==========================================================

def get_dashboard_stats(latest_ip=None):
    """
    Build the stat-card numbers for the dashboard.

    FIX: this used to determine "the latest scan" by reading the newest
    row of `risk_summary`, while every other part of the app (get_latest_ip()
    in app.py, used by /ports, /vulnerabilities, /cves, /history, and the
    main dashboard tables) determines it from `scan_history` instead.
    Those two tables get written at different points in the scan
    pipeline (scan_history near the start, risk_summary at the very
    end), so whichever scan finished most recently didn't necessarily
    start most recently — the two "latest" pointers could point at two
    different targets, which is why the stat cards and the detail pages
    could disagree.

    Fix: the caller (app.py) now computes latest_ip once via
    get_latest_ip() and passes it in here, so every part of the
    dashboard agrees on the same target. If nothing is passed in (e.g.
    running this file standalone via `python database/dashboard_stats.py`),
    it falls back to deriving latest_ip from scan_history itself, matching
    app.py's own logic instead of risk_summary's.
    """

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    stats = {
        "latest_ip": "-",
        "latest_scan": "-",
        "total_assets": 0,
        "live_hosts": 0,
        "offline_hosts": 0,
        "avg_risk": 0,
        "risk_level": "Unknown",
        "open_ports": 0,
        "services": 0,
        "vulnerabilities": 0,
        "cves": 0,
    }

    # ======================================================
    # LATEST TARGET
    # ======================================================

    if not latest_ip:
        try:
            cur.execute("""
                SELECT target_ip
                FROM scan_history
                ORDER BY id DESC
                LIMIT 1
            """)
            row = cur.fetchone()
            latest_ip = row["target_ip"] if row else None
        except Exception as e:
            print("Latest IP Fallback Error:", e)
            latest_ip = None

    stats["latest_ip"] = latest_ip if latest_ip else "-"

    # ======================================================
    # TOTAL ASSETS & HOST STATUS (Current Live Scan Target)
    # ======================================================

    if latest_ip:
        try:
            cur.execute("""
                SELECT COUNT(DISTINCT target_ip)
                FROM host_status
                WHERE target_ip=?
            """, (latest_ip,))
            row = cur.fetchone()
            stats["total_assets"] = row[0] if row else 0
        except Exception as e:
            print("Total Assets Error:", e)

        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM host_status
                WHERE target_ip=? AND (status LIKE 'Alive%' OR status = 'Online' OR status = 'Up')
            """, (latest_ip,))
            row = cur.fetchone()
            stats["live_hosts"] = row[0] if row else 0
        except Exception as e:
            print("Live Hosts Error:", e)

        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM host_status
                WHERE target_ip=? AND (status LIKE 'Dead%' OR status LIKE 'Unreachable%' OR status = 'Offline' OR status = 'Down')
            """, (latest_ip,))
            row = cur.fetchone()
            stats["offline_hosts"] = row[0] if row else 0
        except Exception as e:
            print("Offline Hosts Error:", e)

    # ======================================================
    # LATEST SCAN TIME
    # Pulled from host_status for this specific target, since that's
    # what /ports and friends effectively treat as "when the current
    # target was last touched".
    # ======================================================

    if latest_ip:
        try:
            cur.execute("""
                SELECT scan_time
                FROM host_status
                WHERE target_ip=?
                ORDER BY id DESC
                LIMIT 1
            """, (latest_ip,))
            row = cur.fetchone()
            if row:
                stats["latest_scan"] = row["scan_time"]
        except Exception as e:
            print("Latest Scan Time Error:", e)

    # ======================================================
    # RISK (for the current latest_ip specifically, not just
    # whichever risk_summary row happens to be newest overall)
    # ======================================================

    if latest_ip:
        try:
            cur.execute("""
                SELECT total_score, risk_level
                FROM risk_summary
                WHERE ip=?
                ORDER BY id DESC
                LIMIT 1
            """, (latest_ip,))

            row = cur.fetchone()

            if row:
                stats["avg_risk"] = row["total_score"]
                stats["risk_level"] = row["risk_level"]

        except Exception as e:
            print("Risk Error:", e)

    # ======================================================
    # OPEN PORTS
    # ======================================================

    if latest_ip:

        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM ports
                WHERE id IN (
                    SELECT MAX(id) FROM ports WHERE ip=? GROUP BY port
                ) AND state='open'
            """, (latest_ip,))

            row = cur.fetchone()
            stats["open_ports"] = row[0] if row else 0

        except Exception as e:
            print("Ports Error:", e)

    # ======================================================
    # SERVICES
    # ======================================================

    if latest_ip:

        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM service_versions
                WHERE id IN (
                    SELECT MAX(id) FROM service_versions WHERE ip=? GROUP BY port
                )
            """, (latest_ip,))

            row = cur.fetchone()
            stats["services"] = row[0] if row else 0

        except Exception as e:
            print("Services Error:", e)

    # ======================================================
    # VULNERABILITIES
    # ======================================================

    if latest_ip:

        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM vulnerabilities
                WHERE id IN (
                    SELECT MAX(id) FROM vulnerabilities WHERE ip=? GROUP BY port, risk, service
                )
            """, (latest_ip,))

            row = cur.fetchone()
            stats["vulnerabilities"] = row[0] if row else 0

        except Exception as e:
            print("Vulnerability Error:", e)

    # ======================================================
    # CVEs
    # ======================================================

    if latest_ip:

        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM cves
                WHERE id IN (
                    SELECT MAX(id) FROM cves WHERE ip=? GROUP BY cve_id, port
                )
            """, (latest_ip,))

            row = cur.fetchone()
            stats["cves"] = row[0] if row else 0

        except Exception as e:
            print("CVE Error:", e)

    conn.close()

    return stats



# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    from pprint import pprint

    print("\n" + "=" * 60)
    print("CyberShieldAI Dashboard Statistics")
    print("=" * 60)

    pprint(get_dashboard_stats())