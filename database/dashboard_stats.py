from database.db_engine import get_db_connection


# ==========================================================
# DASHBOARD STATS
# ==========================================================

def get_dashboard_stats(latest_ip=None, scan_id=None):
    """
    Build the stat-card numbers for the dashboard.
    When scan_id is provided, queries the exact scan dataset for complete multi-user isolation.
    """

    conn = get_db_connection()
    cur = conn.cursor()

    stats = {
        "latest_ip": latest_ip if latest_ip else "-",
        "latest_scan": "-",
        "total_assets": 0,
        "live_hosts": 0,
        "offline_hosts": 0,
        "avg_risk": 0,
        "risk_level": "No Scan Yet",
        "open_ports": 0,
        "services": 0,
        "vulnerabilities": 0,
        "cves": 0,
    }

    if not latest_ip or latest_ip == "-":
        return stats

    # ======================================================
    # TOTAL ASSETS & HOST STATUS
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
    # ======================================================

    if scan_id:
        try:
            cur.execute("""
                SELECT scan_time
                FROM host_status
                WHERE scan_id=?
                ORDER BY id DESC
                LIMIT 1
            """, (scan_id,))
            row = cur.fetchone()
            if row:
                stats["latest_scan"] = row["scan_time"]
        except Exception as e:
            print("Scan Time Error:", e)
    elif latest_ip:
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
    # RISK
    # ======================================================

    if scan_id:
        try:
            cur.execute("""
                SELECT total_score, risk_level
                FROM risk_summary
                WHERE scan_id=?
                ORDER BY id DESC
                LIMIT 1
            """, (scan_id,))
            row = cur.fetchone()
            if row:
                stats["avg_risk"] = row["total_score"]
                stats["risk_level"] = row["risk_level"]
        except Exception as e:
            print("Risk Error:", e)
    elif latest_ip:
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

    if scan_id:
        try:
            cur.execute("""
                SELECT COUNT(DISTINCT port)
                FROM ports
                WHERE scan_id=? AND (state='open' OR state IS NULL OR state='')
            """, (scan_id,))
            row = cur.fetchone()
            stats["open_ports"] = row[0] if row else 0
        except Exception as e:
            print("Ports Error:", e)
    elif latest_ip:
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

    if scan_id:
        try:
            cur.execute("""
                SELECT COUNT(DISTINCT port)
                FROM service_versions
                WHERE scan_id=?
            """, (scan_id,))
            row = cur.fetchone()
            stats["services"] = row[0] if row else 0
        except Exception as e:
            print("Services Error:", e)
    elif latest_ip:
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

    if scan_id:
        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM vulnerabilities
                WHERE scan_id=?
            """, (scan_id,))
            row = cur.fetchone()
            stats["vulnerabilities"] = row[0] if row else 0
        except Exception as e:
            print("Vulnerability Error:", e)
    elif latest_ip:
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

    if scan_id:
        try:
            cur.execute("""
                SELECT COUNT(*)
                FROM cves
                WHERE scan_id=?
            """, (scan_id,))
            row = cur.fetchone()
            stats["cves"] = row[0] if row else 0
        except Exception as e:
            print("CVE Error:", e)
    elif latest_ip:
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