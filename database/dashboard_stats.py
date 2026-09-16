from database.db_engine import get_db_connection


# ==========================================================
# DASHBOARD STATS
# ==========================================================

def get_dashboard_stats(latest_ip=None, scan_id=None, user_id=None, precomputed=None):
    """
    Build the stat-card numbers for the dashboard.
    When scan_id is provided, queries the exact scan dataset for complete multi-user isolation.
    If user_id is provided, filters global counts to the specific user.
    If precomputed dict is provided (from get_ip_scan_context), skips redundant DB round-trips.
    """

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

    pre = precomputed or {}

    # 1. TOTAL ASSETS & HOST STATUS (Single aggregated query)
    conn = get_db_connection()
    try:
        cur = conn.cursor()

        base_where = "WHERE target_ip=?"
        params = [latest_ip]
        if user_id:
            base_where += " AND user_id=?"
            params.append(user_id)

        try:
            cur.execute(f"""
                SELECT 
                    COUNT(DISTINCT target_ip) AS total_assets,
                    COALESCE(SUM(CASE WHEN status LIKE 'Alive%' OR status = 'Online' OR status = 'Up' THEN 1 ELSE 0 END), 0) AS live_hosts,
                    COALESCE(SUM(CASE WHEN status LIKE 'Dead%' OR status LIKE 'Unreachable%' OR status = 'Offline' OR status = 'Down' THEN 1 ELSE 0 END), 0) AS offline_hosts
                FROM host_status
                {base_where}
            """, params)
            row = cur.fetchone()
            if row:
                stats["total_assets"] = row[0] or 0
                stats["live_hosts"] = row[1] or 0
                stats["offline_hosts"] = row[2] or 0
        except Exception as e:
            print("Host Status Counts Error:", e)

        # 2. LATEST SCAN TIME
        if "host" in pre and pre["host"]:
            stats["latest_scan"] = pre["host"]["scan_time"] if "scan_time" in pre["host"].keys() else "-"
        elif scan_id:
            try:
                cur.execute("SELECT scan_time FROM host_status WHERE scan_id=? ORDER BY id DESC LIMIT 1", (scan_id,))
                row = cur.fetchone()
                if row:
                    stats["latest_scan"] = row["scan_time"]
            except Exception as e:
                print("Scan Time Error:", e)
        elif latest_ip:
            try:
                cur.execute("SELECT scan_time FROM host_status WHERE target_ip=? ORDER BY id DESC LIMIT 1", (latest_ip,))
                row = cur.fetchone()
                if row:
                    stats["latest_scan"] = row["scan_time"]
            except Exception as e:
                print("Latest Scan Time Error:", e)

        # 3. RISK
        if "risk" in pre and pre["risk"]:
            stats["avg_risk"] = pre["risk"]["total_score"] or 0
            stats["risk_level"] = pre["risk"]["risk_level"] or "Low"
        elif scan_id:
            try:
                cur.execute("SELECT total_score, risk_level FROM risk_summary WHERE scan_id=? ORDER BY id DESC LIMIT 1", (scan_id,))
                row = cur.fetchone()
                if row:
                    stats["avg_risk"] = row["total_score"]
                    stats["risk_level"] = row["risk_level"]
            except Exception as e:
                print("Risk Error:", e)
        elif latest_ip:
            try:
                cur.execute("SELECT total_score, risk_level FROM risk_summary WHERE ip=? ORDER BY id DESC LIMIT 1", (latest_ip,))
                row = cur.fetchone()
                if row:
                    stats["avg_risk"] = row["total_score"]
                    stats["risk_level"] = row["risk_level"]
            except Exception as e:
                print("Risk Error:", e)

        # 4. OPEN PORTS
        if "ports" in pre:
            stats["open_ports"] = sum(1 for p in pre["ports"] if (p["state"] or "open").lower() == "open")
        elif scan_id:
            try:
                cur.execute("SELECT COUNT(DISTINCT port) FROM ports WHERE scan_id=? AND (state='open' OR state IS NULL OR state='')", (scan_id,))
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

        # 5. SERVICES
        if "services" in pre:
            stats["services"] = len(pre["services"])
        elif scan_id:
            try:
                cur.execute("SELECT COUNT(DISTINCT port) FROM service_versions WHERE scan_id=?", (scan_id,))
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

        # 6. VULNERABILITIES
        if "vulnerabilities" in pre:
            stats["vulnerabilities"] = len(pre["vulnerabilities"])
        elif scan_id:
            try:
                cur.execute("SELECT COUNT(*) FROM vulnerabilities WHERE scan_id=?", (scan_id,))
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

        # 7. CVEs
        if "cves" in pre:
            stats["cves"] = len(pre["cves"])
        elif scan_id:
            try:
                cur.execute("SELECT COUNT(*) FROM cves WHERE scan_id=?", (scan_id,))
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
    finally:
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