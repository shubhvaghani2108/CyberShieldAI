import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def calculate_risk(target_ip, scan_id=None):
    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()

    try:
        cursor.execute("PRAGMA table_info(risk_summary)")
        cols = [r[1] for r in cursor.fetchall()]
        if "scan_id" not in cols:
            try:
                cursor.execute("ALTER TABLE risk_summary ADD COLUMN scan_id TEXT")
            except Exception:
                pass

        if scan_id:
            # Count vulnerabilities specifically for this scan_id
            cursor.execute("""
                SELECT 
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'critical' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'high' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'medium' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'low' THEN 1 ELSE 0 END), 0)
                FROM vulnerabilities
                WHERE ip = ? AND scan_id = ?
            """, (target_ip, scan_id))
        else:
            # Count active/latest unique vulnerabilities per port & service to avoid duplicate historical inflation
            cursor.execute("""
                SELECT 
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'critical' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'high' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'medium' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN LOWER(risk) = 'low' THEN 1 ELSE 0 END), 0)
                FROM vulnerabilities
                WHERE ip = ? AND id IN (
                    SELECT MAX(id) FROM vulnerabilities WHERE ip = ? GROUP BY port, service
                )
            """, (target_ip, target_ip))

        row = cursor.fetchone()
        critical_count = int(row[0]) if row else 0
        high_count = int(row[1]) if row else 0
        medium_count = int(row[2]) if row else 0
        low_count = int(row[3]) if row else 0

        total_score = (
            critical_count * 10 +
            high_count * 7 +
            medium_count * 4 +
            low_count * 1
        )

        if total_score >= 25:
            risk_level = "Critical"
        elif total_score >= 15:
            risk_level = "High"
        elif total_score >= 5:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO risk_summary
            (
                scan_id,
                ip,
                critical_count,
                high_count,
                medium_count,
                low_count,
                total_score,
                risk_level,
                scan_time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            target_ip,
            critical_count,
            high_count,
            medium_count,
            low_count,
            total_score,
            risk_level,
            scan_time
        ))

        conn.commit()

        print(f"""
IP: {target_ip} [scan_id={scan_id}]
Critical: {critical_count}
High: {high_count}
Medium: {medium_count}
Low: {low_count}
Total Score: {total_score}
Risk Level: {risk_level}
""")

        print("[+] Risk Summary Saved Successfully")
        return {
            "scan_id": scan_id,
            "ip": target_ip,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "total_score": total_score,
            "risk_level": risk_level,
            "scan_time": scan_time,
        }

    except Exception as e:
        print("[!] Risk calculation error:", e)
        return None

    finally:
        conn.close()


if __name__ == "__main__":
    target = input("Enter target IP: ").strip()
    calculate_risk(target)