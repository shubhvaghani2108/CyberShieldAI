from datetime import datetime
from database.db_helpers import get_db_connection


def save_security_headers(ip, url, headers_result, scan_id=None, scan_time=None):
    if not headers_result:
        return

    conn = get_db_connection()
    if not scan_time:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        header_map = {
            "Strict-Transport-Security": "Enable HSTS header",
            "Content-Security-Policy": "Implement CSP policy",
            "X-Frame-Options": "Enable clickjacking protection",
            "X-Content-Type-Options": "Prevent MIME sniffing",
            "Referrer-Policy": "Configure referrer policy",
            "Permissions-Policy": "Restrict browser features",
        }

        for header_name, recommendation in header_map.items():
            present = headers_result.get(header_name, False)
            status = "Present" if present else "Missing"
            risk = "Low" if present else "Medium"

            conn.execute(
                """
                INSERT INTO security_headers
                (
                    scan_id,
                    ip,
                    url,
                    header_name,
                    status,
                    risk,
                    recommendation,
                    scan_time
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    ip,
                    url,
                    header_name,
                    status,
                    risk,
                    recommendation,
                    scan_time,
                ),
            )

        conn.commit()
        print(f"[OK] Security Headers Saved [scan_id={scan_id}]")

    except Exception as e:
        conn.rollback()
        print("[ERROR] Security Header Save Error:", e)

    finally:
        conn.close()


def get_previous_security_headers(ip, current_scan_time=None):
    conn = get_db_connection()

    if current_scan_time:
        rows = conn.execute(
            """
            SELECT header_name, status, risk, recommendation, scan_time
            FROM security_headers
            WHERE ip = ?
              AND scan_time < ?
            ORDER BY id DESC
            """,
            (ip, current_scan_time),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT header_name, status, risk, recommendation, scan_time
            FROM security_headers
            WHERE ip = ?
            ORDER BY id DESC
            LIMIT 6 OFFSET 6
            """,
            (ip,),
        ).fetchall()

    conn.close()
    return rows