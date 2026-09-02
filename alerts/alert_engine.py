import os
import sys
from datetime import datetime
from database.db_engine import get_db_connection

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from alerts.alert_rules import (
    check_headers,
    check_header_coverage,
    check_new_ports,
    check_new_vulnerabilities,
    check_ports,
    check_risk_score,
    check_score_drop,
    check_ssl,
    check_ssl_expiry,
    check_vulnerabilities,
    check_cves,
)
from alerts.save_alert import save_alert

DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def generate_alerts(target, risk=None, ssl=None, ports=None, headers=None, vulnerabilities=None, cves=None, ip=None):
    """
    Standard alert generator for static scan findings across both IP and URL targets.
    """
    alerts = []

    if risk:
        alerts.extend(check_risk_score(risk))
    if ssl:
        alerts.extend(check_ssl(ssl))
    if ports:
        alerts.extend(check_ports(ports))
    if headers:
        alerts.extend(check_headers(headers))
    if vulnerabilities:
        alerts.extend(check_vulnerabilities(vulnerabilities))
    if cves:
        alerts.extend(check_cves(cves))

    target_name = target or ip or "Unknown"
    ip_addr = ip or target or "Unknown"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for alert in alerts:
        save_alert(
            target=target_name,
            alert_type=alert.get("alert_type") or alert.get("title", "Security Alert"),
            severity=alert.get("severity", "Medium"),
            message=alert.get("message") or alert.get("description", ""),
            recommendation=alert.get("recommendation", ""),
            ip=ip_addr,
            title=alert.get("title"),
            description=alert.get("description"),
            created_at=now_str,
            scan_time=now_str,
        )

    return alerts



def process_monitoring_alerts(
    target: str,
    current_scan: dict,
    previous_scan: dict = None,
    delta: dict = None,
) -> list:
    """
    Core Monitoring Alert Pipeline:
    Evaluates scan changes and triggers alerts for:
    1. Security Score Drops
    2. New Open Port Found
    3. New Vulnerability Found
    4. SSL Certificate expires within 30 days
    5. Security Header Coverage decreases

    Stores generated alerts into the existing alerts table.
    """
    alerts = []
    if not current_scan:
        return alerts

    target_val = target or current_scan.get("url") or current_scan.get("ip") or "Unknown"
    ip = current_scan.get("ip") or target_val

    # Compute delta if not provided
    if delta is None:
        from scanner.scan_comparison_engine import compare_scans
        delta = compare_scans(current_scan, previous_scan)

    # 1. Security Score Drops
    curr_score = current_scan.get("security_score") if current_scan.get("security_score") is not None else current_scan.get("score")
    prev_score = previous_scan.get("security_score") if previous_scan and previous_scan.get("security_score") is not None else (previous_scan.get("score") if previous_scan else None)
    alerts.extend(check_score_drop(curr_score, prev_score, target=target_val))

    # 2. New Open Port Found
    new_ports = delta.get("new_ports", []) if delta else []
    alerts.extend(check_new_ports(new_ports, target=target_val))

    # 3. New Vulnerability Found
    new_vulns = delta.get("new_vulnerabilities", []) if delta else []
    alerts.extend(check_new_vulnerabilities(new_vulns, target=target_val))

    # 4. SSL Certificate expires within 30 days
    ssl_info = current_scan.get("ssl_data") or current_scan.get("ssl") or current_scan.get("tls")
    alerts.extend(check_ssl_expiry(ssl_info, target=target_val))

    # 5. Security Header Coverage decreases
    curr_headers = current_scan.get("headers")
    prev_headers = previous_scan.get("headers") if previous_scan else None
    alerts.extend(check_header_coverage(curr_headers, prev_headers, target=target_val))

    # Persist all alerts into database
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for alert in alerts:
        save_alert(
            target=target_val,
            alert_type=alert.get("alert_type") or alert.get("title", "Security Alert"),
            severity=alert.get("severity", "Medium"),
            message=alert.get("message") or alert.get("description", ""),
            recommendation=alert.get("recommendation", ""),
            ip=ip,
            title=alert.get("title"),
            description=alert.get("description"),
            created_at=now_str,
            scan_time=now_str,
        )

    return alerts


def get_monitoring_alerts(limit=50):
    """
    Retrieves recent alerts for the Monitoring Dashboard from the existing alerts table.
    Returns clean dictionaries with:
    - id
    - target
    - alert_type
    - severity
    - message
    - created_at
    """
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT 
                id,
                COALESCE(target, ip, 'Unknown') AS target,
                COALESCE(alert_type, title, 'Security Alert') AS alert_type,
                COALESCE(severity, 'Medium') AS severity,
                COALESCE(message, description, title, '') AS message,
                COALESCE(created_at, scan_time, datetime('now')) AS created_at
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[ERROR] Failed to fetch monitoring alerts: {e}")
        return []
    finally:
        conn.close()