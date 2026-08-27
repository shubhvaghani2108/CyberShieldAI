import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def _ensure_alerts_table_columns():
    """
    Ensures that existing alerts table has all required columns:
    target, alert_type, severity, message, created_at, ip, title, description, recommendation, scan_time
    without creating duplicate tables.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                alert_type TEXT,
                severity TEXT,
                message TEXT,
                created_at TEXT,
                ip TEXT,
                title TEXT,
                description TEXT,
                recommendation TEXT,
                scan_time TEXT
            )
            """
        )
        cursor.execute("PRAGMA table_info(alerts)")
        existing_cols = {r[1] for r in cursor.fetchall()}

        needed_cols = {
            "target": "TEXT",
            "alert_type": "TEXT",
            "message": "TEXT",
            "created_at": "TEXT",
            "ip": "TEXT",
            "title": "TEXT",
            "description": "TEXT",
            "recommendation": "TEXT",
            "scan_time": "TEXT",
        }

        for col_name, col_type in needed_cols.items():
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ALERTS DB INIT ERROR] {e}")


_ensure_alerts_table_columns()


def save_alert(
    target=None,
    alert_type=None,
    severity="Medium",
    message=None,
    recommendation="",
    ip=None,
    title=None,
    description=None,
    created_at=None,
    scan_time=None,
    **kwargs,
):
    """
    Saves an alert into the existing alerts table.
    Supports both new schema (target, alert_type, severity, message, created_at)
    and legacy calls (ip, severity, title, description, recommendation).
    """
    _ensure_alerts_table_columns()

    # Normalize fields across different calling conventions
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_time = created_at or scan_time or now_str

    # If called positional with legacy signature (ip, severity, title, description, recommendation)
    if message is None and description is not None:
        message = description
    elif message is None and title is not None:
        message = title

    if alert_type is None and title is not None:
        alert_type = title
    elif alert_type is None:
        alert_type = "Security Alert"

    final_target = target or ip or "Unknown"
    final_ip = ip or target or "Unknown"
    final_title = title or alert_type
    final_desc = description or message or ""
    final_msg = message or description or final_title
    final_rec = recommendation or ""

    conn = sqlite3.connect(DB_FILE)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alerts(
                target,
                alert_type,
                severity,
                message,
                created_at,
                ip,
                title,
                description,
                recommendation,
                scan_time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                final_target,
                alert_type,
                severity,
                final_msg,
                alert_time,
                final_ip,
                final_title,
                final_desc,
                final_rec,
                alert_time,
            ),
        )
        conn.commit()
        alert_id = cur.lastrowid
        print(f"[OK] Alert Saved: [{severity}] {alert_type} - {final_msg[:60]}")

        # Dispatch email alert if configured
        try:
            from alerts.email_notifier import dispatch_alert_email
            dispatch_alert_email({
                "id": alert_id,
                "target": final_target,
                "alert_type": alert_type,
                "severity": severity,
                "message": final_msg,
                "recommendation": final_rec,
                "created_at": alert_time,
                "ip": final_ip,
            })
        except Exception as e:
            print(f"[DISPATCH ERROR] {e}")

        return alert_id
    finally:
        conn.close()
