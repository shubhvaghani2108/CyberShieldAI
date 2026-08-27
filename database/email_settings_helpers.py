import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def _get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_email_settings_table():
    """
    Initializes email_settings table in cybershield.db.
    """
    conn = _get_conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                smtp_server TEXT DEFAULT '',
                smtp_port INTEGER DEFAULT 587,
                smtp_user TEXT DEFAULT '',
                smtp_password TEXT DEFAULT '',
                from_email TEXT DEFAULT '',
                recipient_email TEXT DEFAULT '',
                use_tls INTEGER DEFAULT 1,
                use_ssl INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 0,
                alert_score_drop INTEGER DEFAULT 1,
                alert_new_vuln INTEGER DEFAULT 1,
                alert_critical INTEGER DEFAULT 1,
                alert_ssl_expiry INTEGER DEFAULT 1,
                alert_new_port INTEGER DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Check if default row exists
        row = conn.execute("SELECT id FROM email_settings WHERE id = 1").fetchone()
        if not row:
            conn.execute(
                """
                INSERT INTO email_settings (
                    id, smtp_server, smtp_port, smtp_user, smtp_password,
                    from_email, recipient_email, use_tls, use_ssl, enabled,
                    alert_score_drop, alert_new_vuln, alert_critical,
                    alert_ssl_expiry, alert_new_port
                )
                VALUES (1, 'smtp.gmail.com', 587, '', '', '', '', 1, 0, 0, 1, 1, 1, 1, 1)
                """
            )
        conn.commit()
    finally:
        conn.close()


init_email_settings_table()


def get_email_settings() -> dict:
    """
    Retrieves the email and SMTP settings.
    """
    init_email_settings_table()
    conn = _get_conn()
    try:
        row = conn.execute("SELECT * FROM email_settings WHERE id = 1").fetchone()
        env_from = os.environ.get("EMAIL_FROM", "").strip() or "defenderr0809@gmail.com"
        env_user = os.environ.get("SMTP_USERNAME", "").strip() or env_from
        env_recip = os.environ.get("ALERT_RECIPIENT", "").strip() or "smvaghani2005@gmail.com"
        
        if row:
            d = dict(row)
            if not d.get("from_email"):
                d["from_email"] = env_from
            if not d.get("smtp_user"):
                d["smtp_user"] = env_user
            if not d.get("recipient_email"):
                d["recipient_email"] = env_recip
            return d

        return {
            "id": 1,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_user": env_user,
            "smtp_password": "",
            "from_email": env_from,
            "recipient_email": env_recip,
            "use_tls": 1,
            "use_ssl": 0,
            "enabled": 1,
            "alert_score_drop": 1,
            "alert_new_vuln": 1,
            "alert_critical": 1,
            "alert_ssl_expiry": 1,
            "alert_new_port": 1,
        }
    finally:
        conn.close()


def save_email_settings(settings: dict) -> bool:
    """
    Saves or updates the email and SMTP settings.
    """
    init_email_settings_table()
    conn = _get_conn()
    try:
        smtp_server = str(settings.get("smtp_server", "")).strip()
        smtp_port = int(settings.get("smtp_port", 587) or 587)
        smtp_user = str(settings.get("smtp_user", "")).strip()
        smtp_password = str(settings.get("smtp_password", "")).strip()
        from_email = str(settings.get("from_email", "")).strip()
        recipient_email = str(settings.get("recipient_email", "")).strip()
        
        enc_mode = settings.get("encryption_mode")
        if enc_mode == "ssl" or smtp_port == 465:
            use_ssl = 1
            use_tls = 0
        elif enc_mode == "tls" or smtp_port == 587:
            use_ssl = 0
            use_tls = 1
        else:
            use_tls = 1 if settings.get("use_tls") in [1, "1", True, "true", "on"] else 0
            use_ssl = 1 if settings.get("use_ssl") in [1, "1", True, "true", "on"] else 0
            
        enabled = 1 if settings.get("enabled") in [1, "1", True, "true", "on"] else 0



        alert_score_drop = 1 if settings.get("alert_score_drop") in [1, "1", True, "true", "on"] else 0
        alert_new_vuln = 1 if settings.get("alert_new_vuln") in [1, "1", True, "true", "on"] else 0
        alert_critical = 1 if settings.get("alert_critical") in [1, "1", True, "true", "on"] else 0
        alert_ssl_expiry = 1 if settings.get("alert_ssl_expiry") in [1, "1", True, "true", "on"] else 0
        alert_new_port = 1 if settings.get("alert_new_port") in [1, "1", True, "true", "on"] else 0

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn.execute(
            """
            INSERT OR REPLACE INTO email_settings (
                id, smtp_server, smtp_port, smtp_user, smtp_password,
                from_email, recipient_email, use_tls, use_ssl, enabled,
                alert_score_drop, alert_new_vuln, alert_critical,
                alert_ssl_expiry, alert_new_port, updated_at
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                smtp_server,
                smtp_port,
                smtp_user,
                smtp_password,
                from_email,
                recipient_email,
                use_tls,
                use_ssl,
                enabled,
                alert_score_drop,
                alert_new_vuln,
                alert_critical,
                alert_ssl_expiry,
                alert_new_port,
                now_str,
            ),
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[EMAIL SETTINGS ERROR] Failed to save email settings: {e}")
        return False
    finally:
        conn.close()
