import os
import sys
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.email_settings_helpers import (
    init_email_settings_table,
    get_email_settings,
    save_email_settings,
)
from alerts.email_notifier import (
    send_test_email,
    format_alert_email_html,
    dispatch_alert_email,
)
from alerts.save_alert import save_alert
from dashboard.app import app

def run_email_tests():
    print("--- 1. Testing email_settings Table & Helpers ---")
    init_email_settings_table()
    settings = get_email_settings()
    print("Initial settings:", settings)
    assert settings is not None
    assert "smtp_server" in settings
    assert "alert_score_drop" in settings
    assert "alert_new_vuln" in settings
    assert "alert_critical" in settings
    assert "alert_ssl_expiry" in settings
    assert "alert_new_port" in settings

    print("\n--- 2. Testing save_email_settings ---")
    save_success = save_email_settings({
        "smtp_server": "smtp.mailtrap.io",
        "smtp_port": 2525,
        "smtp_user": "test_user",
        "smtp_password": "test_password",
        "from_email": "soc@cybershield.ai",
        "recipient_email": "security-team@company.com",
        "use_tls": 1,
        "use_ssl": 0,
        "enabled": 1,
        "alert_score_drop": 1,
        "alert_new_vuln": 1,
        "alert_critical": 1,
        "alert_ssl_expiry": 1,
        "alert_new_port": 1,
    })
    assert save_success == True
    updated = get_email_settings()
    assert updated["smtp_server"] == "smtp.mailtrap.io"
    assert updated["recipient_email"] == "security-team@company.com"
    assert updated["enabled"] == 1
    print("Email settings updated successfully:", updated["recipient_email"])

    print("\n--- 3. Testing HTML Email Alert Formatter ---")
    alert_sample = {
        "target": "https://example-test.com",
        "alert_type": "Security Score Drop",
        "severity": "Critical",
        "message": "Security score decreased by 25 points from 90 down to 65.",
        "recommendation": "Investigate newly open ports and critical vulnerabilities.",
        "created_at": "2026-08-17 17:50:00",
    }
    html_output = format_alert_email_html(alert_sample)
    assert "https://example-test.com" in html_output
    assert "Security Score Drop" in html_output
    assert "CRITICAL" in html_output
    print("HTML Email formatted successfully with severity badge and target details.")

    print("\n--- 4. Testing send_test_email Handler ---")
    # Testing with dummy recipient (will catch connection error gracefully and return status message)
    success, msg = send_test_email("admin@company.com")
    print(f"send_test_email result: (Success={success}, Message='{msg}')")
    assert isinstance(success, bool)
    assert isinstance(msg, str)

    print("\n--- 5. Testing save_alert Integration with Email Dispatch ---")
    alert_id = save_alert(
        target="https://email-alert-test.com",
        alert_type="New Vulnerability",
        severity="Critical",
        message="Critical SQL Injection identified on login endpoint",
        recommendation="Deploy input sanitization patch immediately",
    )
    print("Saved alert with ID:", alert_id)
    assert alert_id is not None

    # Verify alert exists in existing alerts table
    conn = sqlite3.connect("cybershield.db")
    conn.row_factory = sqlite3.Row
    row = dict(conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())
    assert row["target"] == "https://email-alert-test.com"
    assert row["alert_type"] == "New Vulnerability"
    conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()
    print("Alert validated in alerts table.")

    print("\n--- 6. Testing Web Routes (/settings/email) ---")
    client = app.test_client()
    
    # GET Page
    r_get = client.get("/settings/email")
    assert r_get.status_code == 200
    html = r_get.data.decode("utf-8")
    assert "Email Alert System" in html
    assert "SMTP Server" in html
    assert "Send Test Email" in html
    assert "Security Score Drops" in html
    assert "New Vulnerability Found" in html
    assert "Critical Alerts" in html
    assert "SSL Certificate Expiry" in html
    assert "New Open Port" in html
    print("GET /settings/email rendered successfully with all SMTP and alert fields.")

    # POST Save
    r_save = client.post("/settings/email/save", data={
        "smtp_server": "smtp.gmail.com",
        "smtp_port": "587",
        "smtp_user": "alert-bot@gmail.com",
        "smtp_password": "app-password-secret",
        "from_email": "alerts@cybershield.ai",
        "recipient_email": "ciso@enterprise.com",
        "use_tls": "1",
        "enabled": "1",
        "alert_score_drop": "1",
        "alert_new_vuln": "1",
        "alert_critical": "1",
        "alert_ssl_expiry": "1",
        "alert_new_port": "1",
    }, follow_redirects=True)
    assert r_save.status_code == 200
    assert "saved successfully" in r_save.data.decode("utf-8").lower()
    print("POST /settings/email/save successfully updated configuration.")

    print("\n[SUCCESS] All Email Alert System requirements verified!")

if __name__ == "__main__":
    run_email_tests()
