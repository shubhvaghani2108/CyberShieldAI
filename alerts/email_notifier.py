import os
import smtplib
import sys
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.email_settings_helpers import get_email_settings


def send_smtp_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str = None,
    settings: dict = None,
) -> tuple:
    """
    Sends an email using configured SMTP settings with RFC-compliant headers.
    Returns (success: bool, message: str).
    """
    if not settings:
        settings = get_email_settings()

    smtp_server = settings.get("smtp_server")
    smtp_port = int(settings.get("smtp_port", 587) or 587)
    smtp_user = settings.get("smtp_user", "").strip()
    smtp_password = settings.get("smtp_password", "").strip()
    
    # For Gmail and standard SMTP, from_email should match smtp_user to pass SPF/DKIM
    configured_from = settings.get("from_email", "").strip()
    if smtp_user and ("gmail" in str(smtp_server).lower() or not configured_from or configured_from == "alerts@cybershield.ai"):
        from_email = smtp_user
    else:
        from_email = configured_from or smtp_user or "alerts@cybershield.ai"

    use_tls = bool(settings.get("use_tls", 1))
    use_ssl = bool(settings.get("use_ssl", 0))

    if not smtp_server:
        return False, "SMTP Server is not configured."
    if not to_email:
        return False, "Recipient email address is missing."

    # Derive domain for Message-ID
    msg_domain = "gmail.com" if "gmail" in str(smtp_server).lower() else (from_email.split("@")[-1] if "@" in from_email else "cybershield.local")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"CyberShieldAI SOC <{from_email}>"
    msg["To"] = to_email
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=msg_domain)
    msg["Reply-To"] = from_email
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    msg["Precedence"] = "bulk"

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    if not smtp_user or not smtp_password:
        return False, "SMTP credentials are not configured. Please set SMTP_USERNAME and SMTP_PASSWORD in your environment variables (or settings)."

    import socket
    import ssl

    def _open_smtp_connection(server_host, port, ssl_mode, tls_mode):
        # Resolve to IPv4 to prevent [Errno 101] Network is unreachable on IPv6-broken cloud networks
        ipv4_addrs = []
        try:
            addr_infos = socket.getaddrinfo(server_host, port, socket.AF_INET, socket.SOCK_STREAM)
            for item in addr_infos:
                ip = item[4][0]
                if ip not in ipv4_addrs:
                    ipv4_addrs.append(ip)
        except Exception:
            ipv4_addrs = [server_host]

        if not ipv4_addrs:
            ipv4_addrs = [server_host]

        last_conn_err = None
        for target_ip in ipv4_addrs:
            try:
                if ssl_mode or port == 465:
                    srv = smtplib.SMTP_SSL(target_ip, port, timeout=12)
                    srv.helo(server_host)
                    return srv
                else:
                    srv = smtplib.SMTP(target_ip, port, timeout=12)
                    srv.helo(server_host)
                    if tls_mode or port == 587:
                        srv.starttls()
                    return srv
            except Exception as ce:
                last_conn_err = ce
                continue
        if last_conn_err:
            raise last_conn_err
        raise ConnectionError(f"Unable to connect to SMTP server {server_host}:{port}")

    try:
        # Try configured port and mode first
        try:
            server = _open_smtp_connection(smtp_server, smtp_port, use_ssl, use_tls)
        except Exception as primary_err:
            # Fallback strategy: if port 587 failed, try port 465 SSL; if port 465 failed, try port 587 TLS
            if smtp_port == 587:
                server = _open_smtp_connection(smtp_server, 465, ssl_mode=True, tls_mode=False)
            elif smtp_port == 465:
                server = _open_smtp_connection(smtp_server, 587, ssl_mode=False, tls_mode=True)
            else:
                raise primary_err

        if smtp_user and smtp_password:
            clean_pw = smtp_password.replace(" ", "").strip()
            try:
                server.login(smtp_user, clean_pw)
            except smtplib.SMTPAuthenticationError:
                server.login(smtp_user, smtp_password)

        recipients = [r.strip() for r in to_email.split(",") if r.strip()]
        server.sendmail(from_email, recipients, msg.as_string())
        server.quit()
        return True, f"Email successfully sent to {to_email}."

    except smtplib.SMTPAuthenticationError as auth_err:
        advice = ""
        if "gmail" in str(smtp_server).lower():
            advice = " (Note: For Gmail, you must use a 16-character Google 'App Password' created at https://myaccount.google.com/apppasswords)"
        return False, f"SMTP Authentication failed: {auth_err}{advice}"
    except Exception as e:
        return False, f"Failed to send email via SMTP: {str(e)}"



def send_test_email(to_email: str = None) -> tuple:
    """
    Sends a test verification email to validate SMTP configuration.
    """
    settings = get_email_settings()
    recipient = to_email or settings.get("recipient_email") or settings.get("from_email")

    if not recipient:
        return False, "Please specify a recipient email address for testing."

    subject = "[CyberShieldAI] Test Alert Notification - SMTP Verification"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0c1017; color: #e2e8f0; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: #131a26; border: 1px solid #243042; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }}
        .header {{ background: #0ea5e9; background: linear-gradient(135deg, #0ea5e9 0%, #38bdf8 100%); padding: 20px 24px; text-align: left; }}
        .header h1 {{ margin: 0; font-size: 20px; color: #ffffff; font-weight: 700; }}
        .content {{ padding: 24px; font-size: 14px; line-height: 1.6; color: #cbd5e1; }}
        .card {{ background: #1a2332; border: 1px solid #2b3a4f; border-radius: 6px; padding: 16px; margin: 18px 0; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 700; background: #22c55e; color: #000; }}
        .footer {{ padding: 16px 24px; background: #0c1017; border-top: 1px solid #243042; font-size: 12px; color: #64748b; text-align: center; }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🛡 CyberShieldAI SOC Platform</h1>
        </div>
        <div class="content">
          <h2 style="color:#ffffff; margin-top:0; font-size:16px;">SMTP Notification System Verified</h2>
          <p>This is a test notification confirming that your CyberShieldAI email alerting system is properly connected and functioning.</p>
          <div class="card">
            <p style="margin:4px 0;"><strong>Status:</strong> <span class="badge">Active & Connected</span></p>
            <p style="margin:4px 0;"><strong>SMTP Server:</strong> {settings.get('smtp_server')}:{settings.get('smtp_port')}</p>
            <p style="margin:4px 0;"><strong>Recipient:</strong> {recipient}</p>
            <p style="margin:4px 0;"><strong>Timestamp:</strong> {timestamp}</p>
          </div>
          <p>Automated alerts for critical posture drops, new open ports, vulnerabilities, and expiring SSL certificates will be dispatched here in real-time.</p>
        </div>
        <div class="footer">
          CyberShieldAI Automated Security Intelligence Engine &middot; {timestamp}
        </div>
      </div>
    </body>
    </html>
    """

    text_content = f"""
    CyberShieldAI - Test Alert Notification
    --------------------------------------------------
    SMTP Notification System Verified successfully.
    Timestamp: {timestamp}
    Server: {settings.get('smtp_server')}:{settings.get('smtp_port')}
    """

    return send_smtp_email(recipient, subject, html_content, text_content, settings=settings)


def format_alert_email_html(alert: dict) -> str:
    """
    Renders an HTML email for security alert findings using clean inline CSS
    and table layouts for highest email deliverability across Gmail, Outlook, and Apple Mail.
    """
    target = alert.get("target") or alert.get("ip") or "Unknown Target"
    alert_type = alert.get("alert_type") or alert.get("title") or "Security Alert"
    severity = str(alert.get("severity") or "Medium").capitalize()
    message = alert.get("message") or alert.get("description") or "Security anomaly detected."
    recommendation = alert.get("recommendation") or "Review target configuration and apply security remediation."
    timestamp = alert.get("created_at") or alert.get("scan_time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Severity styling
    if severity == "Critical":
        sev_color = "#dc2626"
        sev_bg = "#fee2e2"
    elif severity == "High":
        sev_color = "#ea580c"
        sev_bg = "#ffedd5"
    elif severity == "Medium":
        sev_color = "#d97706"
        sev_bg = "#fef3c7"
    else:
        sev_color = "#0284c7"
        sev_bg = "#e0f2fe"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberShieldAI Security Alert</title>
</head>
<body style="margin: 0; padding: 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; color: #1e293b;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" align="center" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
    <!-- Header -->
    <tr>
      <td style="background-color: #0f172a; padding: 20px 24px; text-align: left;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td>
              <h1 style="margin: 0; font-size: 18px; font-weight: 700; color: #ffffff; letter-spacing: 0.5px;">🛡 CyberShieldAI Security Alert</h1>
            </td>
            <td align="right">
              <span style="display: inline-block; padding: 4px 12px; font-size: 12px; font-weight: 700; border-radius: 4px; background-color: {sev_bg}; color: {sev_color}; text-transform: uppercase;">
                {severity}
              </span>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Body Content -->
    <tr>
      <td style="padding: 24px;">
        <h2 style="margin: 0 0 12px 0; font-size: 17px; font-weight: 600; color: #0f172a;">{alert_type} on {target}</h2>
        <p style="margin: 0 0 18px 0; font-size: 14px; line-height: 1.6; color: #475569;">{message}</p>

        <!-- Finding Details Table -->
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 20px;">
          <tr>
            <td style="padding: 10px 14px; font-size: 13px; font-weight: 600; color: #64748b; border-bottom: 1px solid #e2e8f0; width: 35%;">Target Host</td>
            <td style="padding: 10px 14px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #e2e8f0; font-family: monospace;">{target}</td>
          </tr>
          <tr>
            <td style="padding: 10px 14px; font-size: 13px; font-weight: 600; color: #64748b; border-bottom: 1px solid #e2e8f0;">Alert Category</td>
            <td style="padding: 10px 14px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #e2e8f0;">{alert_type}</td>
          </tr>
          <tr>
            <td style="padding: 10px 14px; font-size: 13px; font-weight: 600; color: #64748b; border-bottom: 1px solid #e2e8f0;">Severity</td>
            <td style="padding: 10px 14px; font-size: 13px; font-weight: 700; color: {sev_color}; border-bottom: 1px solid #e2e8f0;">{severity}</td>
          </tr>
          <tr>
            <td style="padding: 10px 14px; font-size: 13px; font-weight: 600; color: #64748b;">Detection Timestamp</td>
            <td style="padding: 10px 14px; font-size: 13px; color: #0f172a; font-family: monospace;">{timestamp}</td>
          </tr>
        </table>

        <!-- Recommended Remediation Box -->
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f0f9ff; border-left: 4px solid #0284c7; border-radius: 4px; padding: 12px 14px;">
          <tr>
            <td>
              <strong style="color: #0369a1; font-size: 13px; display: block; margin-bottom: 4px;">Recommended Remediation:</strong>
              <p style="margin: 0; font-size: 13px; line-height: 1.5; color: #0c4a6e;">{recommendation}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="background-color: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; text-align: center; font-size: 12px; color: #94a3b8;">
        CyberShieldAI SOC &bull; Automated Security Incident Notification &bull; {timestamp}
      </td>
    </tr>
  </table>
</body>
</html>
"""



_LAST_SENT_LOG = {}
_DISPATCH_LOCK = threading.Lock()


def dispatch_alert_email(alert: dict):
    """
    Asynchronously checks email settings and sends an alert email if conditions match.
    Includes smart throttling to avoid triggering university mail gateway flood/spam filters.
    """
    def _worker():
        try:
            settings = get_email_settings()
            if not settings.get("enabled"):
                return

            recipient = settings.get("recipient_email")
            if not recipient:
                return

            alert_type = str(alert.get("alert_type") or alert.get("title") or "")
            severity = str(alert.get("severity") or "").capitalize()
            target = alert.get("target") or alert.get("ip") or "Unknown"

            should_send = False

            # 1. Critical Alert (any alert with Critical severity)
            if severity == "Critical" and settings.get("alert_critical"):
                should_send = True

            # 2. Security Score Drop
            if "score drop" in alert_type.lower() and settings.get("alert_score_drop"):
                should_send = True

            # 3. New Vulnerability
            if "vulnerability" in alert_type.lower() and settings.get("alert_new_vuln"):
                should_send = True

            # 4. SSL Expiry (<30 days)
            if ("ssl" in alert_type.lower() or "certificate" in alert_type.lower() or "expiry" in alert_type.lower()) and settings.get("alert_ssl_expiry"):
                should_send = True

            # 5. New Open Port
            if ("port" in alert_type.lower()) and settings.get("alert_new_port"):
                should_send = True

            if not should_send:
                return

            # Smart throttle: Prevent sending duplicate alert types for the same target within 60s
            throttle_key = f"{target}::{alert_type}::{severity}"
            now_ts = datetime.now().timestamp()
            with _DISPATCH_LOCK:
                last_time = _LAST_SENT_LOG.get(throttle_key, 0)
                if now_ts - last_time < 60:
                    return
                _LAST_SENT_LOG[throttle_key] = now_ts

            subject = f"CyberShieldAI Security Alert: {alert_type} on {target}"
            html_body = format_alert_email_html(alert)
            text_body = f"CyberShieldAI Security Alert\nSeverity: {severity}\nType: {alert_type}\nTarget: {target}\nMessage: {alert.get('message', '')}\nRecommendation: {alert.get('recommendation', '')}\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

            success, msg = send_smtp_email(recipient, subject, html_body, text_body, settings=settings)
            if success:
                print(f"[EMAIL NOTIFIER] Dispatched email alert to {recipient} for {target} ({alert_type})")
            else:
                print(f"[EMAIL NOTIFIER ERROR] {msg}")
        except Exception as e:
            print(f"[EMAIL NOTIFIER WORKER ERROR] {e}")

    threading.Thread(target=_worker, daemon=True).start()

