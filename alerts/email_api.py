import os
import sys
import json
import logging
import requests

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

logger = logging.getLogger("cybershield.email_api")


def get_email_api_config() -> dict:
    """
    Reads email API configuration from environment variables with intelligent fallbacks.
    """
    env_provider = os.environ.get("EMAIL_PROVIDER", "").strip().lower()
    
    # Check general API key or provider-specific keys
    api_key = (
        os.environ.get("BREVO_API_KEY") or
        os.environ.get("EMAIL_API_KEY") or
        os.environ.get("SENDINBLUE_API_KEY") or
        os.environ.get("RESEND_API_KEY") or
        os.environ.get("SENDGRID_API_KEY") or
        os.environ.get("MAILGUN_API_KEY") or
        ""
    ).strip()

    # Determine provider
    if env_provider:
        provider = env_provider
    elif os.environ.get("BREVO_API_KEY") or os.environ.get("SENDINBLUE_API_KEY"):
        provider = "brevo"
    elif os.environ.get("SMTP_USERNAME") or os.environ.get("SMTP_HOST"):
        provider = "smtp"
    elif os.environ.get("SENDGRID_API_KEY"):
        provider = "sendgrid"
    elif os.environ.get("MAILGUN_API_KEY"):
        provider = "mailgun"
    else:
        provider = "brevo" if api_key.startswith("xkeysib-") else "resend"

    from_name = (
        os.environ.get("EMAIL_FROM_NAME") or
        os.environ.get("BREVO_FROM_NAME") or
        "CyberShieldAI"
    ).strip()

    from_email = (
        os.environ.get("EMAIL_FROM") or
        os.environ.get("BREVO_SENDER_EMAIL") or
        os.environ.get("SMTP_FROM_EMAIL") or
        os.environ.get("SMTP_USER") or
        os.environ.get("SMTP_USERNAME") or
        ""
    ).strip()

    # Fallback to database email settings if available
    if not from_email:
        try:
            from database.email_settings_helpers import get_email_settings
            db_s = get_email_settings() or {}
            from_email = (db_s.get("from_email") or db_s.get("smtp_user") or "").strip()
        except Exception:
            pass

    # Verified sender fallback for Brevo
    if not from_email:
        if provider in ("brevo", "sendinblue"):
            from_email = "defenderr0809@gmail.com"
        elif provider == "resend":
            from_email = "onboarding@resend.dev"
        elif provider == "sendgrid":
            from_email = "alerts@cybershield.ai"
        else:
            from_email = "defenderr0809@gmail.com"

    mailgun_domain = os.environ.get("MAILGUN_DOMAIN", "").strip()

    return {
        "provider": provider,
        "api_key": api_key,
        "from_name": from_name,
        "from_email": from_email,
        "mailgun_domain": mailgun_domain,
    }


def _send_via_resend(api_key: str, from_name: str, from_email: str, to_email: str, subject: str, html_body: str, text_body: str) -> tuple:
    """
    Sends email via Resend HTTPS REST API (https://api.resend.com/emails).
    """
    if not api_key:
        logger.warning("[EMAIL_API_WARNING] provider=resend error=missing_api_key")
        print("[EMAIL] BREVO/EMAIL SEND FAILED: Resend API key is missing.", flush=True)
        return False, "Resend API key is missing. Please configure EMAIL_API_KEY in environment variables."

    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "CyberShieldAI/1.0",
    }

    formatted_from = f"{from_name} <{from_email}>" if from_name else from_email

    payload = {
        "from": formatted_from,
        "to": [to_email.strip()],
        "subject": subject,
        "html": html_body,
    }
    if text_body:
        payload["text"] = text_body

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=12)
        if response.status_code in (200, 201, 202):
            try:
                res_id = response.json().get("id") or "ok"
            except Exception:
                res_id = "ok"
            print(f"[EMAIL] Provider: Resend", flush=True)
            print(f"[EMAIL] Resend response: success (HTTP {response.status_code})", flush=True)
            print(f"[EMAIL] Resend message ID: {res_id}", flush=True)
            return True, "Email successfully sent via Resend."
        
        try:
            err_data = response.json()
            err_msg = err_data.get("message") or err_data.get("error") or str(response.status_code)
        except Exception:
            err_msg = f"HTTP {response.status_code}"
        
        logger.error(f"[EMAIL_API_ERROR] provider=resend status={response.status_code} error={err_msg}")
        print(f"[EMAIL] RESEND EMAIL SEND FAILED - Status: {response.status_code} - Error: {err_msg}", flush=True)
        return False, f"Resend API error: {err_msg}"
    except requests.RequestException as e:
        logger.error(f"[EMAIL_API_ERROR] provider=resend exception={type(e).__name__}")
        print(f"[EMAIL] Resend connection failed: {type(e).__name__}", flush=True)
        return False, "Failed to connect to Resend API over HTTPS."


def _send_via_sendgrid(api_key: str, from_name: str, from_email: str, to_email: str, subject: str, html_body: str, text_body: str) -> tuple:
    """
    Sends email via SendGrid HTTPS REST API (https://api.sendgrid.com/v3/mail/send).
    """
    if not api_key:
        logger.warning("[EMAIL_API_WARNING] provider=sendgrid error=missing_api_key")
        return False, "SendGrid API key is missing. Please configure EMAIL_API_KEY in environment variables."

    url = "https://api.sendgrid.com/v3/mail/send"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    content_list = []
    if text_body:
        content_list.append({"type": "text/plain", "value": text_body})
    if html_body:
        content_list.append({"type": "text/html", "value": html_body})

    payload = {
        "personalizations": [{"to": [{"email": to_email.strip()}]}],
        "from": {"email": from_email, "name": from_name},
        "subject": subject,
        "content": content_list,
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=12)
        if response.status_code in (200, 201, 202):
            print(f"[EMAIL] Provider: SendGrid - response: success (HTTP {response.status_code})", flush=True)
            return True, "Email successfully sent via SendGrid."
        
        logger.error(f"[EMAIL_API_ERROR] provider=sendgrid status={response.status_code}")
        print(f"[EMAIL] SENDGRID EMAIL SEND FAILED - Status: {response.status_code}", flush=True)
        return False, f"SendGrid API responded with status {response.status_code}."
    except requests.RequestException as e:
        logger.error(f"[EMAIL_API_ERROR] provider=sendgrid exception={type(e).__name__}")
        return False, "Failed to connect to SendGrid API over HTTPS."


def _send_via_mailgun(api_key: str, domain: str, from_name: str, from_email: str, to_email: str, subject: str, html_body: str, text_body: str) -> tuple:
    """
    Sends email via Mailgun HTTPS REST API.
    """
    if not api_key or not domain:
        logger.warning("[EMAIL_API_WARNING] provider=mailgun error=missing_credentials_or_domain")
        return False, "Mailgun API key or domain is missing. Please configure EMAIL_API_KEY and MAILGUN_DOMAIN."

    url = f"https://api.mailgun.net/v3/{domain}/messages"
    formatted_from = f"{from_name} <{from_email}>" if from_name else from_email

    data = {
        "from": formatted_from,
        "to": [to_email.strip()],
        "subject": subject,
        "html": html_body,
    }
    if text_body:
        data["text"] = text_body

    try:
        response = requests.post(url, auth=("api", api_key), data=data, timeout=12)
        if response.status_code in (200, 201, 202):
            print(f"[EMAIL] Provider: Mailgun - response: success (HTTP {response.status_code})", flush=True)
            return True, "Email successfully sent via Mailgun."
        
        logger.error(f"[EMAIL_API_ERROR] provider=mailgun status={response.status_code}")
        print(f"[EMAIL] MAILGUN EMAIL SEND FAILED - Status: {response.status_code}", flush=True)
        return False, f"Mailgun API responded with status {response.status_code}."
    except requests.RequestException as e:
        logger.error(f"[EMAIL_API_ERROR] provider=mailgun exception={type(e).__name__}")
        return False, "Failed to connect to Mailgun API over HTTPS."


def _send_via_brevo(api_key: str, from_name: str, from_email: str, to_email: str, subject: str, html_body: str, text_body: str) -> tuple:
    """
    Sends email via Brevo (Sendinblue) HTTPS REST Transactional API (https://api.brevo.com/v3/smtp/email).
    Uses api-key header over HTTPS Port 443 with detailed diagnostics and message ID tracking.
    """
    clean_recipient = (to_email or "").strip()
    clean_sender = (from_email or "").strip()
    sender_name = (from_name or "CyberShieldAI").strip()

    print("[EMAIL] Provider: Brevo", flush=True)
    print(f"[EMAIL] Sending email to: {clean_recipient} (Sender: {sender_name} <{clean_sender}>)", flush=True)

    if not api_key:
        print("[EMAIL] BREVO EMAIL SEND FAILED", flush=True)
        print("[EMAIL] Status: 400", flush=True)
        print("[EMAIL] Error: Brevo API key is missing. Set BREVO_API_KEY in environment variables.", flush=True)
        logger.warning("[EMAIL_API_WARNING] provider=brevo error=missing_api_key")
        return False, "Brevo API key is missing. Please configure BREVO_API_KEY in Render environment variables."

    if not clean_sender:
        print("[EMAIL] BREVO EMAIL SEND FAILED", flush=True)
        print("[EMAIL] Status: 400", flush=True)
        print("[EMAIL] Error: Sender email is missing. Set EMAIL_FROM in environment variables.", flush=True)
        return False, "Sender email is missing. Please configure EMAIL_FROM in Render environment variables."

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "api-key": api_key,
        "accept": "application/json",
        "content-type": "application/json",
    }

    payload = {
        "sender": {
            "name": sender_name,
            "email": clean_sender,
        },
        "to": [
            {
                "email": clean_recipient,
            }
        ],
        "replyTo": {
            "name": sender_name,
            "email": clean_sender,
        },
        "subject": subject,
        "htmlContent": html_body,
    }
    if text_body:
        payload["textContent"] = text_body

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        
        # Brevo returns HTTP 201 Created on successful email submission
        if response.status_code in (200, 201, 202):
            try:
                res_data = response.json()
                message_id = res_data.get("messageId") or "accepted"
            except Exception:
                message_id = "accepted"

            print("[EMAIL] BREVO EMAIL SEND SUCCESS", flush=True)
            print(f"[EMAIL] Brevo response: success (HTTP {response.status_code})", flush=True)
            print(f"[EMAIL] Brevo message ID: {message_id}", flush=True)
            logger.info(f"[EMAIL] provider=brevo status={response.status_code} messageId={message_id}")
            return True, f"Email successfully sent via Brevo. Message ID: {message_id}"

        # Parse Brevo error details safely
        try:
            err_json = response.json()
            safe_err_code = err_json.get("code") or "error"
            safe_err_msg = err_json.get("message") or f"HTTP {response.status_code}"
            full_err_str = f"{safe_err_code}: {safe_err_msg}"
        except Exception:
            full_err_str = f"HTTP {response.status_code}"

        print("[EMAIL] BREVO EMAIL SEND FAILED", flush=True)
        print(f"[EMAIL] Status: {response.status_code}", flush=True)
        print(f"[EMAIL] Error: {full_err_str}", flush=True)
        logger.error(f"[EMAIL_API_ERROR] provider=brevo status={response.status_code} error={full_err_str}")

        if response.status_code == 400 and "not verified" in full_err_str.lower():
            return False, f"Sender email '{clean_sender}' is not verified in your Brevo account. Please verify it in Brevo -> Senders & IP."
        elif response.status_code in (401, 403):
            return False, "Invalid Brevo API Key. Please verify BREVO_API_KEY in Render environment variables."
        
        return False, f"Brevo API error ({response.status_code}): {full_err_str}"

    except requests.RequestException as e:
        err_type = type(e).__name__
        print("[EMAIL] BREVO EMAIL SEND FAILED", flush=True)
        print(f"[EMAIL] Status: Connection Error", flush=True)
        print(f"[EMAIL] Error: {err_type}", flush=True)
        logger.error(f"[EMAIL_API_ERROR] provider=brevo exception={err_type}")
        return False, "Failed to connect to Brevo API over HTTPS."


def send_https_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str = None,
    config: dict = None,
) -> tuple:
    """
    Sends an email using configured HTTPS Email API provider (Brevo, Resend, SendGrid, Mailgun).
    Never attempts direct raw SMTP ports (25/465/587) unless provider is explicitly set to 'smtp'.
    Returns (success: bool, safe_message: str).
    """
    if not to_email or not to_email.strip():
        return False, "Recipient email address is missing."

    cfg = config or get_email_api_config()
    provider = (cfg.get("provider") or "brevo").strip().lower()
    api_key = cfg.get("api_key", "")
    from_name = cfg.get("from_name", "CyberShieldAI")
    from_email = cfg.get("from_email", "defenderr0809@gmail.com")

    if provider in ("brevo", "sendinblue"):
        return _send_via_brevo(api_key, from_name, from_email, to_email, subject, html_body, text_body)
    elif provider == "resend":
        return _send_via_resend(api_key, from_name, from_email, to_email, subject, html_body, text_body)
    elif provider == "sendgrid":
        return _send_via_sendgrid(api_key, from_name, from_email, to_email, subject, html_body, text_body)
    elif provider == "mailgun":
        return _send_via_mailgun(api_key, cfg.get("mailgun_domain", ""), from_name, from_email, to_email, subject, html_body, text_body)
    elif provider == "smtp":
        from alerts.email_notifier import send_smtp_email
        return send_smtp_email(to_email=to_email, subject=subject, html_body=html_body, text_body=text_body)
    else:
        logger.error(f"[EMAIL_API_ERROR] unknown_provider={provider}")
        return False, f"Unsupported email provider '{provider}'."


def send_admin_test_email(to_email: str) -> tuple:
    """
    Dispatches a test verification email via the active HTTPS Email API to confirm delivery.
    """
    clean_recipient = (to_email or "").strip()
    if not clean_recipient:
        return False, "Recipient email is required for testing."

    cfg = get_email_api_config()
    provider = cfg.get("provider", "resend").capitalize()
    from_addr = cfg.get("from_email", "onboarding@resend.dev")

    subject = "[CyberShieldAI] Email Delivery System Test"
    text_body = f"""CyberShieldAI — Email Delivery Test
--------------------------------------------------
This is a test notification confirming that your CyberShieldAI email delivery system is functioning properly.

Provider: {provider} (HTTPS API)
Sender: {from_addr}
Recipient: {clean_recipient}

If you received this message, your verified domain and email configuration are working correctly.

— CyberShieldAI Security Team
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin: 0; padding: 20px; background-color: #070d19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #f8fafc;">
    <table role="presentation" width="100%" style="max-width: 520px; margin: 0 auto; background: #0f172a; border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px; padding: 24px;">
        <tr>
            <td>
                <h2 style="color: #38bdf8; margin-top: 0;">🛡️ CyberShieldAI Email Test</h2>
                <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
                    This is an automated test verifying that your <strong>{provider} HTTPS API</strong> email delivery pipeline is operational.
                </p>
                <div style="background: rgba(11, 19, 41, 0.9); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 14px; margin: 16px 0; font-size: 13px; color: #94a3b8;">
                    <p style="margin: 4px 0;"><strong>Status:</strong> <span style="color: #22c55e;">● Verified & Operational</span></p>
                    <p style="margin: 4px 0;"><strong>Sender:</strong> {from_addr}</p>
                    <p style="margin: 4px 0;"><strong>Recipient:</strong> {clean_recipient}</p>
                </div>
                <p style="color: #64748b; font-size: 11px; margin-bottom: 0;">
                    CyberShieldAI Security Operations Center
                </p>
            </td>
        </tr>
    </table>
</body>
</html>
"""
    return send_https_email(to_email=clean_recipient, subject=subject, html_body=html_body, text_body=text_body)
