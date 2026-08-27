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
    Reads email API configuration from environment variables.
    """
    provider = os.environ.get("EMAIL_PROVIDER", "").strip().lower() or "resend"
    
    # Check general API key or provider-specific keys
    api_key = (
        os.environ.get("EMAIL_API_KEY") or
        os.environ.get("RESEND_API_KEY") or
        os.environ.get("SENDGRID_API_KEY") or
        os.environ.get("MAILGUN_API_KEY") or
        ""
    ).strip()

    from_name = os.environ.get("EMAIL_FROM_NAME", "CyberShieldAI").strip()
    from_email = os.environ.get("EMAIL_FROM", "").strip()

    # Default from_email for Resend testing domain if not specified
    if not from_email:
        if provider == "resend":
            from_email = "onboarding@resend.dev"
        elif provider == "sendgrid":
            from_email = "alerts@cybershield.ai"
        else:
            from_email = "alerts@cybershield.ai"

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
        return False, "Resend API key is missing. Please configure EMAIL_API_KEY in environment variables."

    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "CyberShieldAI/1.0",
    }

    # Format from header
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
            return True, "Email successfully sent via Resend."
        
        # Log sanitized error
        try:
            err_data = response.json()
            err_msg = err_data.get("message") or err_data.get("error") or str(response.status_code)
        except Exception:
            err_msg = f"HTTP {response.status_code}"
        
        logger.error(f"[EMAIL_API_ERROR] provider=resend status={response.status_code} error={err_msg}")
        return False, f"Resend API error: {err_msg}"
    except requests.RequestException as e:
        logger.error(f"[EMAIL_API_ERROR] provider=resend exception={type(e).__name__}")
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
            return True, "Email successfully sent via SendGrid."
        
        logger.error(f"[EMAIL_API_ERROR] provider=sendgrid status={response.status_code}")
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
            return True, "Email successfully sent via Mailgun."
        
        logger.error(f"[EMAIL_API_ERROR] provider=mailgun status={response.status_code}")
        return False, f"Mailgun API responded with status {response.status_code}."
    except requests.RequestException as e:
        logger.error(f"[EMAIL_API_ERROR] provider=mailgun exception={type(e).__name__}")
        return False, "Failed to connect to Mailgun API over HTTPS."


def send_https_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str = None,
    config: dict = None,
) -> tuple:
    """
    Sends an email using configured HTTPS Email API provider (Resend, SendGrid, Mailgun).
    Never attempts direct raw SMTP ports (25/465/587) unless provider is explicitly set to 'smtp'.
    Returns (success: bool, safe_message: str).
    """
    if not to_email or not to_email.strip():
        return False, "Recipient email address is missing."

    cfg = config or get_email_api_config()
    provider = (cfg.get("provider") or "resend").strip().lower()
    api_key = cfg.get("api_key", "")
    from_name = cfg.get("from_name", "CyberShieldAI")
    from_email = cfg.get("from_email", "onboarding@resend.dev")

    if provider == "resend":
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
