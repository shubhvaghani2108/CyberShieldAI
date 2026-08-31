import os
import secrets
import sys
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from alerts.email_notifier import send_smtp_email
from database.email_settings_helpers import get_email_settings


def generate_secure_otp(length: int = 6) -> str:
    """
    Generates a cryptographically secure numeric OTP string of given length using secrets module.
    """
    return "".join(secrets.choice("0123456789") for _ in range(length))


def hash_otp(otp: str) -> str:
    """
    Returns a secure cryptographic one-way hash of the OTP for storage.
    """
    return generate_password_hash(str(otp).strip())


def verify_otp_hash(stored_hash: str, input_otp: str) -> bool:
    """
    Constant-time comparison verifying an input OTP against the stored cryptographic hash.
    """
    if not stored_hash or not input_otp:
        return False
    return check_password_hash(stored_hash, str(input_otp).strip())


def get_otp_config() -> dict:
    """
    Returns OTP policies configured via environment variables or defaults.
    """
    try:
        expiry_minutes = int(os.environ.get("OTP_EXPIRY_MINUTES", 10))
    except (ValueError, TypeError):
        expiry_minutes = 10

    try:
        max_attempts = int(os.environ.get("OTP_MAX_ATTEMPTS", 5))
    except (ValueError, TypeError):
        max_attempts = 5

    try:
        resend_cooldown = int(os.environ.get("OTP_RESEND_COOLDOWN", 60))
    except (ValueError, TypeError):
        resend_cooldown = 60

    return {
        "expiry_minutes": expiry_minutes,
        "max_attempts": max_attempts,
        "resend_cooldown": resend_cooldown,
    }


def get_smtp_effective_settings() -> dict:
    """
    Retrieves SMTP settings, giving precedence to environment variables,
    falling back to database settings when environment variables are omitted.
    """
    db_settings = get_email_settings() or {}

    env_host = os.environ.get("SMTP_HOST") or os.environ.get("SMTP_SERVER")
    env_port = os.environ.get("SMTP_PORT")
    env_user = os.environ.get("SMTP_USERNAME") or os.environ.get("SMTP_USER")
    env_password = os.environ.get("SMTP_PASSWORD")
    env_use_tls = os.environ.get("SMTP_USE_TLS")
    env_from = os.environ.get("SMTP_FROM_EMAIL")

    smtp_server = env_host if env_host is not None else db_settings.get("smtp_server", "smtp.gmail.com")
    
    try:
        smtp_port = int(env_port) if env_port else int(db_settings.get("smtp_port", 587) or 587)
    except (ValueError, TypeError):
        smtp_port = 587

    smtp_user = env_user if env_user is not None else db_settings.get("smtp_user", "")
    smtp_password = env_password if env_password is not None else db_settings.get("smtp_password", "")
    from_email = env_from if env_from is not None else db_settings.get("from_email", "")

    if env_use_tls is not None:
        use_tls = 1 if env_use_tls.lower() in ("1", "true", "yes") else 0
    else:
        use_tls = int(db_settings.get("use_tls", 1))

    use_ssl = 1 if smtp_port == 465 else int(db_settings.get("use_ssl", 0))

    return {
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_password": smtp_password,
        "from_email": from_email,
        "use_tls": use_tls,
        "use_ssl": use_ssl,
        "enabled": 1,
    }


def send_verification_otp_email(to_email: str, username: str, otp: str, expires_in_minutes: int = 10) -> tuple:
    """
    Constructs and sends a professional CyberShieldAI branded OTP verification email via HTTPS API.
    Returns (success: bool, message: str).
    """
    clean_email = (to_email or "").strip()
    if not clean_email:
        return False, "Recipient email address is required."

    subject = f"{otp} is your CyberShieldAI verification code"

    text_body = f"""Your CyberShieldAI verification code is: {otp}

Enter this code on the verification page to activate your account.
This verification code expires in {expires_in_minutes} minutes.

Security Notice:
Do not share this security code with anyone. CyberShieldAI will never ask you for this code.
If you did not request this verification, no action is required.

—
CyberShieldAI Security Operations
https://cybershieldai-nqhd.onrender.com
"""

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{otp} is your CyberShieldAI verification code</title>
</head>
<body style="margin: 0; padding: 0; background-color: #070d19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
    <!-- Preheader preview text to prevent spam snippet parsing -->
    <div style="display: none; max-height: 0px; overflow: hidden; mso-hide: all; font-size: 1px; line-height: 1px; color: #070d19;">
        Your CyberShieldAI security verification code is {otp}. This code expires in {expires_in_minutes} minutes.
    </div>

    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #070d19; padding: 30px 15px;">
        <tr>
            <td align="center">
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 520px; background: #0f172a; border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 32px 32px 20px 32px; text-align: center; border-bottom: 1px solid rgba(255, 255, 255, 0.08); background: linear-gradient(180deg, rgba(56, 189, 248, 0.08) 0%, transparent 100%);">
                            <div style="display: inline-block; width: 48px; height: 48px; line-height: 48px; border-radius: 12px; background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.4); text-align: center; margin-bottom: 12px;">
                                <span style="font-size: 24px; color: #38bdf8;">🛡️</span>
                            </div>
                            <h1 style="margin: 0; font-size: 22px; font-weight: 800; letter-spacing: -0.5px; color: #ffffff;">
                                Cyber<span style="color: #38bdf8;">Shield</span><span style="font-size: 11px; font-weight: 700; background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 6px; padding: 2px 6px; margin-left: 6px; vertical-align: middle;">AI</span>
                            </h1>
                            <p style="margin: 6px 0 0 0; font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">Security Operations Center</p>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 32px;">
                            <h2 style="margin: 0 0 12px 0; font-size: 18px; font-weight: 700; color: #f8fafc;">Verify Your Email Address</h2>
                            <p style="margin: 0 0 20px 0; font-size: 14px; line-height: 1.6; color: #94a3b8;">
                                Hello <strong style="color: #ffffff;">{username}</strong>,<br>
                                Use the verification code below to complete your account registration:
                            </p>
                            
                            <!-- OTP Box -->
                            <div style="margin: 28px 0; text-align: center;">
                                <div style="display: inline-block; padding: 16px 36px; background: rgba(11, 19, 41, 0.95); border: 2px solid #38bdf8; border-radius: 12px; box-shadow: 0 0 25px rgba(56, 189, 248, 0.25);">
                                    <span style="font-family: 'Courier New', Courier, monospace, 'JetBrains Mono'; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; text-align: center;">{otp}</span>
                                </div>
                                <p style="margin: 12px 0 0 0; font-size: 12px; color: #64748b;">
                                    ⏱️ This code expires in <strong style="color: #cbd5e1;">{expires_in_minutes} minutes</strong>.
                                </p>
                            </div>

                            <!-- Security Alert Box -->
                            <div style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid #ef4444; border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 24px 0 0 0;">
                                <p style="margin: 0; font-size: 12px; line-height: 1.5; color: #fca5a5;">
                                    <strong>🔒 Security Notice:</strong> Do not share this code with anyone. If you did not request this account, you can safely ignore this email.
                                </p>
                            </div>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 32px; background: #0b1329; border-top: 1px solid rgba(255, 255, 255, 0.06); text-align: center;">
                            <p style="margin: 0; font-size: 11px; color: #64748b; line-height: 1.5;">
                                CyberShieldAI Security Team<br>
                                Automated Identity &amp; Access Protection
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""

    from alerts.email_api import send_https_email
    return send_https_email(
        to_email=clean_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
    )


# Alias helper function
def send_otp_email(recipient_email: str, username: str, otp: str) -> tuple:
    """
    Sends an OTP verification email using the SMTP service.
    """
    return send_verification_otp_email(to_email=recipient_email, username=username, otp=otp)


def send_password_reset_otp_email(to_email: str, username: str = "", otp: str = "", expires_in_minutes: int = 10) -> tuple:
    """
    Dispatches a high-deliverability password recovery OTP email with transactional headers.
    """
    clean_email = (to_email or "").strip().lower()
    if not clean_email or not otp:
        return False, "Recipient email and OTP code are required."

    subject = f"{otp} is your CyberShieldAI password reset code"
    user_display = (username or clean_email.split("@")[0] or "Security Operator").strip()

    text_body = f"""CyberShieldAI Password Recovery

Hello {user_display},

Your 6-digit password recovery verification code is: {otp}

This code will expire in {expires_in_minutes} minutes.
Enter this code on the password recovery verification screen to proceed with resetting your password.

SECURITY NOTICE:
If you did not request a password reset for your CyberShieldAI account, please ignore this email or review your account security immediately.

CyberShieldAI Security Team
Automated Identity & Access Protection
"""

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberShieldAI Password Recovery Code</title>
</head>
<body style="margin: 0; padding: 0; background-color: #070d19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
    <!-- Preheader Hidden Text -->
    <div style="display: none; max-height: 0px; overflow: hidden; opacity: 0; font-size: 1px; line-height: 1px; color: #070d19;">
        {otp} is your CyberShieldAI password recovery code. Expires in {expires_in_minutes} minutes.
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #070d19; padding: 32px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 500px; background: #0f172a; border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 28px 32px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-bottom: 1px solid rgba(56, 189, 248, 0.15); text-align: center;">
                            <div style="display: inline-block; width: 44px; height: 44px; line-height: 44px; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px; font-size: 22px;">
                                🛡️
                            </div>
                            <h1 style="margin: 12px 0 0 0; font-size: 20px; font-weight: 700; color: #f8fafc; letter-spacing: -0.3px;">
                                CyberShield<span style="color: #38bdf8;">AI</span>
                            </h1>
                            <p style="margin: 4px 0 0 0; font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                                Password Recovery Verification
                            </p>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 32px;">
                            <p style="margin: 0 0 14px 0; font-size: 14px; line-height: 1.6; color: #cbd5e1;">
                                Hello <strong style="color: #f8fafc;">{user_display}</strong>,
                            </p>
                            <p style="margin: 0 0 24px 0; font-size: 14px; line-height: 1.6; color: #94a3b8;">
                                We received a request to reset your CyberShieldAI account password. Use the single-use verification code below to authorize your password reset:
                            </p>

                            <!-- OTP Box -->
                            <div style="background: rgba(11, 19, 41, 0.85); border: 2px dashed #0284c7; border-radius: 12px; padding: 22px; text-align: center; margin: 20px 0;">
                                <span style="font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 34px; font-weight: 800; letter-spacing: 10px; color: #38bdf8; display: block; padding-left: 10px;">
                                    {otp}
                                </span>
                                <span style="display: block; font-size: 12px; color: #64748b; margin-top: 10px;">
                                    ⏱ Expires in <strong style="color: #cbd5e1;">{expires_in_minutes} minutes</strong> &middot; Single-use only
                                </span>
                            </div>

                            <!-- Security Alert Box -->
                            <div style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid #ef4444; border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 24px 0 0 0;">
                                <p style="margin: 0; font-size: 12px; line-height: 1.5; color: #fca5a5;">
                                    <strong>🔒 Security Notice:</strong> If you did not request this password recovery, someone may be attempting to access your account. You can safely ignore this email; your existing password will remain unchanged.
                                </p>
                            </div>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 32px; background: #0b1329; border-top: 1px solid rgba(255, 255, 255, 0.06); text-align: center;">
                            <p style="margin: 0; font-size: 11px; color: #64748b; line-height: 1.5;">
                                CyberShieldAI Security Operations<br>
                                Automated Identity &amp; Access Protection
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""

    from alerts.email_api import send_https_email
    return send_https_email(
        to_email=clean_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
    )


def send_password_changed_notification_email(to_email: str, username: str = "") -> tuple:
    """
    Dispatches a security notification email confirming that the user's password was changed.
    """
    clean_email = (to_email or "").strip().lower()
    if not clean_email:
        return False, "Recipient email is required."

    subject = "Security Alert: Your CyberShieldAI password was changed"
    user_display = (username or clean_email.split("@")[0] or "Security Operator").strip()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    text_body = f"""CyberShieldAI Security Alert

Hello {user_display},

This is an automated confirmation that the password for your CyberShieldAI account ({clean_email}) was successfully changed on {timestamp}.

If you performed this action, no further steps are required.

SECURITY WARNING:
If you did not change your password, your account may be compromised. Please contact your system administrator or initiate a password reset immediately.

CyberShieldAI Security Operations
"""

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberShieldAI Password Changed</title>
</head>
<body style="margin: 0; padding: 0; background-color: #070d19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #070d19; padding: 32px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 500px; background: #0f172a; border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 28px 32px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-bottom: 1px solid rgba(56, 189, 248, 0.15); text-align: center;">
                            <div style="display: inline-block; width: 44px; height: 44px; line-height: 44px; background: rgba(34, 197, 94, 0.12); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 12px; font-size: 22px;">
                                🔒
                            </div>
                            <h1 style="margin: 12px 0 0 0; font-size: 20px; font-weight: 700; color: #f8fafc;">
                                Password Updated Successfully
                            </h1>
                            <p style="margin: 4px 0 0 0; font-size: 12px; color: #4ade80; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                                Account Security Confirmation
                            </p>
                        </td>
                    </tr>
                    <!-- Content -->
                    <tr>
                        <td style="padding: 32px;">
                            <p style="margin: 0 0 14px 0; font-size: 14px; line-height: 1.6; color: #cbd5e1;">
                                Hello <strong style="color: #f8fafc;">{user_display}</strong>,
                            </p>
                            <p style="margin: 0 0 18px 0; font-size: 14px; line-height: 1.6; color: #94a3b8;">
                                The password for your CyberShieldAI account (<code style="color: #38bdf8; background: rgba(56, 189, 248, 0.1); padding: 2px 6px; border-radius: 4px;">{clean_email}</code>) was successfully updated on <strong>{timestamp}</strong>.
                            </p>

                            <div style="background: rgba(34, 197, 94, 0.08); border-left: 3px solid #22c55e; border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 20px 0;">
                                <p style="margin: 0; font-size: 13px; line-height: 1.5; color: #86efac;">
                                    ✓ If you made this change, you can safely disregard this message.
                                </p>
                            </div>

                            <div style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid #ef4444; border-radius: 0 8px 8px 0; padding: 12px 16px; margin: 20px 0 0 0;">
                                <p style="margin: 0; font-size: 12px; line-height: 1.5; color: #fca5a5;">
                                    <strong>⚠ Did not make this change?</strong> Please secure your account immediately or notify your security administrator.
                                </p>
                            </div>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 32px; background: #0b1329; border-top: 1px solid rgba(255, 255, 255, 0.06); text-align: center;">
                            <p style="margin: 0; font-size: 11px; color: #64748b; line-height: 1.5;">
                                CyberShieldAI Security Operations<br>
                                Automated Identity &amp; Access Protection
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""

    from alerts.email_api import send_https_email
    return send_https_email(
        to_email=clean_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
    )
