import json
import logging
import os
import re
import secrets
import sys
import threading
import traceback
from datetime import datetime

logger = logging.getLogger("cybershield.routes")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import flash, jsonify, redirect, render_template, request, send_file, session, url_for

from dashboard.pdf_generator import (
    _build_empty_state_pdf,
    _build_ip_scan_pdf,
    _build_url_scan_pdf,
    _determine_latest_scan_type,
)
from dashboard.scan_jobs import (
    SCAN_JOBS,
    SCAN_JOBS_LOCK,
    _new_job,
    _run_ip_scan_job,
    _run_url_scan_job,
)
from database.db_helpers import (
    get_db_connection,
    get_ip_scan_context,
    get_latest_host_status,
    get_latest_ip,
    get_latest_url_scan,
    get_url_scan_dashboard_context,
)

from alerts.dashboard_alerts import (
    get_recent_alerts,
    get_alert_statistics
)

from database.save_url_intelligence import save_url_intelligence
from database.ssl_results import get_latest_ssl, save_ssl, get_previous_ssl
from database.security_headers_db import get_previous_security_headers
from database.security_posture import save_security_posture, get_previous_security_posture
from database.monitoring_helpers import (
    get_monitored_targets,
    add_monitored_target,
    delete_monitored_target,
    enable_monitoring,
    disable_monitoring,
)
from scanner.banner_interpreter import interpret_banner
from scanner.recommendation_engine import generate_recommendations
from scanner.ssl_scanner import analyze_ssl
from scanner.technology_detector import detect_technology, classify_technologies
from scanner.url_intelligence import analyze_url_intelligence
from scanner.url_scanner import scan_url, score_to_risk_level
from ai.ai_engine import run_ai_engine
from scanner.scan_comparator import compare_url_scans
from scanner.scan_timeline import generate_scan_timeline
from dashboard.auth import (
    is_authenticated,
    login_user,
    logout_user,
    is_safe_url,
    get_current_user,
)
from database.user_helpers import verify_user_credentials, create_user, has_users

def register_routes(app):
    """Registers all web dashboard routes on the Flask app."""

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        # If users already exist, setup is locked
        if has_users():
            return redirect(url_for("login"))

        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not username:
                error = "Username is required."
            elif len(password) < 4:
                error = "Password must be at least 4 characters long."
            elif password != confirm_password:
                error = "Passwords do not match."
            else:
                try:
                    create_user(
                        username=username,
                        password=password,
                        role="ADMIN",
                        email=email,
                        is_active=1,
                    )
                    user = verify_user_credentials(username, password)
                    if user:
                        login_user(user)
                        return redirect(url_for("dashboard"))
                    return redirect(url_for("login"))
                except Exception as e:
                    error = f"Setup failed: {str(e)}"

        return render_template("setup.html", error=error)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        error = None
        if request.method == "POST":
            import re
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            # 1. Validation
            if not username:
                error = "Username is required."
            elif len(username) < 3 or len(username) > 30:
                error = "Username must be between 3 and 30 characters long."
            elif not re.match(r"^[a-zA-Z0-9_.-]+$", username):
                error = "Username can only contain letters, numbers, underscores, dots, and hyphens."
            elif not email:
                error = "Email address is required."
            elif not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
                error = "Please enter a valid email address."
            elif not password or len(password) < 6:
                error = "Password must be at least 6 characters long."
            elif password != confirm_password:
                error = "Passwords do not match."
            else:
                from database.user_helpers import get_user_by_username, get_user_by_email
                if get_user_by_username(username):
                    error = "This username is already taken. Please choose another."
                elif get_user_by_email(email):
                    error = "An account with this email address already exists. Please sign in."
                else:
                    try:
                        from werkzeug.security import generate_password_hash
                        from alerts.otp_service import generate_secure_otp, hash_otp, get_otp_config, send_verification_otp_email
                        from database.otp_helpers import create_pending_registration, delete_pending_registration

                        # 2. Hash password & generate secure 6-digit OTP
                        password_hash = generate_password_hash(password)
                        otp = generate_secure_otp(6)
                        otp_hash = hash_otp(otp)
                        otp_cfg = get_otp_config()

                        # 3. Send OTP email via HTTPS Email API first
                        sent, send_msg = send_verification_otp_email(
                            to_email=email,
                            username=username,
                            otp=otp,
                            expires_in_minutes=otp_cfg["expiry_minutes"],
                        )

                        if not sent:
                            error = f"{send_msg}"
                            return render_template(
                                "register.html",
                                error=error,
                                username=username,
                                email=email,
                            )

                        # 4. Store pending registration once email is successfully dispatched
                        reg_id = create_pending_registration(
                            username=username,
                            email=email,
                            password_hash=password_hash,
                            otp_hash=otp_hash,
                            expires_in_minutes=otp_cfg["expiry_minutes"],
                            max_attempts=otp_cfg["max_attempts"],
                        )

                        # 5. Save session context
                        session["pending_registration_id"] = reg_id
                        session["pending_email"] = email
                        session.modified = True

                        try:
                            from database.security_activity_helpers import log_security_activity
                            log_security_activity("REGISTRATION", "SUCCESS", username=username, email=email, details="New account verification initiated")
                        except Exception:
                            pass

                        flash(f"A 6-digit verification code has been sent to {email}. Please enter it below to activate your account.", "info")
                        return redirect(url_for("verify_otp"))
                    except Exception as e:
                        error = "Unable to send the verification email right now. Please try again later."

        return render_template(
            "register.html",
            error=error,
            username=request.form.get("username", "") if request.method == "POST" else "",
            email=request.form.get("email", "") if request.method == "POST" else "",
        )

    @app.route("/verify-otp", methods=["GET", "POST"])
    def verify_otp():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        reg_id = session.get("pending_registration_id")
        if not reg_id:
            flash("No active registration verification session found. Please register first.", "error")
            return redirect(url_for("register"))

        from database.otp_helpers import (
            get_pending_registration,
            increment_pending_attempts,
            delete_pending_registration,
        )
        pending = get_pending_registration(reg_id)
        if not pending:
            session.pop("pending_registration_id", None)
            session.pop("pending_email", None)
            flash("Your verification session has expired or was already completed. Please register or sign in.", "error")
            return redirect(url_for("register"))

        error = None
        if request.method == "POST":
            otp = request.form.get("otp", "").strip()

            if not otp or len(otp) != 6 or not otp.isdigit():
                error = "Please enter a valid 6-digit numeric verification code."
            else:
                from datetime import datetime, timezone
                # Check expiration
                try:
                    exp_time = datetime.fromisoformat(pending["expires_at"])
                    if exp_time.tzinfo is None:
                        exp_time = exp_time.replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    is_expired = now_utc > exp_time
                except Exception:
                    is_expired = False

                if is_expired:
                    error = "Your verification code has expired. Please click 'Resend Code' to receive a new one."
                elif pending["attempts"] >= pending["max_attempts"]:
                    delete_pending_registration(reg_id)
                    session.pop("pending_registration_id", None)
                    session.pop("pending_email", None)
                    flash("Maximum verification attempts exceeded. For security, your pending registration has been cancelled. Please register again.", "error")
                    return redirect(url_for("register"))
                else:
                    # Increment attempts
                    new_attempts = increment_pending_attempts(reg_id)
                    from alerts.otp_service import verify_otp_hash
                    
                    if not verify_otp_hash(pending["otp_hash"], otp):
                        remaining = max(0, pending["max_attempts"] - new_attempts)
                        if remaining == 0:
                            delete_pending_registration(reg_id)
                            session.pop("pending_registration_id", None)
                            session.pop("pending_email", None)
                            flash("Maximum verification attempts exceeded. Pending registration cancelled. Please register again.", "error")
                            return redirect(url_for("register"))
                        else:
                            error = f"Invalid verification code. {remaining} attempt(s) remaining."
                    else:
                        # Correct OTP! Activate account as normal USER role
                        from database.user_helpers import create_user_with_hash, get_user_by_username, get_user_by_email
                        
                        # Guard against race conditions
                        if get_user_by_username(pending["username"]) or get_user_by_email(pending["email"]):
                            delete_pending_registration(reg_id)
                            session.pop("pending_registration_id", None)
                            session.pop("pending_email", None)
                            flash("An account with this username or email already exists. Please sign in.", "error")
                            return redirect(url_for("login"))

                        create_user_with_hash(
                            username=pending["username"],
                            password_hash=pending["password_hash"],
                            role="USER",
                            email=pending["email"],
                            is_active=1,
                            auth_provider="local",
                        )

                        try:
                            from database.security_activity_helpers import log_security_activity
                            log_security_activity("REGISTRATION", "SUCCESS", username=pending["username"], email=pending["email"], details="New user account registered and activated")
                            log_security_activity("OTP_VERIFIED", "SUCCESS", username=pending["username"], email=pending["email"], details="Registration email verification OTP confirmed")
                        except Exception:
                            pass

                        # Clean up pending record and session
                        delete_pending_registration(reg_id)
                        session.pop("pending_registration_id", None)
                        session.pop("pending_email", None)

                        flash("Your email has been verified and your account is active! Please sign in below.", "success")
                        return redirect(url_for("login"))

        return render_template(
            "verify_otp.html",
            error=error,
            email=pending["email"],
            expires_at=pending["expires_at"],
        )

    @app.route("/resend-otp", methods=["GET", "POST"])
    def resend_otp():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        reg_id = session.get("pending_registration_id")
        if not reg_id:
            flash("No active registration verification session found. Please register first.", "error")
            return redirect(url_for("register"))

        from database.otp_helpers import get_pending_registration, update_pending_otp
        pending = get_pending_registration(reg_id)
        if not pending:
            session.pop("pending_registration_id", None)
            session.pop("pending_email", None)
            flash("Your registration session expired. Please register again.", "error")
            return redirect(url_for("register"))

        from datetime import datetime, timezone
        from alerts.otp_service import get_otp_config, generate_secure_otp, hash_otp, send_verification_otp_email

        otp_cfg = get_otp_config()
        cooldown = otp_cfg["resend_cooldown"]

        # Check rate-limit cooldown
        try:
            last_resend = datetime.fromisoformat(pending["last_resend_at"])
            if last_resend.tzinfo is None:
                last_resend = last_resend.replace(tzinfo=timezone.utc)
            now_utc = datetime.now(timezone.utc)
            elapsed = (now_utc - last_resend).total_seconds()
            if elapsed < cooldown:
                wait_sec = int(cooldown - elapsed)
                flash(f"Please wait {wait_sec} seconds before requesting a new verification code.", "error")
                return redirect(url_for("verify_otp"))
        except Exception:
            pass

        # Generate new OTP, hash, and invalidate old OTP
        new_otp = generate_secure_otp(6)
        new_otp_hash = hash_otp(new_otp)
        update_pending_otp(reg_id, new_otp_hash, expires_in_minutes=otp_cfg["expiry_minutes"])

        # Send new OTP email
        sent, send_msg = send_verification_otp_email(
            to_email=pending["email"],
            username=pending["username"],
            otp=new_otp,
            expires_in_minutes=otp_cfg["expiry_minutes"],
        )

        if sent:
            flash(f"A new 6-digit verification code has been sent to {pending['email']}.", "success")
        else:
            flash("Unable to send the verification email right now. Please try again later.", "error")

        return redirect(url_for("verify_otp"))

    # =========================================================================
    # FORGOT PASSWORD / PASSWORD RECOVERY SYSTEM
    # =========================================================================

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        error = None
        input_val = ""

        if request.method == "POST":
            input_val = request.form.get("email", "").strip()

            if not input_val:
                error = "Please enter your username or registered email address."
            else:
                from database.user_helpers import get_user_by_email, get_user_by_username
                from database.password_reset_helpers import create_password_reset_request
                from alerts.otp_service import (
                    generate_secure_otp,
                    hash_otp,
                    get_otp_config,
                    send_password_reset_otp_email,
                )

                if "@" in input_val:
                    user = get_user_by_email(input_val.lower())
                else:
                    user = get_user_by_username(input_val)

                otp_cfg = get_otp_config()

                if user and user.get("is_active", 1) and user.get("email"):
                    target_email = user["email"].strip().lower()
                    # Generate cryptographically secure 6-digit OTP
                    otp = generate_secure_otp(6)
                    otp_hash = hash_otp(otp)

                    # Create single-use 10-minute reset request
                    reset_id = create_password_reset_request(
                        user_id=user["id"],
                        email=target_email,
                        otp_hash=otp_hash,
                        expires_in_minutes=otp_cfg["expiry_minutes"],
                        max_attempts=otp_cfg["max_attempts"],
                    )

                    # Send recovery email via Brevo / HTTPS email API
                    print(f"[EMAIL] Password reset email: sending to {target_email}", flush=True)
                    sent, send_msg = send_password_reset_otp_email(
                        to_email=target_email,
                        username=user.get("username", ""),
                        otp=otp,
                        expires_in_minutes=otp_cfg["expiry_minutes"],
                    )
                    if not sent:
                        print(f"[EMAIL] Password reset email dispatch failed: {send_msg}", flush=True)
                        logger.warning(f"[EMAIL] Password reset dispatch failed for {target_email}: {send_msg}")

                    session["password_reset_id"] = reset_id
                    session["password_reset_email"] = target_email
                    session.modified = True

                    try:
                        from database.security_activity_helpers import log_security_activity
                        log_security_activity("PASSWORD_RESET_REQUESTED", "SUCCESS", username=user.get("username", ""), email=target_email, details="Password recovery code requested")
                    except Exception:
                        pass
                else:
                    # Anti-enumeration placeholder session
                    print(f"[EMAIL] Password reset requested for unregistered/inactive account: {input_val} (anti-enumeration active)", flush=True)
                    session["password_reset_id"] = "nonexistent"
                    session["password_reset_email"] = input_val
                    session.modified = True

                # Generic response to prevent user enumeration
                flash("If this email address is registered, a password reset code has been sent.", "info")
                return redirect(url_for("verify_forgot_password_otp"))

        return render_template("forgot_password.html", error=error, email=input_val)

    @app.route("/forgot-password/verify", methods=["GET", "POST"])
    def verify_forgot_password_otp():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        reset_id = session.get("password_reset_id")
        stored_email = session.get("password_reset_email", "")

        if not reset_id or not stored_email:
            flash("Please initiate a password recovery request first.", "error")
            return redirect(url_for("forgot_password"))

        def _mask_email(e):
            parts = e.split("@")
            if len(parts) == 2 and len(parts[0]) > 2:
                return parts[0][:2] + "***@" + parts[1]
            return e

        masked_email = _mask_email(stored_email)

        # Handle non-existent email session consistently without revealing account absence
        if reset_id == "nonexistent":
            error = None
            if request.method == "POST":
                error = "Invalid or expired recovery code. Please check and try again."
            return render_template("verify_forgot_password_otp.html", error=error, email=masked_email)

        from database.password_reset_helpers import (
            get_password_reset_by_id,
            increment_password_reset_attempts,
            delete_password_reset,
            authorize_password_reset_token,
        )
        record = get_password_reset_by_id(reset_id)
        if not record or record.get("is_used"):
            session.pop("password_reset_id", None)
            session.pop("password_reset_email", None)
            flash("Your recovery session has expired or was already used. Please request a new recovery code.", "error")
            return redirect(url_for("forgot_password"))

        error = None
        if request.method == "POST":
            otp = request.form.get("otp", "").strip()

            if not otp or len(otp) != 6 or not otp.isdigit():
                error = "Please enter a valid 6-digit numeric verification code."
            else:
                from datetime import datetime, timezone
                try:
                    exp_time = datetime.fromisoformat(record["expires_at"])
                    if exp_time.tzinfo is None:
                        exp_time = exp_time.replace(tzinfo=timezone.utc)
                    is_expired = datetime.now(timezone.utc) > exp_time
                except Exception:
                    is_expired = False

                if is_expired:
                    error = "Your recovery code has expired. Please click 'Resend Code' to receive a new one."
                elif record["attempts"] >= record["max_attempts"]:
                    delete_password_reset(reset_id)
                    session.pop("password_reset_id", None)
                    session.pop("password_reset_email", None)
                    flash("Maximum verification attempts exceeded. For security, please request a new recovery code.", "error")
                    return redirect(url_for("forgot_password"))
                else:
                    from alerts.otp_service import verify_otp_hash, hash_otp
                    if not verify_otp_hash(record["otp_hash"], otp):
                        new_attempts = increment_password_reset_attempts(reset_id)
                        remaining = max(0, record["max_attempts"] - new_attempts)
                        if remaining <= 0:
                            delete_password_reset(reset_id)
                            session.pop("password_reset_id", None)
                            session.pop("password_reset_email", None)
                            flash("Maximum verification attempts exceeded. For security, please request a new recovery code.", "error")
                            return redirect(url_for("forgot_password"))
                        error = f"Invalid recovery code. {remaining} attempt(s) remaining."
                    else:
                        # OTP is valid! Generate high-entropy authorization token for /reset-password
                        reset_token = secrets.token_urlsafe(32)
                        authorize_password_reset_token(reset_id, hash_otp(reset_token))
                        session["password_reset_token"] = reset_token
                        session.modified = True
                        return redirect(url_for("reset_password"))

        return render_template(
            "verify_forgot_password_otp.html",
            error=error,
            email=masked_email,
        )

    @app.route("/forgot-password/resend", methods=["POST"])
    def resend_forgot_password_otp():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        reset_id = session.get("password_reset_id")
        stored_email = session.get("password_reset_email", "")

        if not reset_id or not stored_email:
            flash("Please initiate a password recovery request first.", "error")
            return redirect(url_for("forgot_password"))

        if reset_id == "nonexistent":
            flash("If this email address is registered, a new recovery code has been sent.", "info")
            return redirect(url_for("verify_forgot_password_otp"))

        from database.password_reset_helpers import get_password_reset_by_id, update_password_reset_otp
        record = get_password_reset_by_id(reset_id)
        if not record or record.get("is_used"):
            flash("Recovery session expired. Please start over.", "error")
            return redirect(url_for("forgot_password"))

        from datetime import datetime, timezone
        from alerts.otp_service import (
            get_otp_config,
            generate_secure_otp,
            hash_otp,
            send_password_reset_otp_email,
        )

        otp_cfg = get_otp_config()
        cooldown = otp_cfg["resend_cooldown"]

        # Check rate-limit cooldown
        try:
            last_resend = datetime.fromisoformat(record["last_resend_at"])
            if last_resend.tzinfo is None:
                last_resend = last_resend.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - last_resend).total_seconds()
            if elapsed < cooldown:
                wait_sec = int(cooldown - elapsed)
                flash(f"Please wait {wait_sec} seconds before requesting a new recovery code.", "error")
                return redirect(url_for("verify_forgot_password_otp"))
        except Exception:
            pass

        # Generate new OTP, update DB & dispatch email
        new_otp = generate_secure_otp(6)
        update_password_reset_otp(reset_id, hash_otp(new_otp), expires_in_minutes=otp_cfg["expiry_minutes"])

        from database.user_helpers import get_user_by_id
        user = get_user_by_id(record["user_id"])
        username = user.get("username", "") if user else ""

        print("[EMAIL] Password reset resend email: sending", flush=True)
        sent, send_msg = send_password_reset_otp_email(
            to_email=record["email"],
            username=username,
            otp=new_otp,
            expires_in_minutes=otp_cfg["expiry_minutes"],
        )
        if not sent:
            print(f"[EMAIL] Password reset resend dispatch failed: {send_msg}", flush=True)
            logger.warning(f"[EMAIL] Password reset resend dispatch failed for {record['email']}: {send_msg}")

        flash(f"A new 6-digit recovery code has been sent.", "success")
        return redirect(url_for("verify_forgot_password_otp"))

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        reset_id = session.get("password_reset_id")
        reset_token = session.get("password_reset_token")

        if not reset_id or not reset_token or reset_id == "nonexistent":
            flash("Please verify your recovery code first.", "error")
            return redirect(url_for("forgot_password"))

        from database.password_reset_helpers import (
            get_password_reset_by_id,
            verify_and_consume_reset_token,
            delete_password_reset,
        )

        record = get_password_reset_by_id(reset_id)
        if not record or record.get("is_used"):
            session.pop("password_reset_id", None)
            session.pop("password_reset_token", None)
            session.pop("password_reset_email", None)
            flash("Your password reset session has expired or has already been used.", "error")
            return redirect(url_for("login"))

        error = None
        if request.method == "POST":
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not password or len(password) < 6:
                error = "Password must be at least 6 characters long."
            elif password != confirm_password:
                error = "Passwords do not match."
            else:
                success, user_id = verify_and_consume_reset_token(reset_id, reset_token)
                if not success or not user_id:
                    session.pop("password_reset_id", None)
                    session.pop("password_reset_token", None)
                    session.pop("password_reset_email", None)
                    flash("Invalid or expired reset token. Please request a new recovery code.", "error")
                    return redirect(url_for("forgot_password"))

                from database.user_helpers import get_user_by_id, update_user_password
                user = get_user_by_id(user_id)
                if not user:
                    flash("Account not found. Please register.", "error")
                    return redirect(url_for("register"))

                # Securely hash and update user's password
                update_user_password(user["username"], password)
                delete_password_reset(reset_id)

                # Send security confirmation email
                from alerts.otp_service import send_password_changed_notification_email
                send_password_changed_notification_email(
                    to_email=user.get("email", ""),
                    username=user.get("username", ""),
                )

                # Clear reset session
                session.pop("password_reset_id", None)
                session.pop("password_reset_token", None)
                session.pop("password_reset_email", None)
                session.modified = True

                flash("Password reset successfully. Please sign in with your new password.", "success")
                return redirect(url_for("login"))

        return render_template("reset_password.html", error=error)

    @app.route("/auth/google")
    def google_login():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        google_client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
        google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()

        if not google_client_id or not google_client_secret:
            flash("Google Sign-In is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.", "error")
            return redirect(url_for("login"))

        redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip() or url_for("google_callback", _external=True)

        # Generate cryptographically signed state for robust CSRF defense
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.secret_key, salt="oauth-state")
        state = serializer.dumps({"nonce": secrets.token_urlsafe(16)})
        session["oauth_state"] = state
        session.modified = True

        # Preserve target destination if safe
        next_url = request.args.get("next") or ""
        if next_url and is_safe_url(next_url) and not next_url.startswith("/login") and not next_url.startswith("/auth"):
            session["oauth_next"] = next_url
        else:
            session.pop("oauth_next", None)

        import urllib.parse
        params = {
            "client_id": google_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "prompt": "select_account",
        }
        google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
        return redirect(google_auth_url)

    @app.route("/auth/google/callback")
    def google_callback():
        if is_authenticated():
            return redirect(url_for("dashboard"))

        # Check for provider error
        error = request.args.get("error")
        if error:
            flash(f"Google authentication error: {error}", "error")
            return redirect(url_for("login"))

        # Validate OAuth state parameter (Dual check: Session matching & Cryptographic signature with 10-minute expiry)
        returned_state = request.args.get("state")
        session_state = session.pop("oauth_state", None)

        is_valid_state = False
        if returned_state and session_state and returned_state == session_state:
            is_valid_state = True
        elif returned_state:
            from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
            serializer = URLSafeTimedSerializer(app.secret_key, salt="oauth-state")
            try:
                data = serializer.loads(returned_state, max_age=600)
                if data and "nonce" in data:
                    is_valid_state = True
            except (BadSignature, SignatureExpired):
                is_valid_state = False

        if not is_valid_state:
            flash("Invalid or missing OAuth state parameter (CSRF protection). Please try again.", "error")
            return redirect(url_for("login"))

        # Validate authorization code
        code = request.args.get("code")
        if not code:
            flash("Missing authorization code from Google.", "error")
            return redirect(url_for("login"))

        google_client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
        google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
        redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip() or url_for("google_callback", _external=True)

        if not google_client_id or not google_client_secret:
            flash("Google OAuth credentials are missing on the server.", "error")
            return redirect(url_for("login"))

        try:
            import urllib.request
            import urllib.parse
            import json

            # 1. Exchange authorization code for access token
            token_url = "https://oauth2.googleapis.com/token"
            token_payload = urllib.parse.urlencode({
                "code": code,
                "client_id": google_client_id,
                "client_secret": google_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }).encode("utf-8")

            token_req = urllib.request.Request(token_url, data=token_payload, method="POST")
            token_req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(token_req, timeout=10) as resp:
                token_resp = json.loads(resp.read().decode("utf-8"))

            access_token = token_resp.get("access_token")
            if not access_token:
                flash("Failed to obtain access token from Google.", "error")
                return redirect(url_for("login"))

            # 2. Retrieve verified user profile from OIDC userinfo endpoint
            userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
            userinfo_req = urllib.request.Request(userinfo_url)
            userinfo_req.add_header("Authorization", f"Bearer {access_token}")
            with urllib.request.urlopen(userinfo_req, timeout=10) as user_resp:
                user_info = json.loads(user_resp.read().decode("utf-8"))

            google_sub = user_info.get("sub")
            google_email = (user_info.get("email") or "").strip().lower()
            google_name = user_info.get("name", "")
            avatar_url = user_info.get("picture", "")

            if not google_sub or not google_email:
                flash("Failed to retrieve verified identity from Google.", "error")
                return redirect(url_for("login"))

            from database.user_helpers import get_user_by_google_sub, get_user_by_email, create_google_user

            # 3. Check if user with this google_sub already exists
            user = get_user_by_google_sub(google_sub)

            if not user:
                # Check if existing user has the same verified email and link automatically
                existing_email_user = get_user_by_email(google_email)
                if existing_email_user:
                    from database.user_helpers import link_google_identity, get_user_by_id
                    link_google_identity(existing_email_user["id"], google_sub, avatar_url=avatar_url)
                    user = get_user_by_id(existing_email_user["id"])
                else:
                    # First-time Google login: if system has 0 users (first setup), grant ADMIN, else default to VIEWER
                    from database.user_helpers import has_users
                    initial_role = "ADMIN" if not has_users() else "VIEWER"
                    user = create_google_user(
                        email=google_email,
                        google_sub=google_sub,
                        full_name=google_name,
                        avatar_url=avatar_url,
                        role=initial_role,
                    )

            if not user or not user.get("is_active", 1):
                flash("Your account is deactivated or could not be verified.", "error")
                return redirect(url_for("login"))

            # Always sync avatar_url if provided by Google
            if avatar_url:
                from database.user_helpers import link_google_identity
                link_google_identity(user["id"], google_sub, avatar_url=avatar_url)
                user["avatar_url"] = avatar_url

            login_user(user)

            next_url = session.pop("oauth_next", None)
            if next_url and is_safe_url(next_url) and not next_url.startswith("/login") and not next_url.startswith("/auth"):
                return redirect(next_url)

            flash(f"Welcome, {user.get('full_name') or user.get('username')}! Signed in with Google.", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            flash(f"Google authentication error: {str(e)}", "error")
            return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        # If user is already authenticated, redirect to / or safe next
        if is_authenticated():
            next_url = request.args.get("next") or request.form.get("next")
            if next_url and is_safe_url(next_url) and not next_url.startswith("/login"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        error = None
        next_url = request.args.get("next") or request.form.get("next") or ""

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            user = verify_user_credentials(username, password)
            if user:
                login_user(user)
                try:
                    from database.security_activity_helpers import log_security_activity
                    log_security_activity("LOGIN_SUCCESS", "SUCCESS", username=user.get("username"), email=user.get("email"), user_id=user.get("id"), details="Successful local credential authentication")
                except Exception:
                    pass

                if next_url and is_safe_url(next_url) and not next_url.startswith("/login") and not next_url.startswith("/logout"):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))
            else:
                try:
                    from database.security_activity_helpers import log_security_activity
                    log_security_activity("LOGIN_FAILED", "FAILED", username=username, email=username if "@" in username else "", details="Invalid credentials supplied")
                except Exception:
                    pass
                error = "Invalid username, email, or password."

        return render_template(
            "login.html",
            error=error,
            next_url=next_url if is_safe_url(next_url) else "",
            username=request.form.get("username", "") if request.method == "POST" else "",
        )

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        try:
            from database.security_activity_helpers import log_security_activity
            log_security_activity("LOGOUT", "SUCCESS", username=session.get("username"), email=session.get("email"), user_id=session.get("user_id"), details="User signed out")
        except Exception:
            pass
        logout_user()
        return redirect(url_for("login"))

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "service": "CyberShieldAI"}), 200

    @app.route("/readiness", methods=["GET"])
    def readiness():
        return jsonify({"status": "ready", "service": "CyberShieldAI"}), 200

    @app.route("/alerts", methods=["GET"])
    def alerts_page():
        return redirect(url_for("dashboard"))

    @app.route("/")
    def dashboard():

        data = get_ip_scan_context()

        url_ctx = get_url_scan_dashboard_context()

        # ===============================
        # ALERTS
        # ===============================

        recent_alerts = get_recent_alerts()

        alert_stats = get_alert_statistics()

        return render_template(

            "dashboard/dashboard.html",

            active_page="dashboard",

            page_title="Security Operations Dashboard",

            page_subtitle="Live network posture and vulnerability overview",

            stats=data["stats"],

            assets=data["assets"],

            recent_activity=data["recent_activity"],

            latest_ip=data["latest_ip"],

            host=data["host"],

            ports_data=data["ports_data"],

            services=data["services"],

            vulnerabilities_data=data["vulnerabilities_data"],

            cves_data=data["cves_data"],

            recommendations=data["recommendations"],

            os_info=data["os_info"],

            risk=data["risk"],

            chart_data=data["chart_data"],

            recent_alerts=recent_alerts,

            alert_stats=alert_stats,

            **url_ctx

        )

    @app.route("/ip-scan-result")
    def ip_scan_result_page():
        data = get_ip_scan_context()

        return render_template(
            "ip_result.html",
            active_page="ip_scan_result",
            page_title="IP Scan Result",
            page_subtitle="Full detail for the latest IP/host scan",
            stats=data["stats"],
            latest_ip=data["latest_ip"],
            host=data["host"],
            ports_data=data["ports_data"],
            services=data["services"],
            vulnerabilities_data=data["vulnerabilities_data"],
            cves_data=data["cves_data"],
            recommendations=data["recommendations"],
            os_info=data["os_info"],
            risk=data["risk"],
        )

    @app.route("/url-scan-result")
    def url_scan_result_page():
        latest_url_scan = get_latest_url_scan()
        if not latest_url_scan:
            return render_template(
                "url_result.html",
                result=None,
                active_page="url_scan_result",
                page_title="URL Scan Result",
                page_subtitle="Full detail for the latest URL scan",
                ai_result=None,
                technology=[],
                classified_technology={},
                ports=[],
                services=[],
                os_info=None,
                vulnerabilities=[],
                risk_summary=None,
                recommendations=[],
                remarks=[],
                ssl_info=None,
                url_info=None,
                history_scans=[],
                scan_comparison=None,
                scan_timeline=[],
                virustotal=None,
                cves=[],
            )

        return _render_url_result(latest_url_scan["ip"] or "Unknown")

    def _render_url_result(ip):
        conn = get_db_connection()

        result = conn.execute(
            """
            SELECT *
            FROM url_scan_results
            WHERE ip=?
            ORDER BY id DESC
            LIMIT 1
        """,
            (ip,),
        ).fetchone()

        if result:
            result = dict(result)

        ports = conn.execute(
            """
            SELECT *
            FROM ports
            WHERE id IN (
                SELECT MAX(id) FROM ports WHERE ip=? GROUP BY port
            )
            ORDER BY port ASC
        """,
            (ip,),
        ).fetchall()

        services = conn.execute(
            """
            SELECT *
            FROM service_versions
            WHERE id IN (
                SELECT MAX(id) FROM service_versions WHERE ip=? GROUP BY port
            )
            ORDER BY port ASC
        """,
            (ip,),
        ).fetchall()

        os_info = conn.execute(
            """
            SELECT *
            FROM os_info
            WHERE ip=?
            ORDER BY id DESC
            LIMIT 1
        """,
            (ip,),
        ).fetchone()

        if os_info:
            os_info = dict(os_info)

        raw_vulnerabilities = conn.execute(
            """
            SELECT *
            FROM vulnerabilities
            WHERE id IN (
                SELECT MAX(id) FROM vulnerabilities WHERE ip=? GROUP BY port, risk, service
            )
            ORDER BY port ASC
        """,
            (ip,),
        ).fetchall()


        from ai.ai_rules import enrich_vulnerability_with_cvss
        vulnerabilities = [enrich_vulnerability_with_cvss(v) for v in raw_vulnerabilities]

        cves = conn.execute(
            """
            SELECT *
            FROM cves
            WHERE id IN (
                SELECT MAX(id) FROM cves WHERE ip=? GROUP BY cve_id, port
            )
            ORDER BY
                CASE LOWER(severity)
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END,
                port ASC
        """,
            (ip,),
        ).fetchall()

        risk_summary = conn.execute(
            """
            SELECT *
            FROM risk_summary
            WHERE ip=?
            ORDER BY id DESC
            LIMIT 1
        """,
            (ip,),
        ).fetchone()


        if risk_summary:
            risk_summary = dict(risk_summary)

        technology_row = conn.execute(
            """
            SELECT *
            FROM technology_detection
            WHERE ip=?
            ORDER BY id DESC
            LIMIT 1
        """,
            (ip,),
        ).fetchone()

        technology = None
        server_val = "Unknown"
        tech_list = []

        if technology_row:
            if "server" in technology_row.keys() and technology_row["server"]:
                server_val = technology_row["server"]

            if technology_row["technologies"]:
                try:
                    technology = json.loads(technology_row["technologies"])
                except (TypeError, ValueError):
                    technology = technology_row["technologies"]

        if isinstance(technology, dict):
            server_val = technology.get("server", server_val)
            tech_list = technology.get("technologies", [])
        elif isinstance(technology, list):
            tech_list = technology
        elif isinstance(technology, str):
            tech_list = [t.strip() for t in technology.split(",") if t.strip()]

        classified_technology = classify_technologies(tech_list, server_val)

        recommendations = generate_recommendations(
            ports, services, os_info, vulnerabilities
        )

        conn.close()

        remarks = []
        if result and result["remarks"]:
            remarks = [r.strip() for r in str(result["remarks"]).split("|") if r.strip()]

        ssl_info = None
        if result and result["domain"]:
            ssl_info = get_latest_ssl(result["domain"])

        current_scan_id = (result.get("scan_id") if result and hasattr(result, "keys") and "scan_id" in result.keys() else None)
        if not current_scan_id:
            from scanner.scan_snapshot import get_latest_scan_id
            current_scan_id = get_latest_scan_id(ip)

        url_info = {}
        try:
            if result and result["url"]:
                url_info = analyze_url_intelligence(result["url"], scan_id=current_scan_id)
        except Exception as e:
            print("URL Intelligence Error:", e)
            url_info = {}

        # =====================================
        # AI Security Engine
        # =====================================

        ai_result = {}
        try:
            effective_risk = risk_summary or {
                "total_score": (result["score"] if result and "score" in result.keys() and result["score"] is not None else 0),
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "risk_level": (result["risk"] if result and "risk" in result.keys() and result["risk"] else "Low")
            }
            ai_result = run_ai_engine(
                risk=effective_risk,
                ports=ports,
                vulnerabilities=vulnerabilities,
                ssl_info=ssl_info,
                url_info=url_info,
                technology=technology,
                result=result,
                ports_scanned=bool(ports and len(ports) > 0),
                ssl_scanned=bool(ssl_info),
                dns_scanned=bool(url_info and isinstance(url_info, dict) and url_info.get("dns")),
                technology_scanned=bool(technology),
                vulnerability_scanned=bool(vulnerabilities and len(vulnerabilities) > 0)
            )
            if ai_result and isinstance(ai_result, dict):
                try:
                    save_security_posture(
                        scan_id=current_scan_id,
                        ip=ip,
                        url=result["url"] if result and "url" in result.keys() else ip,
                        security_score=ai_result.get("score"),
                        security_grade=ai_result.get("grade", "N/A"),
                        threat_score=result.get("score", 0) if result and "score" in result.keys() else 0,
                        risk_level=result.get("risk", "Low") if result and "risk" in result.keys() else "Low",
                        assessment_status=ai_result.get("status", "ASSESSED"),
                        scan_time=result.get("scan_time") if result and "scan_time" in result.keys() else None
                    )
                except Exception as post_err:
                    print("Security Posture Save Error:", post_err)
        except Exception as e:
            print("AI Engine Error:", e)
            ai_result = {}

        # =====================================
        # Historical Trend Analysis & Comparison
        # =====================================
        from scanner.scan_snapshot import get_scan_snapshot, get_previous_scan_id
        conn2 = get_db_connection()
        posture_target = result["domain"] if result and "domain" in result.keys() else ip

        previous_scan_id = get_previous_scan_id(posture_target, current_scan_id)

        # Build Empirical Current and Previous Snapshots via scan_id
        current_scan_dict = get_scan_snapshot(current_scan_id)
        if not current_scan_dict:
            current_scan_dict = {
                "scan_id": current_scan_id,
                "score": ai_result.get("score"),
                "status": ai_result.get("status", "ASSESSED"),
                "grade": ai_result.get("grade", "N/A"),
                "threat_score": result.get("score", 0) if result else 0,
                "protocol": result.get("protocol", "HTTPS") if result else "HTTPS",
                "open_ports": [p["port"] for p in ports] if ports else [],
                "tls_version": ssl_info.get("tls_version") if ssl_info else None,
                "ssl_data": ssl_info,
                "headers": {},
                "headers_available": False,
                "waf": None,
                "waf_available": False,
                "technologies": [],
                "technologies_available": False,
                "cves": [],
                "scan_time": result.get("scan_time", "Current") if result else "Current"
            }

        previous_scan_dict = get_scan_snapshot(previous_scan_id) if previous_scan_id else {"has_previous": False}
        if previous_scan_dict and "scan_id" in previous_scan_dict:
            previous_scan_dict["has_previous"] = True

        # Fetch Posture History Records for Trend Chart/Table (Grouped by scan_id / id)
        like_posture_target = f"%{posture_target}%"
        posture_history_rows = conn2.execute(
            """
            SELECT *
            FROM security_posture
            WHERE ip = ? OR url = ? OR url LIKE ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (ip, posture_target, like_posture_target)
        ).fetchall()
        
        history_scans = []
        for r in posture_history_rows:
            d = dict(r)
            d["security_score"] = d.get("security_score")
            d["security_grade"] = d.get("security_grade")
            d["score"] = d.get("security_score")
            d["grade"] = d.get("security_grade")
            d["risk"] = d.get("risk_level", "Low")
            d["protocol"] = result.get("protocol", "HTTPS") if result else "HTTPS"
            history_scans.append(d)

        conn2.close()

        scan_comparison = compare_url_scans(current_scan_dict, previous_scan_dict)
        scan_timeline = generate_scan_timeline(
            scan_time_str=result["scan_time"] if result and "scan_time" in result.keys() else None,
            url_info=url_info,
            ssl_info=ssl_info,
            ai_result=ai_result
        )

        from scanner.virustotal_scanner import get_latest_virustotal
        virustotal = get_latest_virustotal(
            url=result["url"] if result and "url" in result.keys() else None,
            domain=result["domain"] if result and "domain" in result.keys() else None,
            scan_id=current_scan_id
        )

        return render_template(
            "url_result.html",
            active_page="url_scan_result",
            page_title="URL Scan Result",
            page_subtitle="Full detail for this URL scan",
            result=result,
            technology=technology,
            classified_technology=classified_technology,
            ports=ports,
            services=services,
            os_info=os_info,
            vulnerabilities=vulnerabilities,
            risk_summary=risk_summary,
            recommendations=recommendations,
            remarks=remarks,
            ssl_info=ssl_info,
            url_info=url_info,
            ai_result=ai_result,
            history_scans=history_scans,
            scan_comparison=scan_comparison,
            scan_timeline=scan_timeline,
            virustotal=virustotal,
            cves=cves,
        )




    @app.route("/url-result/<ip>")
    def url_result_page(ip):
        return _render_url_result(ip)

    @app.route("/scan", methods=["POST"])
    def scan():
        target = request.form.get("target", "").strip()
        mode = request.form.get("mode", "quick").strip().lower()

        if not target:
            return "No target IP provided"

        ports = "1-65535" if mode == "full" else "top-1000"
        job_id = _new_job(target, job_type="ip")

        thread = threading.Thread(
            target=_run_ip_scan_job, args=(job_id, target, ports), daemon=True
        )
        thread.start()
        return redirect(url_for("scanning_status_page", job_id=job_id))

    @app.route("/scanning/<job_id>")
    def scanning_status_page(job_id):
        with SCAN_JOBS_LOCK:
            job = SCAN_JOBS.get(job_id)

        if not job:
            return redirect(url_for("dashboard"))
        return render_template("scanning.html", job=job)

    @app.route("/scan-status/<job_id>")
    def scan_status(job_id):
        """JSON polling endpoint used by scanning.html to show live progress."""
        with SCAN_JOBS_LOCK:
            job = SCAN_JOBS.get(job_id)
            if job and job.get("status") == "running":
                import time
                elapsed = time.time() - job.get("start_time", time.time())
                if elapsed > 300:
                    job["status"] = "error"
                    job["error"] = "Scan execution timed out after 300 seconds. Target host may be unresponsive or heavily firewalled."

        if not job:
            return jsonify({"status": "not_found"}), 404
        return jsonify(job)

    @app.route("/scan-url", methods=["POST"])
    def scan_url_route():
        url = request.form.get("url", "").strip()

        if not url:
            return redirect(url_for("dashboard"))

        job_id = _new_job(url, job_type="url")
        thread = threading.Thread(
            target=_run_url_scan_job, args=(job_id, url), daemon=True
        )
        thread.start()
        return redirect(url_for("scanning_status_page", job_id=job_id))

    @app.route("/ports")
    def view_ports():
        scope = request.args.get("scope", "latest")
        target = request.args.get("target", "")
        latest_ip = get_latest_ip()
        conn = get_db_connection()

        if scope == "all":
            rows = conn.execute(
                """
                SELECT ip, port, state, service, banner, scan_time
                FROM ports
                WHERE id IN (
                    SELECT MAX(id) FROM ports GROUP BY ip, port
                ) AND state = 'open'
                ORDER BY ip ASC, port ASC
            """
            ).fetchall()
        elif target:
            rows = conn.execute(
                """
                SELECT ip, port, state, service, banner, scan_time
                FROM ports
                WHERE id IN (
                    SELECT MAX(id) FROM ports WHERE ip = ? GROUP BY port
                ) AND state = 'open'
                ORDER BY port ASC
            """,
                (target,),
            ).fetchall()
        elif latest_ip:
            rows = conn.execute(
                """
                SELECT ip, port, state, service, banner, scan_time
                FROM ports
                WHERE id IN (
                    SELECT MAX(id) FROM ports WHERE ip = ? GROUP BY port
                ) AND state = 'open'
                ORDER BY port ASC
            """,
                (latest_ip,),
            ).fetchall()
        else:
            rows = []

        conn.close()
        meanings = [interpret_banner(r["service"], r["banner"]) for r in rows]

        return render_template(
            "ports.html",
            active_page="ports",
            page_title="Open Ports",
            page_subtitle="Open ports and service banners for " + ("all scanned assets" if scope == "all" else (f"target {target or latest_ip}")),
            rows=rows,
            meanings=meanings,
            latest_ip=latest_ip,
            scope=scope,
            current_target=target or (latest_ip if scope != "all" else "all"),
        )

    @app.route("/vulnerabilities")
    def view_vulnerabilities():
        latest_ip = get_latest_ip()
        conn = get_db_connection()

        if latest_ip:
            rows = conn.execute(
                """
                SELECT ip, port, service, risk, description, remediation, scan_time
                FROM vulnerabilities
                WHERE ip = ? AND id IN (
                    SELECT MAX(id) FROM vulnerabilities WHERE ip = ? GROUP BY port, service
                )
                ORDER BY
                    CASE LOWER(risk)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    port ASC
            """,
                (latest_ip, latest_ip),
            ).fetchall()
        else:
            rows = []

        conn.close()
        return render_template(
            "vulnerabilities.html",
            active_page="vulnerabilities",
            page_title="Vulnerabilities",
            page_subtitle=f"Active findings for target {latest_ip}" if latest_ip else "Active vulnerability findings",
            rows=rows,
            latest_ip=latest_ip,
        )

    @app.route("/cves")
    def view_cves():
        scope = request.args.get("scope", "latest")
        target = request.args.get("target", "")
        latest_ip = get_latest_ip()
        conn = get_db_connection()

        if scope == "all":
            raw_cves = conn.execute(
                """
                SELECT *
                FROM cves
                WHERE id IN (
                    SELECT MAX(id) FROM cves GROUP BY ip, cve_id, port
                )
                ORDER BY
                    CASE LOWER(severity)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    id DESC
            """
            ).fetchall()
        elif target:
            raw_cves = conn.execute(
                """
                SELECT *
                FROM cves
                WHERE id IN (
                    SELECT MAX(id) FROM cves WHERE ip = ? GROUP BY cve_id, port
                )
                ORDER BY
                    CASE LOWER(severity)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    port ASC
            """,
                (target,),
            ).fetchall()
        elif latest_ip:
            raw_cves = conn.execute(
                """
                SELECT *
                FROM cves
                WHERE id IN (
                    SELECT MAX(id) FROM cves WHERE ip = ? GROUP BY cve_id, port
                )
                ORDER BY
                    CASE LOWER(severity)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    port ASC
            """,
                (latest_ip,),
            ).fetchall()
        else:
            raw_cves = []

        from scanner.cve_scanner import get_cve_info
        rows = []
        for r in raw_cves:
            r_dict = dict(r)
            if not r_dict.get("cwe_id") or not r_dict.get("references"):
                info = get_cve_info(r_dict.get("port"), r_dict.get("service"))
                r_dict["cwe_id"] = r_dict.get("cwe_id") or info.get("cwe_id", "CWE-200")
                r_dict["cwe_name"] = r_dict.get("cwe_name") or info.get("cwe_name", "Exposure of Sensitive Information")
                cve_id_val = str(r_dict.get('cve_id', ''))
                default_ref = f"https://nvd.nist.gov/vuln/detail/{cve_id_val}" if (cve_id_val and not cve_id_val.startswith('CVE-GENERIC')) else f"https://nvd.nist.gov/vuln/search/results?query={r_dict.get('service', 'security')}"
                r_dict["references"] = r_dict.get("references") or info.get("references") or default_ref
            rows.append(r_dict)

        conn.close()
        return render_template(
            "cves.html",
            active_page="cves",
            page_title="CVE Database",
            page_subtitle="Matched CVEs and CWE mapping for " + ("all scanned assets catalog" if scope == "all" else (f"target {target or latest_ip}")),
            rows=rows,
            latest_ip=latest_ip,
            scope=scope,
            current_target=target or (latest_ip if scope != "all" else "all"),
        )


        conn.close()
        return render_template(
            "cves.html",
            active_page="cves",
            page_title="CVE Database",
            page_subtitle="Matched CVEs for the latest scan",
            rows=rows,
            latest_ip=latest_ip,
        )

    @app.route("/history")
    def history():
        conn = get_db_connection()
        rows = conn.execute(
            """
            SELECT id, target_ip, status, scan_time
            FROM scan_history
            ORDER BY id DESC
        """
        ).fetchall()
        if not rows:
            rows = conn.execute(
                """
                SELECT id, target_ip, status, scan_time
                FROM host_status
                ORDER BY id DESC
            """
            ).fetchall()
        conn.close()
        return render_template(
            "history.html",
            active_page="history",
            page_title="IP Scan History",
            page_subtitle="Every host scan that has been run",
            rows=rows,
        )

    @app.route("/url-history")
    def url_history():
        conn = get_db_connection()
        rows = conn.execute(
            """
            SELECT id, url, domain, ip, protocol, score, risk, scan_time
            FROM url_scan_results
            ORDER BY id DESC
        """
        ).fetchall()
        conn.close()
        return render_template(
            "url_history.html",
            active_page="url_history",
            page_title="URL Scan History",
            page_subtitle="Every URL scan that has been run",
            rows=rows,
        )

    @app.route("/risk-report")
    def risk_report():
        requested_target = request.args.get("target", "").strip()
        latest_ip = get_latest_ip()
        target_ip = requested_target if requested_target else latest_ip

        conn = get_db_connection()

        # 1. Available Targets List
        available_targets = []
        try:
            target_rows = conn.execute(
                """
                SELECT DISTINCT target_ip 
                FROM host_status 
                WHERE target_ip IS NOT NULL AND target_ip != ''
                ORDER BY id DESC
            """
            ).fetchall()
            for tr in target_rows:
                ip_val = tr[0]
                # Get latest risk for this IP
                r_row = conn.execute(
                    "SELECT risk_level, total_score FROM risk_summary WHERE ip = ? ORDER BY id DESC LIMIT 1",
                    (ip_val,),
                ).fetchone()
                risk_lvl = r_row["risk_level"] if r_row else "Low"
                available_targets.append({"ip": ip_val, "risk_level": risk_lvl})
        except Exception:
            available_targets = [{"ip": target_ip, "risk_level": "Low"}] if target_ip else []

        # 2. Host Metadata
        host_meta = {}
        if target_ip:
            h_row = conn.execute(
                "SELECT * FROM host_status WHERE target_ip = ? ORDER BY id DESC LIMIT 1",
                (target_ip,),
            ).fetchone()
            if h_row:
                host_meta = dict(h_row)
            os_row = conn.execute(
                "SELECT * FROM os_info WHERE ip = ? ORDER BY id DESC LIMIT 1",
                (target_ip,),
            ).fetchone()
            if os_row:
                host_meta["os_name"] = os_row["os_name"] or host_meta.get("os_name", "Linux / Generic")
                host_meta["device_type"] = os_row["device_type"] or host_meta.get("device_type", "Unknown")
                host_meta["os_accuracy"] = os_row["os_details"] or "95%"

        # 3. Posture / Score
        posture = {"security_score": 75, "security_grade": "B", "risk_level": "Medium"}
        if target_ip:
            p_row = conn.execute(
                "SELECT * FROM security_posture WHERE ip = ? ORDER BY id DESC LIMIT 1",
                (target_ip,),
            ).fetchone()
            if p_row:
                posture = dict(p_row)
            else:
                r_latest = conn.execute(
                    "SELECT * FROM risk_summary WHERE ip = ? ORDER BY id DESC LIMIT 1",
                    (target_ip,),
                ).fetchone()
                if r_latest:
                    tot = r_latest["total_score"] or 0
                    calc_score = max(20, min(100, 100 - (tot * 3)))
                    posture["security_score"] = calc_score
                    posture["security_grade"] = "A" if calc_score >= 80 else ("B" if calc_score >= 60 else "C")
                    posture["risk_level"] = r_latest["risk_level"] or "Medium"

        # 4. Risk Summary History Rows
        if target_ip:
            rows = conn.execute(
                """
                SELECT ip, critical_count, high_count, medium_count, low_count, total_score, risk_level, scan_time
                FROM risk_summary
                WHERE ip = ?
                ORDER BY id DESC
            """,
                (target_ip,),
            ).fetchall()
        else:
            rows = []

        # 5. Active Findings & Deduplicated Vulnerabilities
        vuln_rows = []
        if target_ip:
            vuln_rows = conn.execute(
                """
                SELECT * FROM vulnerabilities
                WHERE id IN (
                    SELECT MAX(id) FROM vulnerabilities WHERE ip = ? GROUP BY port, service
                )
                ORDER BY
                    CASE LOWER(risk)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        ELSE 3
                    END,
                    port ASC
            """,
                (target_ip,),
            ).fetchall()

        # 6. Deduplicated Ports & Services
        port_rows = []
        if target_ip:
            port_rows = conn.execute(
                """
                SELECT * FROM ports
                WHERE id IN (
                    SELECT MAX(id) FROM ports WHERE ip = ? GROUP BY port
                )
                ORDER BY port ASC
            """,
                (target_ip,),
            ).fetchall()

        # 7. Actionable Remediation Steps
        remediation_items = []
        for v in vuln_rows:
            port_num = v["port"]
            srv_name = v["service"] or f"Port {port_num}"
            risk_val = v["risk"] or "Medium"

            # Match CVE ID if available
            cve_match = conn.execute(
                "SELECT cve_id FROM cves WHERE ip = ? AND port = ? ORDER BY id DESC LIMIT 1",
                (target_ip, port_num),
            ).fetchone()
            matched_cve = cve_match["cve_id"] if cve_match and cve_match["cve_id"] else f"CVE-SEC-{port_num}"

            desc_text = v["description"] if ("description" in v.keys() and v["description"]) else f"Potential exposure point on exposed {srv_name} listening service on port {port_num}."
            rem_text = v["remediation"] if ("remediation" in v.keys() and v["remediation"]) else f"Harden {srv_name} daemon configuration, enforce TLS encryption, and restrict public access via firewall security groups."

            remediation_items.append({
                "service": srv_name,
                "port": port_num,
                "risk": risk_val,
                "cve_id": matched_cve,
                "description": desc_text,
                "action": rem_text,
            })


        # Summary & Top Driver
        top_driver = None
        summary_text = None
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        risk_level = posture.get("risk_level", "Low")

        if rows:
            latest_r = rows[0]
            critical_count = latest_r["critical_count"] or 0
            high_count = latest_r["high_count"] or 0
            medium_count = latest_r["medium_count"] or 0
            low_count = latest_r["low_count"] or 0
            risk_level = latest_r["risk_level"] or risk_level

        if vuln_rows:
            top_v = vuln_rows[0]
            top_driver = {
                "service": top_v["service"] or f"Port {top_v['port']}",
                "port": top_v["port"],
                "risk": top_v["risk"] or "Medium",
            }

        finding_phrases = []
        if critical_count:
            finding_phrases.append(f"{critical_count} critical")
        if high_count:
            finding_phrases.append(f"{high_count} high-severity")
        if medium_count:
            finding_phrases.append(f"{medium_count} medium-severity")
        if low_count:
            finding_phrases.append(f"{low_count} low-severity")

        if finding_phrases:
            findings_str = ", ".join(finding_phrases[:-1]) + f", and {finding_phrases[-1]}" if len(finding_phrases) > 1 else finding_phrases[0]
            summary_text = (
                f"Target host {target_ip} demonstrates an executive risk posture of {risk_level}, "
                f"with {findings_str} exposure point{'s' if (critical_count+high_count+medium_count+low_count)!=1 else ''} cataloged across {len(port_rows)} active network port{'s' if len(port_rows)!=1 else ''}."
            )
            if top_driver:
                summary_text += (
                    f" The most immediate threat vector is {top_driver['service']} operating on port {top_driver['port']} "
                    f"({top_driver['risk']} risk tier). Prompt remediation of this component is strongly advised."
                )
        else:
            summary_text = (
                f"Target host {target_ip} currently displays a healthy security profile with no active critical "
                f"or high severity exposures mapped across scanned perimeter interfaces."
            )

        conn.close()
        return render_template(
            "risk_report.html",
            active_page="risk_report",
            page_title="Executive Risk Report",
            page_subtitle="Comprehensive threat profile, posture rating, and prioritized remediation matrix",
            rows=rows,
            target_ip=target_ip,
            latest_ip=latest_ip,
            available_targets=available_targets,
            host_meta=host_meta,
            posture=posture,
            vuln_rows=vuln_rows,
            port_rows=port_rows,
            remediation_items=remediation_items,
            summary_text=summary_text,
            top_driver=top_driver,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            total_score=rows[0]["total_score"] if rows else 0,
            risk_level=risk_level,
        )


    @app.route("/analytics")
    def security_analytics():
        return redirect(url_for("dashboard"))

    @app.route("/soc")
    def soc_dashboard():
        return redirect(url_for("dashboard"))

    @app.route("/api/analytics/trends")
    def api_analytics_trends():
        from analytics.trend_analytics import get_all_trend_analytics
        limit = request.args.get("limit", 20, type=int)
        analytics_data = get_all_trend_analytics(limit=limit)
        return jsonify(analytics_data)

    @app.route("/download-full-report-pdf")
    def download_full_report_pdf():
        requested = request.args.get("type", "").strip().lower()

        if requested == "ip":
            scan_type = "ip"
        elif requested == "url":
            scan_type = "url"
        else:
            latest_host = get_latest_host_status()
            latest_url = get_latest_url_scan()
            scan_type = _determine_latest_scan_type(latest_host, latest_url)

        if scan_type == "ip":
            pdf_path, filename = _build_ip_scan_pdf()
        elif scan_type == "url":
            pdf_path, filename = _build_url_scan_pdf()
        else:
            pdf_path, filename = _build_empty_state_pdf()

        return send_file(pdf_path, as_attachment=True, download_name=filename)

    @app.route("/download-report-json")
    def download_report_json():
        latest_url_scan = get_latest_url_scan()
        if not latest_url_scan:
            return jsonify({"error": "No scan data found"}), 404
        latest_dict = dict(latest_url_scan) if hasattr(latest_url_scan, "keys") else latest_url_scan
        ip = latest_dict.get("ip") or "Unknown"
        conn = get_db_connection()
        res = conn.execute("SELECT * FROM url_scan_results WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,)).fetchone()
        ports = conn.execute("SELECT * FROM ports WHERE ip=? ORDER BY port", (ip,)).fetchall()
        vulns = conn.execute("SELECT * FROM vulnerabilities WHERE ip=? ORDER BY port", (ip,)).fetchall()
        cves = conn.execute("SELECT * FROM cves WHERE ip=? ORDER BY port", (ip,)).fetchall()
        
        domain_name = res["domain"] if res and "domain" in res.keys() else ip
        ssl_info = get_latest_ssl(domain_name) if domain_name else None
        conn.close()

        res_dict = dict(res) if res else {}
        export_data = {
            "report_title": "CyberShieldAI Vulnerability Assessment Report",
            "export_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": res_dict.get("url", ip),
            "ip": ip,
            "domain": domain_name,
            "security_score": res_dict.get("score", 0),
            "risk_level": res_dict.get("risk", "Low"),
            "protocol": res_dict.get("protocol", "HTTPS"),
            "ssl_info": ssl_info,
            "open_ports": [dict(p) for p in ports],
            "vulnerabilities": [dict(v) for v in vulns],
            "cves": [dict(c) for c in cves],
        }

        response = app.response_class(
            response=json.dumps(export_data, indent=2),
            status=200,
            mimetype="application/json"
        )
        response.headers["Content-Disposition"] = f"attachment; filename=CyberShield_Report_{ip}.json"
        return response

    @app.route("/download-report-csv")
    def download_report_csv():
        import io
        import csv
        latest_url_scan = get_latest_url_scan()
        if not latest_url_scan:
            return "No scan data found", 404
        latest_dict = dict(latest_url_scan) if hasattr(latest_url_scan, "keys") else latest_url_scan
        ip = latest_dict.get("ip") or "Unknown"
        conn = get_db_connection()
        res = conn.execute("SELECT * FROM url_scan_results WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,)).fetchone()
        ports = conn.execute("SELECT * FROM ports WHERE ip=? ORDER BY port", (ip,)).fetchall()
        vulns = conn.execute("SELECT * FROM vulnerabilities WHERE ip=? ORDER BY port", (ip,)).fetchall()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Section", "Item / Port", "Service / Attribute", "Severity / Value", "Details / Description"])
        
        if res:
            res_dict = dict(res)
            writer.writerow(["Overview", "Target URL", res_dict.get("url", "-"), "-", "-"])
            writer.writerow(["Overview", "Resolved IP", res_dict.get("ip", "-"), "-", "-"])
            writer.writerow(["Overview", "Security Score", str(res_dict.get("score", "-")), res_dict.get("risk", "-"), "-"])
            writer.writerow(["Overview", "Protocol", res_dict.get("protocol", "-"), "-", "-"])

        for p in ports:
            p_dict = dict(p)
            writer.writerow(["Port", str(p_dict.get("port", "-")), p_dict.get("service", "-"), p_dict.get("state", "-"), p_dict.get("banner", "-")])

        for v in vulns:
            v_dict = dict(v)
            writer.writerow(["Vulnerability", str(v_dict.get("port", "-")), v_dict.get("service", "-"), v_dict.get("risk", "-"), v_dict.get("description", "-")])

        output.seek(0)
        return app.response_class(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=CyberShield_Report_{ip}.csv"}
        )

    # ==========================================================
    # Monitoring Dashboard & Target Management Routes
    # ==========================================================
    @app.route("/monitoring")
    def monitoring_page():
        from scheduler.monitor import get_monitoring_logs, get_monitored_targets_with_schedule
        from database.monitoring_helpers import get_monitoring_analytics
        from alerts.alert_engine import get_monitoring_alerts
        targets = get_monitored_targets_with_schedule()
        logs = get_monitoring_logs(limit=20)
        analytics = get_monitoring_analytics()
        alerts = get_monitoring_alerts(limit=20)
        return render_template(
            "monitoring.html",
            active_page="monitoring",
            page_title="Target Monitoring",
            page_subtitle="Continuous asset tracking, automated scan schedules, and target health",
            targets=targets,
            logs=logs,
            analytics=analytics,
            alerts=alerts,
        )

    @app.route("/monitoring/run-cycle", methods=["POST"])
    def monitoring_run_cycle_route():
        from scheduler.monitor import run_monitoring_cycle
        results = run_monitoring_cycle()
        count = len(results)
        flash(f"Monitoring cycle executed. Processed {count} active target{'s' if count != 1 else ''}.", "success")
        return redirect(url_for("monitoring_page"))

    @app.route("/monitoring/add", methods=["POST"])
    def monitoring_add():
        from database.monitoring_helpers import add_monitored_target, is_target_exists, get_monitored_targets
        from scheduler.monitor import sync_target_jobs
        raw_target = request.form.get("target") or (request.json.get("target") if request.is_json else "")
        target = str(raw_target or "").strip()
        frequency = request.form.get("frequency") or (request.json.get("frequency") if request.is_json else 24)

        # 1. Validate empty fields
        if not target:
            if request.is_json:
                return jsonify({"status": "error", "message": "Target URL/IP cannot be empty."}), 400
            flash("Target URL/IP cannot be empty. Please enter a valid host or IP address.", "error")
            return redirect(url_for("monitoring_page"))

        # 2. Validate frequency
        try:
            freq_val = int(frequency)
            if freq_val not in [1, 6, 12, 24]:
                freq_val = 24
        except (ValueError, TypeError):
            freq_val = 24

        # 3. Validate duplicate targets
        if is_target_exists(target):
            if request.is_json:
                return jsonify({"status": "error", "message": f"Duplicate target: '{target}' is already being monitored."}), 409
            flash(f"Duplicate target: '{target}' is already registered in the monitoring list.", "error")
            return redirect(url_for("monitoring_page"))

        # 4. Save into monitored_targets table
        success = add_monitored_target(target, freq_val)
        if not success:
            if request.is_json:
                return jsonify({"status": "error", "message": f"Failed to add target '{target}'."}), 500
            flash(f"Failed to add target '{target}' to monitoring.", "error")
            return redirect(url_for("monitoring_page"))

        # Sync APScheduler jobs
        sync_target_jobs()

        # 5. Show success notification
        if request.is_json:
            return jsonify({
                "status": "success",
                "message": f"Target '{target}' added successfully!",
                "targets": get_monitored_targets(),
            })

        flash(f"Target '{target}' has been successfully added to monitoring (Every {freq_val} Hours).", "success")
        return redirect(url_for("monitoring_page"))

    @app.route("/monitoring/enable/<int:target_id>", methods=["POST", "GET"])
    def monitoring_enable_route(target_id):
        from scheduler.monitor import sync_target_jobs
        enable_monitoring(target_id)
        sync_target_jobs()
        if request.is_json:
            return jsonify({"status": "success"})
        flash(f"Target #{target_id} monitoring has been enabled.", "success")
        return redirect(url_for("monitoring_page"))

    @app.route("/monitoring/disable/<int:target_id>", methods=["POST", "GET"])
    def monitoring_disable_route(target_id):
        from scheduler.monitor import sync_target_jobs
        disable_monitoring(target_id)
        sync_target_jobs()
        if request.is_json:
            return jsonify({"status": "success"})
        flash(f"Target #{target_id} monitoring has been paused.", "info")
        return redirect(url_for("monitoring_page"))

    @app.route("/monitoring/delete/<int:target_id>", methods=["POST", "GET"])
    def monitoring_delete_route(target_id):
        from scheduler.monitor import sync_target_jobs
        delete_monitored_target(target_id)
        sync_target_jobs()
        if request.is_json:
            return jsonify({"status": "success"})
        flash(f"Target #{target_id} has been deleted.", "success")
        return redirect(url_for("monitoring_page"))

    # ==========================================================
    # Email Alerts & SMTP Configuration Routes (ADMIN ONLY)
    # ==========================================================
    @app.route("/settings/email", methods=["GET"])
    def email_settings_page():
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to access Email Alert settings.", "error")
            return redirect(url_for("profile_page"))

        from database.email_settings_helpers import get_email_settings
        from alerts.email_api import get_email_api_config
        settings = get_email_settings()
        api_config = get_email_api_config()
        return render_template(
            "settings_email.html",
            active_page="email_settings",
            page_title="Email Alert Settings",
            page_subtitle="Email relay credentials, cloud API providers, and automated incident notification preferences",
            settings=settings,
            api_config=api_config,
        )

    @app.route("/settings/email/save", methods=["POST"])
    def email_settings_save():
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to modify Email Alert settings.", "error")
            return redirect(url_for("profile_page"))

        from database.email_settings_helpers import save_email_settings
        form_data = request.form.to_dict()
        success = save_email_settings(form_data)
        if success:
            flash("SMTP and email alert settings saved successfully.", "success")
        else:
            flash("Failed to save email settings. Please check your parameters.", "error")
        return redirect(url_for("email_settings_page"))

    @app.route("/settings/email/test", methods=["POST"])
    def email_settings_test():
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to dispatch test emails.", "error")
            return redirect(url_for("profile_page"))

        from alerts.email_notifier import send_test_email
        test_recipient = request.form.get("test_recipient", "").strip()
        success, message = send_test_email(to_email=test_recipient)
        if success:
            flash(f"✓ Test email dispatched successfully: {message}", "success")
        else:
            flash(f"⚠ Test email delivery failed: {message}", "error")
        return redirect(url_for("email_settings_page"))

    # ==========================================================
    # User Profile & Account Settings Routes
    # ==========================================================
    @app.route("/settings/profile", methods=["GET"])
    def profile_page():
        from database.user_helpers import get_user_by_id
        user_id = session.get("user_id")
        user = get_user_by_id(user_id)
        if not user:
            user = {
                "username": session.get("username", "Operator"),
                "role": session.get("role", "ADMIN"),
                "email": session.get("email", ""),
                "created_at": "Active",
                "last_login": "Active",
            }
        else:
            session["email"] = user.get("email", "")
            if user.get("avatar_url"):
                session["avatar_url"] = user.get("avatar_url")
            session.modified = True

        return render_template(
            "profile.html",
            active_page="profile",
            page_title="User Profile",
            page_subtitle="Security credentials and role configuration",
            user=user,
        )

    @app.route("/settings/profile/update", methods=["POST"])
    def update_profile_route():
        from database.user_helpers import update_user_profile
        user_id = session.get("user_id")
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        timezone = request.form.get("timezone", "").strip()
        bio = request.form.get("bio", "").strip()
        avatar_url = request.form.get("avatar_url", "").strip() or None

        # Check for avatar file upload
        if "avatar_file" in request.files:
            file = request.files["avatar_file"]
            if file and file.filename:
                ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else "png"
                if ext in ("png", "jpg", "jpeg", "gif", "webp"):
                    avatars_dir = os.path.join(BASE_DIR, "dashboard", "static", "avatars")
                    os.makedirs(avatars_dir, exist_ok=True)
                    filename = f"avatar_{user_id}_{int(datetime.now().timestamp())}.{ext}"
                    filepath = os.path.join(avatars_dir, filename)
                    file.save(filepath)
                    avatar_url = f"/static/avatars/{filename}"

        if not username:
            flash("Username cannot be empty.", "error")
            return redirect(url_for("profile_page"))

        success, err = update_user_profile(
            user_id,
            username=username,
            email=email,
            full_name=full_name,
            phone=phone,
            department=department,
            timezone=timezone,
            bio=bio,
            avatar_url=avatar_url,
        )
        if success:
            session["username"] = username
            session["email"] = email
            if avatar_url:
                session["avatar_url"] = avatar_url
            session.modified = True
            flash("Profile information updated successfully.", "success")
        else:
            flash(err or "Failed to update profile.", "error")
        return redirect(url_for("profile_page"))

    @app.route("/settings/profile/password", methods=["POST"])
    def change_password_route():
        from database.user_helpers import change_password_with_verification
        user_id = session.get("user_id")
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not current_password or not new_password:
            flash("All password fields are required.", "error")
            return redirect(url_for("profile_page"))

        if new_password != confirm_password:
            flash("New password and confirm password do not match.", "error")
            return redirect(url_for("profile_page"))

        success, err = change_password_with_verification(user_id, current_password, new_password)
        if success:
            flash("Password updated successfully.", "success")
        else:
            flash(err or "Failed to update password.", "error")
        return redirect(url_for("profile_page"))

    # ==========================================================
    # Admin SOC Dashboard & System Management Routes
    # ==========================================================
    @app.route("/admin", methods=["GET"])
    def admin_dashboard():
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to access the Admin Dashboard.", "error")
            return redirect(url_for("profile_page")), 403

        from database.user_helpers import list_users, get_user_activity_metrics
        from database.security_activity_helpers import get_security_activity_metrics, get_security_activity_logs
        from database.db_helpers import get_db_connection

        users = list_users()
        user_metrics = get_user_activity_metrics()
        sec_metrics = get_security_activity_metrics()
        security_logs, _, _, _ = get_security_activity_logs(page=1, per_page=10)

        # Real Scanner & Threat Statistics
        scan_metrics = {
            "total_scans": 0,
            "ip_scans": 0,
            "url_scans": 0,
            "successful_scans": 0,
            "total_vulns": 0,
            "critical_vulns": 0,
            "total_cves": 0,
            "monitoring_targets": 0,
            "risk_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        try:
            conn = get_db_connection()
            # Scans count
            try:
                r = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()
                scan_metrics["ip_scans"] = r[0] if r else 0
            except Exception:
                pass

            try:
                r = conn.execute("SELECT COUNT(*) FROM url_scan_results").fetchone()
                scan_metrics["url_scans"] = r[0] if r else 0
            except Exception:
                pass

            scan_metrics["total_scans"] = scan_metrics["ip_scans"] + scan_metrics["url_scans"]

            try:
                r1 = conn.execute("SELECT COUNT(*) FROM scan_history WHERE status IN ('Alive', 'Completed', 'Up', 'Online')").fetchone()
                succ_ip = r1[0] if r1 else 0
                scan_metrics["successful_scans"] = succ_ip + scan_metrics["url_scans"]
            except Exception:
                scan_metrics["successful_scans"] = scan_metrics["total_scans"]

            # Vulnerabilities & CVEs
            try:
                r = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()
                scan_metrics["total_vulns"] = r[0] if r else 0
            except Exception:
                pass

            try:
                r = conn.execute("SELECT COUNT(*) FROM cves").fetchone()
                scan_metrics["total_cves"] = r[0] if r else 0
            except Exception:
                pass

            # Risk breakdown
            try:
                crit_v = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE LOWER(risk) = 'critical'").fetchone()[0]
                high_v = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE LOWER(risk) = 'high'").fetchone()[0]
                med_v = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE LOWER(risk) = 'medium'").fetchone()[0]
                low_v = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE LOWER(risk) = 'low'").fetchone()[0]
                scan_metrics["risk_counts"] = {"critical": crit_v, "high": high_v, "medium": med_v, "low": low_v}
                scan_metrics["critical_vulns"] = crit_v
            except Exception:
                pass

            # Monitoring Targets
            try:
                r = conn.execute("SELECT COUNT(*) FROM monitored_targets").fetchone()
                scan_metrics["monitoring_targets"] = r[0] if r else 0
            except Exception:
                pass

            conn.close()
        except Exception as e:
            logger.warning(f"Error compiling admin stats: {e}")

        return render_template(
            "admin_dashboard.html",
            active_page="admin_dashboard",
            users=users,
            user_metrics=user_metrics,
            scan_metrics=scan_metrics,
            sec_metrics=sec_metrics,
            security_logs=security_logs,
        )

    @app.route("/users", methods=["GET"])
    def users_list():
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to access User Management.", "error")
            return redirect(url_for("profile_page")), 403

        from database.user_helpers import list_users, get_user_activity_metrics
        users = list_users()
        metrics = get_user_activity_metrics()
        return render_template(
            "users.html",
            active_page="users",
            users=users,
            metrics=metrics,
        )

    @app.route("/users/create", methods=["GET", "POST"])
    def users_create():
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to create new users.", "error")
            return redirect(url_for("profile_page")), 403

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            full_name = request.form.get("full_name", "").strip()
            role = request.form.get("role", "VIEWER").strip().upper()
            password = request.form.get("password", "")
            is_active = 1 if request.form.get("is_active") in ("1", "true", "True", True) else 0

            if not username or not password:
                flash("Username and password are required.", "error")
                return render_template(
                    "users_form.html",
                    is_edit=False,
                    target_user={"username": username, "email": email, "full_name": full_name, "role": role, "is_active": is_active},
                    active_page="users",
                )

            if len(password) < 4:
                flash("Password must be at least 4 characters long.", "error")
                return render_template(
                    "users_form.html",
                    is_edit=False,
                    target_user={"username": username, "email": email, "full_name": full_name, "role": role, "is_active": is_active},
                    active_page="users",
                )

            from database.user_helpers import get_user_by_username, get_user_by_email, create_user
            if get_user_by_username(username):
                flash(f"Username '{username}' is already taken.", "error")
                return render_template(
                    "users_form.html",
                    is_edit=False,
                    target_user={"username": username, "email": email, "full_name": full_name, "role": role, "is_active": is_active},
                    active_page="users",
                )

            if email and get_user_by_email(email):
                flash(f"Email '{email}' is already associated with another account.", "error")
                return render_template(
                    "users_form.html",
                    is_edit=False,
                    target_user={"username": username, "email": email, "full_name": full_name, "role": role, "is_active": is_active},
                    active_page="users",
                )

            avatar_url = f"https://api.dicebear.com/7.x/bottts/svg?seed={username}"
            create_user(
                username=username,
                password=password,
                role=role,
                email=email,
                full_name=full_name,
                is_active=is_active,
                avatar_url=avatar_url,
            )

            from database.security_activity_helpers import log_security_activity
            log_security_activity("ADMIN_USER_CREATE", "SUCCESS", username=username, email=email, details=f"Admin created account with role {role}")

            flash(f"User '{username}' ({role}) created successfully.", "success")
            return redirect(url_for("users_list"))

        return render_template(
            "users_form.html",
            is_edit=False,
            target_user=None,
            active_page="users",
        )

    @app.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
    def users_edit(user_id):
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to modify users.", "error")
            return redirect(url_for("profile_page")), 403

        from database.user_helpers import get_user_by_id, admin_update_user
        target_user = get_user_by_id(user_id)
        if not target_user:
            flash("User not found.", "error")
            return redirect(url_for("users_list"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            full_name = request.form.get("full_name", "").strip()
            role = request.form.get("role", "VIEWER").strip().upper()
            password = request.form.get("password", "").strip() or None
            is_active = 1 if request.form.get("is_active") in ("1", "true", "True", True) else 0

            # Prevent active admin from accidentally demoting or deactivating their own account
            if target_user["id"] == session.get("user_id"):
                role = "ADMIN"
                is_active = 1

            success, error_msg = admin_update_user(
                user_id=user_id,
                username=username,
                email=email,
                role=role,
                is_active=is_active,
                new_password=password,
                full_name=full_name,
            )
            if success:
                from database.security_activity_helpers import log_security_activity
                log_security_activity("ADMIN_USER_UPDATE", "SUCCESS", username=username, email=email, details=f"Admin updated user id {user_id}")

                flash(f"User '{username}' updated successfully.", "success")
                return redirect(url_for("users_list"))
            else:
                flash(f"Failed to update user: {error_msg}", "error")
                return render_template(
                    "users_form.html",
                    is_edit=True,
                    target_user={"id": user_id, "username": username, "email": email, "full_name": full_name, "role": role, "is_active": is_active},
                    active_page="users",
                )

        return render_template(
            "users_form.html",
            is_edit=True,
            target_user=target_user,
            active_page="users",
        )

    @app.route("/users/delete/<int:user_id>", methods=["POST"])
    def users_delete(user_id):
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to delete users.", "error")
            return redirect(url_for("profile_page")), 403

        # Prevent currently logged-in admin from deleting themselves
        if user_id == session.get("user_id"):
            flash("Safety Violation: You cannot delete your own active administrator account.", "error")
            return redirect(url_for("users_list"))

        from database.user_helpers import get_user_by_id, delete_user
        target_user = get_user_by_id(user_id)
        if not target_user:
            flash("User not found.", "error")
            return redirect(url_for("users_list"))

        success, error_msg = delete_user(user_id)
        if success:
            from database.security_activity_helpers import log_security_activity
            log_security_activity("ADMIN_USER_DELETE", "SUCCESS", username=target_user.get("username"), email=target_user.get("email"), details=f"Admin deleted user id {user_id}")

            flash(f"User '{target_user.get('username')}' deleted successfully.", "success")
        else:
            flash(f"Failed to delete user: {error_msg}", "error")
        return redirect(url_for("users_list"))

    @app.route("/admin/security-activity", methods=["GET"])
    def security_activity_page():
        if session.get("role") != "ADMIN":
            flash("Administrator privileges are required to access Security Activity.", "error")
            return redirect(url_for("profile_page")), 403

        event_filter = request.args.get("filter", "all").strip().lower()
        page = max(1, request.args.get("page", 1, type=int))
        per_page = 20

        from database.security_activity_helpers import (
            get_security_activity_logs,
            get_security_activity_metrics,
        )

        logs, total_count, total_pages, current_page = get_security_activity_logs(
            event_filter=event_filter,
            page=page,
            per_page=per_page,
        )
        metrics = get_security_activity_metrics()

        return render_template(
            "security_activity.html",
            active_page="security_activity",
            page_title="Security Activity & Audit Trail",
            page_subtitle="Real-time authentication and security event auditing",
            logs=logs,
            metrics=metrics,
            current_filter=event_filter,
            current_page=current_page,
            total_pages=total_pages,
            total_count=total_count,
        )

