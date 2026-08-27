import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Database & Helpers
from database.db_helpers import get_db_connection
from database.monitoring_helpers import get_monitored_targets as fetch_all_targets
from database.save_url_intelligence import save_url_intelligence
from database.security_posture import save_security_posture
from database.ssl_results import save_ssl

# Scan Engine & Snapshot Modules
from scanner.ssl_scanner import analyze_ssl
from scanner.technology_detector import detect_technology
from scanner.url_intelligence import analyze_url_intelligence
from scanner.url_scanner import scan_url, score_to_risk_level
from scanner.virustotal_scanner import query_virustotal

# Alert & Comparison Engine Imports
from alerts.alert_engine import process_monitoring_alerts
from scanner.scan_snapshot import get_scan_snapshot, get_previous_scan_id
from scanner.scan_comparison_engine import compare_scans

# APScheduler Imports
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger


# ==========================================================
# Database Table Initialization for Monitoring Logs
# ==========================================================
def _ensure_monitoring_logs_table():
    try:
        conn = get_db_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print("[MONITORING] Warning initializing monitoring_logs table:", e)

_ensure_monitoring_logs_table()


# ==========================================================
# Unified Logging System (In-Memory + SQLite Database)
# ==========================================================
MONITORING_LOGS = []
MONITORING_LOGS_LOCK = threading.Lock()
MAX_LOG_ENTRIES = 500


def _log(target, status, message="", details=None):
    """
    Persists log records to both in-memory store and SQLite database.
    Statuses: 'Scan Started', 'Scan Completed', 'Scan Failed', 'Alerts Generated'.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "target": target,
        "status": status,
        "message": message,
        "details": details or {},
    }

    # In-memory buffer
    with MONITORING_LOGS_LOCK:
        MONITORING_LOGS.append(entry)
        if len(MONITORING_LOGS) > MAX_LOG_ENTRIES:
            MONITORING_LOGS.pop(0)

    # SQLite Database persistence
    try:
        details_str = json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details else "")
        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO monitoring_logs (target, status, message, details, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (target, status, message, details_str, timestamp),
        )
        conn.commit()
        conn.close()
    except Exception as db_err:
        print(f"[MONITORING LOG DB ERROR] {db_err}")

    print(f"[{timestamp}] [{status}] Target: {target} | {message}".strip())
    return entry


def get_monitoring_logs(limit=100):
    """
    Retrieves recent monitoring logs (newest first), falling back to SQLite database.
    """
    with MONITORING_LOGS_LOCK:
        if MONITORING_LOGS:
            return list(reversed(MONITORING_LOGS[-limit:]))

    # Fallback to database
    try:
        conn = get_db_connection()
        rows = conn.execute(
            """
            SELECT target, status, message, details, created_at as timestamp
            FROM monitoring_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def clear_monitoring_logs():
    """Clears in-memory and database logs."""
    with MONITORING_LOGS_LOCK:
        MONITORING_LOGS.clear()
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM monitoring_logs")
        conn.commit()
        conn.close()
    except Exception:
        pass


# ==========================================================
# Monitored Target Loader & Schedule Calculation
# ==========================================================
def get_monitored_targets(enabled_only=True):
    """
    Retrieves monitored targets from the database.
    When enabled_only=True, returns only active targets (enabled == 1).
    """
    targets = fetch_all_targets()
    if enabled_only:
        return [t for t in targets if t.get("enabled") == 1]
    return targets


def get_target_last_scan(target_val: str):
    """
    Retrieves the last scan timestamp and record for a given target.
    """
    if not target_val:
        return None

    conn = get_db_connection()
    try:
        like_target = f"%{target_val}%"
        row = conn.execute(
            """
            SELECT scan_time, score, risk, ip
            FROM url_scan_results
            WHERE (ip = ? OR domain = ? OR url = ? OR url LIKE ?)
            ORDER BY id DESC LIMIT 1
            """,
            (target_val, target_val, target_val, like_target),
        ).fetchone()

        if row and row["scan_time"]:
            return dict(row)
        return None
    except Exception:
        return None
    finally:
        conn.close()


def is_target_due(target_dict: dict) -> bool:
    """
    Determines if a target is due for scanning based on its configured scan_frequency (in hours).
    """
    if not target_dict or not target_dict.get("enabled"):
        return False

    target_val = target_dict.get("target")
    frequency_hours = int(target_dict.get("scan_frequency", 24))
    last_record = get_target_last_scan(target_val)

    if not last_record or not last_record.get("scan_time"):
        return True  # Never scanned, due immediately

    try:
        last_scan = datetime.strptime(str(last_record["scan_time"]), "%Y-%m-%d %H:%M:%S")
        return datetime.now() >= (last_scan + timedelta(hours=frequency_hours))
    except (ValueError, TypeError):
        return True


# ==========================================================
# URL Scanner Integration & Workflow
# ==========================================================
def scan_monitored_target(target):
    """
    Reuses existing URL scan engine and database storage workflow
    for an individual monitored target, executes comparison, and generates alerts.
    """
    scan_id = uuid.uuid4().hex
    _log(target, "Scan Started", f"Initiating automated scan (scan_id={scan_id[:8]})")

    try:
        # 1. Run core URL analysis engine
        result = scan_url(target)

        # 2. Detect web technologies
        technology = detect_technology(result["url"])

        # 2b. Query VirusTotal Threat Intelligence
        try:
            query_virustotal(result["url"], scan_id=scan_id)
        except Exception as vt_e:
            print("[MONITORING VIRUSTOTAL WARNING]", vt_e)

        # 3. Gather URL intelligence (WHOIS, GeoIP, DNS, WAF, Security Headers)
        url_info = analyze_url_intelligence(result["url"], scan_id=scan_id)
        if url_info:
            save_url_intelligence(url_info, scan_id=scan_id)

        # 4. Domain registration age heuristic check
        whois_info = url_info.get("whois", {}) if isinstance(url_info, dict) else {}
        creation_date_str = (
            whois_info.get("creation_date") if isinstance(whois_info, dict) else None
        )
        if creation_date_str and creation_date_str != "Unknown":
            try:
                created = datetime.strptime(creation_date_str, "%Y-%m-%d")
                age_days = (datetime.now() - created).days
                if age_days < 30:
                    result["score"] += 25
                    result["remarks"].append(
                        f"Domain was registered only {age_days} day(s) ago (newly registered domain risk)"
                    )
                elif age_days < 180:
                    result["score"] += 10
                    result["remarks"].append(
                        f"Domain is relatively new ({age_days} days old)"
                    )
            except (ValueError, TypeError):
                pass

        result["risk"] = score_to_risk_level(result["score"])

        # 5. Analyze and save SSL/TLS certificate details
        ssl_data = analyze_ssl(result["url"])
        if ssl_data:
            save_ssl(ssl_data, scan_id=scan_id)

        # 6. Store results into database tables using project schema
        remarks_str = (
            " | ".join(result["remarks"])
            if isinstance(result["remarks"], list)
            else str(result["remarks"])
        )
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO url_scan_results
            (scan_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result["url"],
                result["domain"],
                result["ip"],
                result["protocol"],
                result["score"],
                result["risk"],
                remarks_str,
                now_str,
            ),
        )

        technology_json = (
            json.dumps(technology)
            if isinstance(technology, (dict, list))
            else json.dumps({"raw": str(technology)})
        )
        conn.execute(
            """
            INSERT INTO technology_detection
            (scan_id, ip, url, technologies, scan_time)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result["ip"],
                result["url"],
                technology_json,
                now_str,
            ),
        )
        conn.commit()
        conn.close()

        # 6b. Generate security score and save security posture
        threat_score = int(result.get("score", 0))
        security_score = max(0, 100 - threat_score)
        if security_score >= 90:
            security_grade = "A+"
        elif security_score >= 80:
            security_grade = "A"
        elif security_score >= 70:
            security_grade = "B"
        elif security_score >= 60:
            security_grade = "C"
        elif security_score >= 50:
            security_grade = "D"
        else:
            security_grade = "F"

        try:
            save_security_posture(
                ip=result["ip"],
                url=result["url"],
                security_score=security_score,
                security_grade=security_grade,
                threat_score=threat_score,
                risk_level=result["risk"],
                scan_time=now_str,
                scan_id=scan_id,
                assessment_status="ASSESSED",
            )
        except Exception as post_err:
            print(f"[MONITORING POSTURE ERROR] {post_err}")

        # 7. Evaluate and trigger security alerts (comparison with previous scan)
        generated_alerts = []
        try:
            prev_scan_id = get_previous_scan_id(target, scan_id)
            current_snapshot = get_scan_snapshot(scan_id)
            previous_snapshot = get_scan_snapshot(prev_scan_id) if prev_scan_id else None
            comparison_delta = compare_scans(current_snapshot, previous_snapshot)

            generated_alerts = process_monitoring_alerts(
                target=target,
                current_scan=current_snapshot,
                previous_scan=previous_snapshot,
                delta=comparison_delta,
            )
        except Exception as alert_err:
            print(f"[ALERT ENGINE] Error evaluating alerts for {target}:", alert_err)

        # 8. Log completion and alert count
        alert_msg = f" ({len(generated_alerts)} alert(s) triggered)" if generated_alerts else ""
        _log(
            target,
            "Scan Completed",
            f"Score: {result['score']}/100, Risk: {result['risk']}, IP: {result['ip']}, Protocol: {result['protocol'].upper()}{alert_msg}",
            details={
                "scan_id": scan_id,
                "score": result["score"],
                "risk": result["risk"],
                "ip": result["ip"],
                "protocol": result["protocol"],
                "alerts_count": len(generated_alerts),
            },
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "result": result,
            "alerts": generated_alerts,
        }

    except Exception as e:
        _log(target, "Scan Failed", f"Error: {str(e)}", details={"error": str(e)})
        return {
            "success": False,
            "scan_id": scan_id,
            "target": target,
            "error": str(e),
        }


# ==========================================================
# Full & Scheduled Monitoring Cycle Execution
# ==========================================================
def run_monitoring_cycle(force_all=True):
    """
    Executes a monitoring cycle.
    If force_all=True, runs all enabled targets immediately.
    If force_all=False, runs only targets that are due according to their scan_frequency.
    """
    enabled_targets = get_monitored_targets(enabled_only=True)

    if not enabled_targets:
        print("No enabled monitored targets found.")
        return []

    results = []
    for item in enabled_targets:
        target = item.get("target")
        if not target:
            continue

        if force_all or is_target_due(item):
            res = scan_monitored_target(target)
            results.append(res)

    return results


# ==========================================================
# APScheduler Background Monitoring Engine
# ==========================================================
_AP_SCHEDULER = None
_SCHEDULER_LOCK = threading.RLock()


def get_apscheduler_instance():
    """Returns or instantiates the global singleton APScheduler instance."""
    global _AP_SCHEDULER
    with _SCHEDULER_LOCK:
        if _AP_SCHEDULER is None:
            _AP_SCHEDULER = BackgroundScheduler(daemon=True)
        return _AP_SCHEDULER


def sync_target_jobs():
    """
    Synchronizes APScheduler jobs with the monitored_targets table:
    - Adds / updates jobs for enabled targets based on scan_frequency (1, 6, 12, 24 Hours).
    - Removes jobs for disabled or deleted targets.
    - Prevents duplicate jobs by using deterministic job IDs (f"target_scan_{target['id']}").
    """
    scheduler = get_apscheduler_instance()
    if not scheduler or not scheduler.running:
        return

    targets = fetch_all_targets()
    active_target_ids = set()

    for t in targets:
        target_id = t.get("id")
        target_val = t.get("target")
        enabled = t.get("enabled", 0) == 1
        freq = int(t.get("scan_frequency", 24))

        job_id = f"target_scan_{target_id}"

        if enabled and target_val:
            active_target_ids.add(job_id)
            
            # Check if job is already registered
            existing_job = scheduler.get_job(job_id)
            if existing_job is None:
                # Calculate next run time
                last_rec = get_target_last_scan(target_val)
                if last_rec and last_rec.get("scan_time"):
                    try:
                        last_scan_dt = datetime.strptime(str(last_rec["scan_time"]), "%Y-%m-%d %H:%M:%S")
                        next_dt = last_scan_dt + timedelta(hours=freq)
                        if next_dt <= datetime.now():
                            next_run = datetime.now() + timedelta(seconds=60)
                        else:
                            next_run = next_dt
                    except Exception:
                        next_run = datetime.now() + timedelta(seconds=60)
                else:
                    # Never scanned: schedule first run in 60 seconds
                    next_run = datetime.now() + timedelta(seconds=60)

                scheduler.add_job(
                    func=scan_monitored_target,
                    trigger=IntervalTrigger(hours=freq),
                    id=job_id,
                    name=f"Monitoring Scan: {target_val} ({freq}h)",
                    args=[target_val],
                    replace_existing=True,
                    max_instances=1,
                    coalesce=True,
                    misfire_grace_time=3600,
                    next_run_time=next_run,
                )
                print(f"[APSCHEDULER] Scheduled job '{job_id}' for {target_val} every {freq}h (Next: {next_run})")
        else:
            # If disabled, ensure job is removed from scheduler
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)
                print(f"[APSCHEDULER] Removed paused/disabled job '{job_id}'")

    # Remove any stale jobs in scheduler not in database
    for job in scheduler.get_jobs():
        if job.id.startswith("target_scan_") and job.id not in active_target_ids:
            try:
                scheduler.remove_job(job.id)
                print(f"[APSCHEDULER] Removed deleted target job '{job.id}'")
            except Exception:
                pass


def get_monitored_targets_with_schedule():
    """
    Returns all monitored targets enriched with:
    - last_scan_time: formatted string or 'Never Scanned'
    - next_scan_time: formatted string, 'Scheduled', or 'Monitoring Paused'
    - monitoring_status: 'Active' or 'Disabled'
    - scheduler_running: True/False
    """
    targets = fetch_all_targets()
    scheduler = get_apscheduler_instance()
    is_running = scheduler.running if scheduler else False

    enriched = []
    for t in targets:
        target_dict = dict(t)
        target_id = target_dict.get("id")
        target_val = target_dict.get("target")
        enabled = target_dict.get("enabled", 0) == 1
        freq = int(target_dict.get("scan_frequency", 24))

        # 1. Last Scan Time
        last_rec = get_target_last_scan(target_val)
        if last_rec and last_rec.get("scan_time"):
            last_scan_str = str(last_rec["scan_time"])
        else:
            last_scan_str = "Never Scanned"
        target_dict["last_scan_time"] = last_scan_str

        # 2. Next Scan Time & Monitoring Status
        if not enabled:
            target_dict["monitoring_status"] = "Disabled"
            target_dict["next_scan_time"] = "Monitoring Paused"
        else:
            target_dict["monitoring_status"] = "Active"
            job_id = f"target_scan_{target_id}"
            job = scheduler.get_job(job_id) if scheduler and is_running else None

            if job and job.next_run_time:
                target_dict["next_scan_time"] = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")
            elif last_scan_str != "Never Scanned":
                try:
                    last_dt = datetime.strptime(last_scan_str, "%Y-%m-%d %H:%M:%S")
                    calc_next = last_dt + timedelta(hours=freq)
                    target_dict["next_scan_time"] = calc_next.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    target_dict["next_scan_time"] = "Pending Cycle"
            else:
                target_dict["next_scan_time"] = "Pending First Scan"

        enriched.append(target_dict)

    return enriched


def start_background_scheduler(check_interval_seconds=30):
    """
    Starts the APScheduler background daemon if not already running.
    Adds a periodic sync job to automatically update targets and prevent duplicate jobs.
    """
    scheduler = get_apscheduler_instance()
    with _SCHEDULER_LOCK:
        if scheduler.running:
            # Sync target jobs if already running
            sync_target_jobs()
            return True

        # Register target jobs synchronization job
        scheduler.add_job(
            func=sync_target_jobs,
            trigger=IntervalTrigger(seconds=check_interval_seconds),
            id="apscheduler_target_sync_job",
            name="Target Jobs Synchronizer",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )

        scheduler.start()
        print(f"[APSCHEDULER] Background scheduler started successfully (Sync Interval: {check_interval_seconds}s)")

        # Run initial sync immediately
        sync_target_jobs()
        return True


def stop_background_scheduler():
    """Stops the APScheduler daemon cleanly."""
    global _AP_SCHEDULER
    with _SCHEDULER_LOCK:
        if _AP_SCHEDULER and _AP_SCHEDULER.running:
            _AP_SCHEDULER.shutdown(wait=False)
            print("[APSCHEDULER] Background scheduler stopped.")


if __name__ == "__main__":
    start_background_scheduler(check_interval_seconds=10)
    run_monitoring_cycle(force_all=True)
