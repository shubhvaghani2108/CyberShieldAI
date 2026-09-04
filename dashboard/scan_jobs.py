import os
import sys
import threading
import uuid

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import get_db_connection
from scanner.cve_scanner import scan_cves
from scanner.host_discovery import check_host_alive
from scanner.port_scanner import scan_target
from scanner.risk_calculator import calculate_risk
from scanner.vulnerability_scanner import scan_vulnerabilities
from alerts.alert_engine import generate_alerts

from database.db_helpers import (
    get_db_connection,
    get_latest_risk,
    get_latest_ssl,
    get_ports,
    get_security_headers,
)

SCAN_JOBS = {}
SCAN_JOBS_LOCK = threading.Lock()


import time


def _new_job(target, job_type="ip", user_id=None):
    job_id = uuid.uuid4().hex
    with SCAN_JOBS_LOCK:
        SCAN_JOBS[job_id] = {
            "job_id": job_id,
            "target": target,
            "type": job_type,
            "user_id": user_id,
            "status": "running",
            "logs": [],
            "error": None,
            "result_ip": None,
            "scan_id": None,
            "start_time": time.time(),
        }
    return job_id


def _job_log(job_id, message):
    with SCAN_JOBS_LOCK:
        if job_id in SCAN_JOBS:
            SCAN_JOBS[job_id]["logs"].append(message)


def _job_done(job_id, result_ip=None, scan_id=None):
    with SCAN_JOBS_LOCK:
        if job_id in SCAN_JOBS:
            SCAN_JOBS[job_id]["status"] = "done"
            SCAN_JOBS[job_id]["result_ip"] = result_ip
            if scan_id:
                SCAN_JOBS[job_id]["scan_id"] = scan_id


MAX_CONCURRENT_SCANS = 2
SCAN_SEMAPHORE = threading.Semaphore(MAX_CONCURRENT_SCANS)


def _sanitize_error_message(err):
    """Ensures no internal credentials, database URLs, or stack traces are shown to users, while giving informative feedback."""
    if not err:
        return "Scan encountered an unexpected condition. Please try again."
    err_str = str(err)
    sensitive_markers = [
        "password", "pooler.supabase", "postgresql://", "postgres://", "conn.cursor",
        "EMAXCONNSESSION", "EMAXCONNECTION", "OperationalError", "psycopg2",
        "aws-0-ap-south-1", "port 5432", "port 6543", "database_url", "dsn=", "connection to server"
    ]
    if any(m.lower() in err_str.lower() for m in sensitive_markers):
        return "Database service is temporarily at maximum capacity. Please retry your scan in a moment."
    if "Traceback" in err_str or "File \"" in err_str:
        lines = [l.strip() for l in err_str.splitlines() if l.strip()]
        last_line = lines[-1] if lines else "Internal processing error"
        return f"Scan failed: {last_line}"
    return err_str[:250]


def _job_error(job_id, error_message):
    with SCAN_JOBS_LOCK:
        if job_id in SCAN_JOBS:
            SCAN_JOBS[job_id]["status"] = "error"
            import re
            cleaned_log = re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", str(error_message))
            print(f"[JOB ERROR] job_id={job_id}: {cleaned_log}")
            SCAN_JOBS[job_id]["error"] = _sanitize_error_message(error_message)


def _run_ip_scan_job(job_id, target, ports="top-1000", user_id=None):
    """Runs the full scan pipeline in a background thread."""
    acquired = SCAN_SEMAPHORE.acquire(blocking=False)
    if not acquired:
        _job_log(job_id, "Scan queued — another scan is currently running.")
        acquired = SCAN_SEMAPHORE.acquire(blocking=True, timeout=180)
        if not acquired:
            _job_error(job_id, "Scan queue timed out. Please try again shortly.")
            return

    try:
        scan_id = uuid.uuid4().hex
        print(f"\n[SCAN] Starting IP scan job_id={job_id} scan_id={scan_id} target={target} user_id={user_id}")

        # 1) Host discovery
        _job_log(job_id, f"Checking if {target} is alive...")
        host_result = check_host_alive(target, scan_id=scan_id, user_id=user_id)

        # 2) Save scan history
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scan_history)")
            cols = [r[1] for r in cursor.fetchall()]
            if "scan_id" not in cols:
                try:
                    cursor.execute("ALTER TABLE scan_history ADD COLUMN scan_id TEXT")
                except Exception:
                    pass
            if "user_id" not in cols:
                try:
                    cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id INTEGER DEFAULT 1")
                except Exception:
                    pass

            cursor.execute(
                """
                INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, user_id, target, host_result["status"], host_result["scan_time"]),
            )
            conn.commit()
        finally:
            conn.close()

        if not host_result["alive"]:
            import ipaddress
            is_private = False
            try:
                ip_obj = ipaddress.ip_address(target)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            except ValueError:
                pass

            if is_private:
                from database.agent_helpers import list_agents_for_user, create_agent_job
                user_agents = list_agents_for_user(user_id) if user_id else []
                if user_agents:
                    create_agent_job(job_id, scan_id, target, user_id)
                    with SCAN_JOBS_LOCK:
                        if job_id in SCAN_JOBS:
                            SCAN_JOBS[job_id]["status"] = "waiting_for_agent"
                    _job_log(
                        job_id,
                        f"Target IP {target} is a private local network address (RFC 1918). "
                        "Job queued for your Local Scan Agent. Awaiting scan results from your network...",
                    )
                    return

                _job_log(
                    job_id,
                    f"Notice: Target IP {target} is a private local network address (RFC 1918). "
                    "Cloud-hosted environments (such as Render) cannot route packets into internal private LANs. "
                    "To scan local devices, run CyberShieldAI locally on your network.",
                )
                _job_log(
                    job_id,
                    f"Target {target} is unreachable from this cloud scanner environment. Stopping scan.",
                )
                _job_done(job_id, result_ip=target, scan_id=scan_id)
                return

            _job_log(
                job_id,
                f"Initial ICMP/TCP ping probes showed {target} un-responsive. Running full port scan (-Pn) to verify open ports...",
            )
            scan_res = scan_target(
                target, ports=ports, progress_callback=lambda m: _job_log(job_id, m), scan_id=scan_id
            )
            if not scan_res or scan_res.get("ports_count", 0) == 0:
                _job_log(
                    job_id,
                    f"Host {target} is unreachable (0 open ports found). Stopping scan.",
                )
                _job_done(job_id, result_ip=target, scan_id=scan_id)
                return
            else:
                # Ports were found! Update host status to Alive in both tables
                conn = get_db_connection()
                try:
                    conn.execute(
                        "UPDATE host_status SET status = 'Alive' WHERE target_ip = ? AND (scan_id = ? OR scan_id IS NULL)",
                        (target, scan_id),
                    )
                    conn.execute(
                        "UPDATE scan_history SET status = 'Alive' WHERE target_ip = ? AND (scan_id = ? OR scan_id IS NULL)",
                        (target, scan_id),
                    )
                    conn.commit()
                finally:
                    conn.close()
        else:
            # 3) Port scan
            scan_target(
                target, ports=ports, progress_callback=lambda m: _job_log(job_id, m), scan_id=scan_id
            )

        # 4) Vulnerability scan
        _job_log(job_id, "Running vulnerability scan...")
        scan_vulnerabilities(target, scan_id=scan_id)

        # 5) CVE scan
        _job_log(job_id, "Running CVE lookup...")
        scan_cves(target, scan_id=scan_id)

        # 6) Risk calculation
        _job_log(job_id, "Calculating risk score...")
        calculate_risk(target, scan_id=scan_id)

        # -----------------------------
        # Generate Security Alerts
        # -----------------------------

        _job_log(job_id, "Generating security alerts...")

        risk = get_latest_risk(target, scan_id=scan_id) if "get_latest_risk" in locals() or "get_latest_risk" in globals() else None
        ssl = get_latest_ssl(target)
        ports_data = get_ports(target, scan_id=scan_id)
        headers = get_security_headers(target)
        from database.db_helpers import get_vulnerabilities, get_cves
        vulns = get_vulnerabilities(target, scan_id=scan_id)
        cves = get_cves(target, scan_id=scan_id)

        generate_alerts(
            target=target,
            risk=risk,
            ssl=ssl,
            ports=ports_data,
            headers=headers,
            vulnerabilities=vulns,
            cves=cves,
            ip=target,
        )

        _job_log(job_id, "Security alerts generated.")

        _job_log(job_id, "Scan complete.")
        _job_done(job_id, result_ip=target, scan_id=scan_id)

    except Exception as e:
        _job_error(job_id, str(e))
    finally:
        SCAN_SEMAPHORE.release()


def resume_ip_scan_after_agent(job_id, scan_id, target, user_id, open_ports):
    """Resumes the scan pipeline after open port results are received from a local agent."""
    acquired = SCAN_SEMAPHORE.acquire(blocking=True, timeout=180)
    if not acquired:
        _job_error(job_id, "Scanner is currently busy with other tasks. Please try again shortly.")
        return

    try:
        from database.agent_helpers import save_agent_port_results, complete_agent_job
        save_agent_port_results(scan_id, target, open_ports)
        complete_agent_job(job_id)

        with SCAN_JOBS_LOCK:
            if job_id in SCAN_JOBS:
                SCAN_JOBS[job_id]["status"] = "running"

        _job_log(job_id, f"Local Agent returned {len(open_ports)} port(s). Resuming vulnerability analysis...")

        # 4) Vulnerability scan
        _job_log(job_id, "Running vulnerability scan...")
        scan_vulnerabilities(target, scan_id=scan_id)

        # 5) CVE scan
        _job_log(job_id, "Running CVE lookup...")
        scan_cves(target, scan_id=scan_id)

        # 6) Risk calculation
        _job_log(job_id, "Calculating risk score...")
        calculate_risk(target, scan_id=scan_id)

        # -----------------------------
        # Generate Security Alerts
        # -----------------------------

        _job_log(job_id, "Generating security alerts...")

        risk = get_latest_risk(target, scan_id=scan_id) if "get_latest_risk" in locals() or "get_latest_risk" in globals() else None
        ssl = get_latest_ssl(target)
        ports_data = get_ports(target, scan_id=scan_id)
        headers = get_security_headers(target)
        from database.db_helpers import get_vulnerabilities, get_cves
        vulns = get_vulnerabilities(target, scan_id=scan_id)
        cves = get_cves(target, scan_id=scan_id)

        generate_alerts(
            target=target,
            risk=risk,
            ssl=ssl,
            ports=ports_data,
            headers=headers,
            vulnerabilities=vulns,
            cves=cves,
            ip=target,
        )

        _job_log(job_id, "Security alerts generated.")

        _job_log(job_id, "Scan complete.")
        _job_done(job_id, result_ip=target, scan_id=scan_id)

    except Exception as e:
        _job_error(job_id, str(e))
    finally:
        SCAN_SEMAPHORE.release()


import json
import uuid
from datetime import datetime

from database.save_url_intelligence import save_url_intelligence
from database.ssl_results import save_ssl
from scanner.ssl_scanner import analyze_ssl
from scanner.technology_detector import detect_technology
from scanner.url_intelligence import analyze_url_intelligence
from scanner.url_scanner import scan_url, score_to_risk_level
from scanner.virustotal_scanner import query_virustotal


def _run_url_scan_job(job_id, url, user_id=None):
    """Runs the full URL analysis and port-scan pipeline asynchronously in a background thread."""
    acquired = SCAN_SEMAPHORE.acquire(blocking=False)
    if not acquired:
        _job_log(job_id, "Scan queued — another scan is currently running.")
        acquired = SCAN_SEMAPHORE.acquire(blocking=True, timeout=180)
        if not acquired:
            _job_error(job_id, "Scan queue timed out. Please try again shortly.")
            return

    try:
        scan_id = uuid.uuid4().hex
        print(f"\n[SCAN] Starting URL scan job_id={job_id} scan_id={scan_id} target={url} user_id={user_id}")

        _job_log(job_id, f"Scanning URL structure and protocol for {url}...")
        result = scan_url(url)

        _job_log(job_id, "Querying VirusTotal reputation intelligence...")
        try:
            vt_res = query_virustotal(result["url"], scan_id=scan_id)
            if vt_res and vt_res.get("configured"):
                _job_log(job_id, f"VirusTotal findings: {vt_res.get('risk_badge')} ({vt_res.get('malicious', 0)} malicious engines)")
        except Exception as vt_err:
            print("[VIRUSTOTAL QUERY ERROR]", vt_err)

        _job_log(job_id, "Detecting web technologies...")
        technology = detect_technology(result["url"])

        _job_log(job_id, "Gathering URL intelligence (WHOIS, GeoIP, DNS, WAF, Security Headers)...")
        url_info = analyze_url_intelligence(result["url"], scan_id=scan_id)
        save_url_intelligence(url_info, scan_id=scan_id)

        whois_info = url_info.get("whois", {}) if isinstance(url_info, dict) else {}
        creation_date_str = whois_info.get("creation_date") if isinstance(whois_info, dict) else None
        if creation_date_str and creation_date_str != "Unknown":
            try:
                created = datetime.strptime(creation_date_str, "%Y-%m-%d")
                age_days = (datetime.now() - created).days
                if age_days < 30:
                    result["score"] += 25
                    result["remarks"].append(
                        f"Domain was registered only {age_days} day(s) ago "
                        "(newly registered domains are commonly used for phishing/scam sites)"
                    )
                elif age_days < 180:
                    result["score"] += 10
                    result["remarks"].append(
                        f"Domain is relatively new ({age_days} days old)"
                    )
            except (ValueError, TypeError):
                pass
        result["risk"] = score_to_risk_level(result["score"])

        _job_log(job_id, "Analyzing SSL/TLS certificate...")
        ssl_data = analyze_ssl(result["url"])
        if ssl_data:
            save_ssl(ssl_data, scan_id=scan_id)

        ip = result["ip"]
        if isinstance(result["remarks"], list):
            remarks = " | ".join(result["remarks"])
        else:
            remarks = str(result["remarks"])

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(url_scan_results)")
            url_cols = [r[1] for r in cursor.fetchall()]
            if "user_id" not in url_cols:
                try:
                    cursor.execute("ALTER TABLE url_scan_results ADD COLUMN user_id INTEGER DEFAULT 1")
                except Exception:
                    pass

            conn.execute(
                """
                INSERT INTO url_scan_results
                (scan_id, user_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               """,
                (
                    scan_id,
                    user_id,
                    result["url"],
                    result["domain"],
                    result["ip"],
                    result["protocol"],
                    result["score"],
                    result["risk"],
                    remarks,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

            if isinstance(technology, (dict, list)):
                technology_json = json.dumps(technology)
            else:
                technology_json = json.dumps({"raw": str(technology)})

            conn.execute(
                """
                INSERT INTO technology_detection
                (scan_id, ip, url, technologies, scan_time)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    ip,
                    result["url"],
                    technology_json,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        if ip != "Unknown":
            _job_log(job_id, f"Checking if resolved IP {ip} is alive...")
            host_result = check_host_alive(ip, scan_id=scan_id, user_id=user_id)

            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(scan_history)")
                cols = [r[1] for r in cursor.fetchall()]
                if "scan_id" not in cols:
                    try:
                        cursor.execute("ALTER TABLE scan_history ADD COLUMN scan_id TEXT")
                    except Exception:
                        pass
                if "user_id" not in cols:
                    try:
                        cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id INTEGER DEFAULT 1")
                    except Exception:
                        pass

                cursor.execute(
                    """
                    INSERT INTO scan_history (scan_id, user_id, target_ip, status, scan_time)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (scan_id, user_id, ip, host_result["status"], host_result["scan_time"]),
                )
                conn.commit()
            finally:
                conn.close()

            _job_log(job_id, f"Scanning open ports for IP {ip}...")
            scan_target(
                ip,
                ports="top-1000",
                progress_callback=lambda m: _job_log(job_id, m),
                scan_id=scan_id,
                hostname=result.get("domain"),
            )

            _job_log(job_id, "Running vulnerability scan...")
            scan_vulnerabilities(ip, scan_id=scan_id)

            _job_log(job_id, "Running CVE lookup...")
            scan_cves(ip, scan_id=scan_id)

            _job_log(job_id, "Calculating risk score...")
            calculate_risk(ip, scan_id=scan_id)

        _job_log(job_id, "Running AI Security Assistant posture evaluation...")
        try:
            from ai.ai_engine import run_ai_engine
            from database.security_posture import save_security_posture
            ai_job_res = run_ai_engine(
                risk={"total_score": result["score"], "risk_level": result["risk"]},
                ports=[],
                vulnerabilities=[],
                ssl_info=ssl_data if 'ssl_data' in locals() else None,
                url_info=url_info if 'url_info' in locals() else None,
                technology=technology if 'technology' in locals() else None,
                result=result,
                ssl_scanned=('ssl_data' in locals() and bool(ssl_data)),
                dns_scanned=('url_info' in locals() and isinstance(url_info, dict) and bool(url_info.get('dns'))),
                technology_scanned=('technology' in locals() and bool(technology))
            )
            if ai_job_res and isinstance(ai_job_res, dict):
                save_security_posture(
                    scan_id=scan_id,
                    user_id=user_id,
                    ip=ip,
                    url=result["url"],
                    security_score=ai_job_res.get("score"),
                    security_grade=ai_job_res.get("grade", "N/A"),
                    threat_score=result["score"],
                    risk_level=result["risk"],
                    assessment_status=ai_job_res.get("status", "ASSESSED"),
                    scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
        except Exception as posture_err:
            print("[POSTURE] Scan Job Posture Error:", posture_err)

        _job_log(job_id, "Generating security alerts...")
        try:
            from alerts.alert_engine import generate_alerts
            from database.db_helpers import get_vulnerabilities, get_cves
            risk_info = get_latest_risk(ip) if ip != "Unknown" else {"total_score": result["score"], "risk_level": result["risk"]}
            ssl_info = ssl_data if ('ssl_data' in locals() and ssl_data) else get_latest_ssl(result.get("domain", ""))
            ports_info = get_ports(ip) if ip != "Unknown" else []
            headers_info = url_info.get("security_headers") if ('url_info' in locals() and isinstance(url_info, dict)) else get_security_headers(ip)
            vulns_info = get_vulnerabilities(ip, scan_id=scan_id) if ip != "Unknown" else []
            cves_info = get_cves(ip, scan_id=scan_id) if ip != "Unknown" else []

            generate_alerts(
                target=result["url"],
                risk=risk_info,
                ssl=ssl_info,
                ports=ports_info,
                headers=headers_info,
                vulnerabilities=vulns_info,
                cves=cves_info,
                ip=ip if ip != "Unknown" else result["domain"],
            )
            _job_log(job_id, "Security alerts generated.")
        except Exception as alert_err:
            print("[ALERT GENERATION ERROR]", alert_err)

        _job_log(job_id, "Scan complete.")
        _job_done(job_id, result_ip=ip if ip != "Unknown" else None, scan_id=scan_id)

    except Exception as e:
        _job_error(job_id, str(e))
    finally:
        SCAN_SEMAPHORE.release()


