import base64
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

DB_PATH = os.path.join(BASE_DIR, "cybershield.db")


def _load_env():
    env_file = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k:
                            os.environ[k] = v
        except Exception:
            pass

_load_env()


from database.db_engine import get_db_connection

def _get_conn():
    return get_db_connection()


def init_virustotal_table():
    """
    Initializes virustotal_results table in cybershield.db.
    """
    conn = _get_conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS virustotal_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                url TEXT,
                domain TEXT,
                malicious INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0,
                harmless INTEGER DEFAULT 0,
                undetected INTEGER DEFAULT 0,
                total_engines INTEGER DEFAULT 0,
                risk_badge TEXT DEFAULT 'Safe',
                reputation INTEGER DEFAULT 0,
                categories TEXT,
                status TEXT DEFAULT 'success',
                message TEXT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


init_virustotal_table()


def calculate_vt_risk_badge(malicious: int, suspicious: int) -> str:
    """
    Calculates the risk badge based on VirusTotal engine detections.
    """
    if malicious > 0:
        return "Malicious"
    elif suspicious > 0:
        return "Suspicious"
    return "Safe"


def save_virustotal_result(data: dict, scan_id: str = None) -> int:
    """
    Saves a VirusTotal analysis result into the database.
    """
    init_virustotal_table()
    conn = _get_conn()
    try:
        url = data.get("url", "")
        domain = data.get("domain", "")
        malicious = int(data.get("malicious", 0))
        suspicious = int(data.get("suspicious", 0))
        harmless = int(data.get("harmless", 0))
        undetected = int(data.get("undetected", 0))
        total_engines = int(data.get("total_engines", 0))
        risk_badge = data.get("risk_badge") or calculate_vt_risk_badge(malicious, suspicious)
        reputation = int(data.get("reputation", 0))
        
        categories = data.get("categories", {})
        cat_str = json.dumps(categories) if isinstance(categories, (dict, list)) else str(categories)
        
        status = data.get("status", "success")
        message = data.get("message", "")
        scan_time = data.get("scan_time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO virustotal_results (
                scan_id, url, domain, malicious, suspicious, harmless,
                undetected, total_engines, risk_badge, reputation,
                categories, status, message, scan_time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                url,
                domain,
                malicious,
                suspicious,
                harmless,
                undetected,
                total_engines,
                risk_badge,
                reputation,
                cat_str,
                status,
                message,
                scan_time,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        print(f"[VIRUSTOTAL DB ERROR] Failed to save result: {e}")
        return 0
    finally:
        conn.close()


def query_virustotal(url: str, api_key: str = None, scan_id: str = None) -> dict:
    """
    Queries the VirusTotal API v3 for a given URL.
    Fetches:
    - malicious
    - suspicious
    - harmless
    - undetected
    Determines risk badge ('Safe', 'Suspicious', 'Malicious').
    Gracefully handles missing API key or network errors.
    """
    if not url:
        return {
            "status": "error",
            "configured": False,
            "url": "",
            "domain": "",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "risk_badge": "Safe",
            "reputation": 0,
            "categories": {},
            "message": "URL not provided.",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # Clean & normalize URL and domain
    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc or parsed.path

    # Check for API key
    _load_env()
    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")

    if not key or str(key).strip().lower() in ["", "none", "null", "your_api_key_here"]:
        fallback_data = {
            "status": "missing_api_key",
            "configured": False,
            "url": url,
            "domain": domain,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "risk_badge": "Safe",
            "reputation": 0,
            "categories": {},
            "message": "VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY to enable automated reputation lookup.",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_virustotal_result(fallback_data, scan_id=scan_id)
        return fallback_data

    # Prepare base64 URL ID for VirusTotal API v3
    # VT v3 requires URL-safe base64 without padding '='
    try:
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={
                "x-apikey": key.strip(),
                "User-Agent": "CyberShieldAI-SOC/2.0",
                "Accept": "application/json",
            },
            method="GET",
        )

        from scanner.config import SCAN_READ_TIMEOUT
        with urllib.request.urlopen(req, timeout=SCAN_READ_TIMEOUT) as response:
            if response.status == 200:
                body = response.read().decode("utf-8")
                json_data = json.loads(body)
                attributes = json_data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                total_engines = malicious + suspicious + harmless + undetected
                reputation = int(attributes.get("reputation", 0))
                categories = attributes.get("categories", {})
                risk_badge = calculate_vt_risk_badge(malicious, suspicious)

                result_data = {
                    "status": "success",
                    "configured": True,
                    "url": url,
                    "domain": domain,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total_engines,
                    "risk_badge": risk_badge,
                    "reputation": reputation,
                    "categories": categories,
                    "message": f"Scanned by {total_engines} engines ({malicious} malicious, {suspicious} suspicious).",
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                save_virustotal_result(result_data, scan_id=scan_id)
                return result_data

    except urllib.error.HTTPError as http_err:
        if http_err.code == 404:
            # URL not yet analyzed in VirusTotal database
            result_data = {
                "status": "not_found",
                "configured": True,
                "url": url,
                "domain": domain,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_engines": 0,
                "risk_badge": "Safe",
                "reputation": 0,
                "categories": {},
                "message": "URL has not been previously analyzed in VirusTotal database.",
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            save_virustotal_result(result_data, scan_id=scan_id)
            return result_data
        elif http_err.code == 401 or http_err.code == 403:
            msg = "Invalid or unauthorized VirusTotal API Key."
        else:
            msg = f"VirusTotal API HTTP error: {http_err.code}"

        result_data = {
            "status": "api_error",
            "configured": True,
            "url": url,
            "domain": domain,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "risk_badge": "Safe",
            "reputation": 0,
            "categories": {},
            "message": msg,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_virustotal_result(result_data, scan_id=scan_id)
        return result_data

    except Exception as e:
        result_data = {
            "status": "network_error",
            "configured": True,
            "url": url,
            "domain": domain,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "risk_badge": "Safe",
            "reputation": 0,
            "categories": {},
            "message": f"VirusTotal query failed: {str(e)}",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_virustotal_result(result_data, scan_id=scan_id)
        return result_data


def get_latest_virustotal(url: str = None, domain: str = None, scan_id: str = None) -> dict:
    """
    Retrieves the most recent VirusTotal scan result for a URL, domain, or scan_id.
    """
    init_virustotal_table()
    conn = _get_conn()
    try:
        row = None
        if scan_id:
            row = conn.execute(
                "SELECT * FROM virustotal_results WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
                (scan_id,),
            ).fetchone()

        if not row and url:
            row = conn.execute(
                "SELECT * FROM virustotal_results WHERE url = ? ORDER BY id DESC LIMIT 1",
                (url,),
            ).fetchone()

        if not row and domain:
            row = conn.execute(
                "SELECT * FROM virustotal_results WHERE domain = ? OR url LIKE ? ORDER BY id DESC LIMIT 1",
                (domain, f"%{domain}%"),
            ).fetchone()

        if not row:
            # Fallback to the latest record in table
            row = conn.execute(
                "SELECT * FROM virustotal_results ORDER BY id DESC LIMIT 1"
            ).fetchone()

        if row:
            res = dict(row)
            if res.get("status") == "missing_api_key":
                _load_env()
                key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
                if key and str(key).strip().lower() not in ["", "none", "null", "your_api_key_here"]:
                    target_url = url or res.get("url")
                    if target_url:
                        conn.close()
                        return query_virustotal(target_url, scan_id=scan_id or res.get("scan_id"))

            if res.get("categories"):
                try:
                    res["categories"] = json.loads(res["categories"])
                except Exception:
                    pass
            res["configured"] = res.get("status") != "missing_api_key"
            return res

        # Default fallback
        _load_env()
        key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
        if key and str(key).strip().lower() not in ["", "none", "null", "your_api_key_here"] and url:
            conn.close()
            return query_virustotal(url, scan_id=scan_id)

        return {

            "status": "missing_api_key",
            "configured": False,
            "url": url or "",
            "domain": domain or "",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "risk_badge": "Safe",
            "reputation": 0,
            "categories": {},
            "message": "No VirusTotal records found.",
            "scan_time": "-",
        }
    finally:
        conn.close()
