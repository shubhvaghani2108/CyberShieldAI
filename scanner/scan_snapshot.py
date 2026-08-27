import sqlite3
import os
import json
from database.db_helpers import get_db_connection

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def get_scan_snapshot(scan_id: str) -> dict:
    """
    Builds a normalized, empirical scan snapshot from the database for a given scan_id.
    Do NOT infer values from score.
    """
    if not scan_id:
        return None

    conn = get_db_connection()

    # 1. Base URL Scan Result
    url_res = conn.execute(
        "SELECT * FROM url_scan_results WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,)
    ).fetchone()
    url_dict = dict(url_res) if url_res else {}

    # 2. Security Posture
    posture_res = conn.execute(
        "SELECT * FROM security_posture WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,)
    ).fetchone()
    posture_dict = dict(posture_res) if posture_res else {}

    # Target fields
    url = posture_dict.get("url") or url_dict.get("url") or ""
    ip = posture_dict.get("ip") or url_dict.get("ip") or ""
    protocol = url_dict.get("protocol", "HTTPS")
    
    if posture_dict and ("assessment_status" in posture_dict or "security_score" in posture_dict):
        security_score = posture_dict.get("security_score")
        if posture_dict.get("assessment_status") == "INCONCLUSIVE":
            security_score = None
    else:
        security_score = None if (url_dict.get("ip") in ("Unknown", "unknown", None) or url_dict.get("protocol") == "unknown") else url_dict.get("score", 0)

    security_grade = posture_dict.get("security_grade") if posture_dict else ("N/A" if security_score is None else "A+")
    threat_score = posture_dict.get("threat_score") if posture_dict and posture_dict.get("threat_score") is not None else url_dict.get("score", 0)
    risk_level = posture_dict.get("risk_level") or url_dict.get("risk", "Low")
    scan_time = posture_dict.get("scan_time") or url_dict.get("scan_time") or ""

    # 3. Open Ports
    port_rows = conn.execute(
        "SELECT port FROM ports WHERE scan_id = ? AND LOWER(state) = 'open'",
        (scan_id,)
    ).fetchall()
    open_ports = sorted(list({r["port"] for r in port_rows}))

    # 4. SSL / TLS
    ssl_row = conn.execute(
        "SELECT * FROM ssl_results WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,)
    ).fetchone()
    ssl_dict = dict(ssl_row) if ssl_row else {}

    tls_info = {
        "tls_version": ssl_dict.get("tls_version", ""),
        "expired": bool(ssl_dict.get("expired", 0)),
        "self_signed": bool(ssl_dict.get("self_signed", 0)),
        "cipher_suite": ssl_dict.get("cipher_suite", ""),
        "key_size": ssl_dict.get("key_size", "")
    }

    # 5. Security Headers
    header_rows = conn.execute(
        "SELECT header_name, status FROM security_headers WHERE scan_id = ?",
        (scan_id,)
    ).fetchall()
    
    headers_dict = {}
    if header_rows:
        for r in header_rows:
            headers_dict[r["header_name"]] = (str(r["status"]).lower() in ["present", "true", "1"])
    else:
        headers_dict = None

    # 6. Technology Detection
    tech_rows = conn.execute(
        "SELECT technologies FROM technology_detection WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,)
    ).fetchall()
    
    tech_list = []
    if tech_rows and tech_rows[0]["technologies"]:
        raw_tech = tech_rows[0]["technologies"]
        try:
            parsed = json.loads(raw_tech)
            if isinstance(parsed, list):
                tech_list = parsed
            elif isinstance(parsed, dict):
                tech_list = list(parsed.keys())
        except Exception:
            tech_list = [t.strip() for t in raw_tech.split(",") if t.strip()]

    # Normalize technologies
    normalized_tech = []
    forbidden_terms = {"classified", "server", "technologies", "raw"}
    for t in tech_list:
        clean_t = str(t).strip()
        if clean_t and clean_t.lower() not in forbidden_terms:
            normalized_tech.append(clean_t)

    # 7. CVE Vulnerabilities
    cve_rows = conn.execute(
        "SELECT DISTINCT cve_id FROM cves WHERE scan_id = ? AND cve_id IS NOT NULL",
        (scan_id,)
    ).fetchall()
    cves = sorted(list({r["cve_id"] for r in cve_rows if r["cve_id"]}))

    # 8. Vulnerabilities List
    vuln_rows = conn.execute(
        "SELECT * FROM vulnerabilities WHERE scan_id = ?",
        (scan_id,)
    ).fetchall()
    vulnerabilities = [dict(r) for r in vuln_rows]

    # 9. WAF Status
    waf_row = conn.execute(
        "SELECT waf FROM url_intelligence WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,)
    ).fetchone()
    
    if waf_row and waf_row["waf"]:
        provider = waf_row["waf"]
        detected = (provider.lower() not in ["none", "unknown", "no waf detected", ""])
        waf_info = {
            "detected": detected,
            "provider": provider if detected else "None",
            "confidence": "High" if detected else "Low"
        }
    else:
        waf_info = None

    conn.close()

    return {
        "scan_id": scan_id,
        "url": url,
        "ip": ip,
        "protocol": protocol,
        "security_score": security_score,
        "score": security_score,
        "security_grade": security_grade,
        "threat_score": threat_score,
        "risk_level": risk_level,
        "scan_time": scan_time,
        "open_ports": open_ports,
        "tls": tls_info,
        "tls_version": tls_info["tls_version"],
        "ssl_data": ssl_dict,
        "headers": headers_dict,
        "headers_available": (headers_dict is not None),
        "technologies": normalized_tech,
        "technologies_available": (tech_rows is not None and len(tech_rows) > 0),
        "cves": cves,
        "vulnerabilities": vulnerabilities,
        "waf": waf_info,
        "waf_available": (waf_info is not None)
    }


def get_latest_scan_id(target: str) -> str:
    """
    Finds the most recent scan_id associated with an IP, domain, or URL.
    """
    conn = get_db_connection()
    like_target = f"%{target}%"
    row = conn.execute(
        """
        SELECT scan_id
        FROM url_scan_results
        WHERE (ip = ? OR domain = ? OR url = ? OR url LIKE ?) AND scan_id IS NOT NULL
        ORDER BY id DESC
        LIMIT 1
        """,
        (target, target, target, like_target)
    ).fetchone()
    if not row:
        row = conn.execute(
            """
            SELECT scan_id
            FROM security_posture
            WHERE (ip = ? OR url = ? OR url LIKE ?) AND scan_id IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (target, target, like_target)
        ).fetchone()
    if not row:
        row = conn.execute(
            """
            SELECT scan_id
            FROM scan_history
            WHERE target_ip = ? AND scan_id IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (target,)
        ).fetchone()
    if not row:
        row = conn.execute(
            """
            SELECT scan_id
            FROM ports
            WHERE ip = ? AND scan_id IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (target,)
        ).fetchone()
    conn.close()
    return row["scan_id"] if row else None


def get_previous_scan_id(target: str, current_scan_id: str) -> str:
    """
    Finds the immediately preceding distinct scan_id for a target.
    """
    conn = get_db_connection()
    like_target = f"%{target}%"
    
    if current_scan_id:
        row = conn.execute(
            """
            SELECT scan_id
            FROM url_scan_results
            WHERE (ip = ? OR domain = ? OR url = ? OR url LIKE ?)
              AND scan_id IS NOT NULL
              AND scan_id != ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (target, target, target, like_target, current_scan_id)
        ).fetchone()
        if not row:
            row = conn.execute(
                """
                SELECT scan_id
                FROM security_posture
                WHERE (ip = ? OR url = ? OR url LIKE ?)
                  AND scan_id IS NOT NULL
                  AND scan_id != ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (target, target, like_target, current_scan_id)
            ).fetchone()
        if not row:
            row = conn.execute(
                """
                SELECT scan_id
                FROM scan_history
                WHERE target_ip = ?
                  AND scan_id IS NOT NULL
                  AND scan_id != ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (target, current_scan_id)
            ).fetchone()
        if not row:
            row = conn.execute(
                """
                SELECT scan_id
                FROM ports
                WHERE ip = ?
                  AND scan_id IS NOT NULL
                  AND scan_id != ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (target, current_scan_id)
            ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT scan_id
            FROM url_scan_results
            WHERE (ip = ? OR domain = ? OR url = ? OR url LIKE ?)
              AND scan_id IS NOT NULL
            ORDER BY id DESC
            LIMIT 1 OFFSET 1
            """,
            (target, target, target, like_target)
        ).fetchone()
        if not row:
            row = conn.execute(
                """
                SELECT scan_id
                FROM scan_history
                WHERE target_ip = ? AND scan_id IS NOT NULL
                ORDER BY id DESC
                LIMIT 1 OFFSET 1
                """,
                (target,)
            ).fetchone()

    conn.close()
    return row["scan_id"] if row else None
