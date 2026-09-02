import json
import os
import sqlite3
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_engine import get_db_connection

def _get_connection():
    return get_db_connection()



def _normalize_tech_list(raw_tech):
    """Parses and normalizes technology detection data into a set of clean strings."""
    if not raw_tech:
        return set()
    if isinstance(raw_tech, (set, list)):
        return {str(t).strip() for t in raw_tech if str(t).strip()}

    if isinstance(raw_tech, dict):
        techs = set()
        for k, v in raw_tech.items():
            if isinstance(v, list):
                techs.update(str(x).strip() for x in v if str(x).strip())
            elif v:
                techs.add(str(v).strip())
        return techs

    try:
        parsed = json.loads(raw_tech)
        return _normalize_tech_list(parsed)
    except Exception:
        pass

    return {t.strip() for t in str(raw_tech).split(",") if t.strip()}


def _extract_ports_from_scan(scan_info, conn=None):
    """Extracts a set of open port numbers from a scan record/id."""
    if isinstance(scan_info, dict) and "open_ports" in scan_info:
        return set(scan_info["open_ports"])

    scan_id = scan_info.get("scan_id") if isinstance(scan_info, dict) else str(scan_info)
    ip = scan_info.get("ip") if isinstance(scan_info, dict) else None

    close_conn = False
    if conn is None:
        conn = _get_connection()
        close_conn = True

    try:
        if scan_id:
            rows = conn.execute(
                "SELECT port FROM ports WHERE scan_id = ? AND (LOWER(state) = 'open' OR state IS NULL)",
                (scan_id,),
            ).fetchall()
            if rows:
                return {r["port"] for r in rows if r["port"] is not None}

        if ip:
            rows = conn.execute(
                "SELECT port FROM ports WHERE ip = ? AND (LOWER(state) = 'open' OR state IS NULL) ORDER BY id DESC LIMIT 50",
                (ip,),
            ).fetchall()
            return {r["port"] for r in rows if r["port"] is not None}

        return set()
    finally:
        if close_conn:
            conn.close()


def _extract_vulnerabilities_from_scan(scan_info, conn=None):
    """Extracts a set/list of vulnerability identifiers from a scan record."""
    vulns = []
    cves = set()

    if isinstance(scan_info, dict):
        if "vulnerabilities" in scan_info and scan_info["vulnerabilities"]:
            for v in scan_info["vulnerabilities"]:
                v_dict = dict(v) if hasattr(v, "keys") else (v if isinstance(v, dict) else {})
                name = v_dict.get("description") or v_dict.get("cve_id") or v_dict.get("service") or str(v)
                vulns.append(str(name).strip())
        if "cves" in scan_info and scan_info["cves"]:
            for c in scan_info["cves"]:
                cves.add(str(c).strip())

    scan_id = scan_info.get("scan_id") if isinstance(scan_info, dict) else str(scan_info)
    ip = scan_info.get("ip") if isinstance(scan_info, dict) else None

    close_conn = False
    if conn is None:
        conn = _get_connection()
        close_conn = True

    try:
        if scan_id:
            cve_rows = conn.execute("SELECT DISTINCT cve_id FROM cves WHERE scan_id = ?", (scan_id,)).fetchall()
            for r in cve_rows:
                if r["cve_id"]:
                    cves.add(str(r["cve_id"]).strip())

            v_rows = conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,)).fetchall()
            for r in v_rows:
                desc = r["description"] or r["service"] or r["risk"]
                if desc and desc not in vulns:
                    vulns.append(str(desc).strip())

        if not vulns and not cves and ip:
            v_rows = conn.execute("SELECT * FROM vulnerabilities WHERE ip = ? ORDER BY id DESC LIMIT 20", (ip,)).fetchall()
            for r in v_rows:
                desc = r["description"] or r["service"] or r["risk"]
                if desc and desc not in vulns:
                    vulns.append(str(desc).strip())

        combined = list(cves) + [v for v in vulns if v not in cves]
        return combined
    finally:
        if close_conn:
            conn.close()


def _extract_technologies_from_scan(scan_info, conn=None):
    """Extracts technologies set from a scan."""
    if isinstance(scan_info, dict) and "technologies" in scan_info:
        return _normalize_tech_list(scan_info["technologies"])

    scan_id = scan_info.get("scan_id") if isinstance(scan_info, dict) else str(scan_info)
    ip = scan_info.get("ip") if isinstance(scan_info, dict) else None
    url = scan_info.get("url") if isinstance(scan_info, dict) else None

    close_conn = False
    if conn is None:
        conn = _get_connection()
        close_conn = True

    try:
        if scan_id:
            row = conn.execute(
                "SELECT technologies, server FROM technology_detection WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
            if row:
                t = _normalize_tech_list(row["technologies"])
                if row["server"] and row["server"] != "Unknown":
                    t.add(str(row["server"]).strip())
                return t

        if ip or url:
            row = conn.execute(
                "SELECT technologies, server FROM technology_detection WHERE (ip = ? OR url = ?) ORDER BY id DESC LIMIT 1",
                (ip, url),
            ).fetchone()
            if row:
                t = _normalize_tech_list(row["technologies"])
                if row["server"] and row["server"] != "Unknown":
                    t.add(str(row["server"]).strip())
                return t

        return set()
    finally:
        if close_conn:
            conn.close()


def _extract_score(scan_info):
    """Extracts the numeric score from a scan record."""
    if not scan_info or not isinstance(scan_info, dict):
        return 0

    for key in ["score", "security_score", "threat_score", "total_score"]:
        val = scan_info.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                continue
    return 0


def compare_scans(latest_scan: dict, previous_scan: dict = None) -> dict:
    """
    Compares a latest scan snapshot with a previous scan snapshot.
    
    Returns exact required format:
    {
        "score_change": <int: latest_score - previous_score>,
        "new_ports": <list: newly opened ports>,
        "closed_ports": <list: closed ports>,
        "new_vulnerabilities": <list: newly detected vulnerabilities/CVEs>,
        "technology_changes": {
            "added": <list: newly detected technologies>,
            "removed": <list: removed technologies>
        }
    }
    """
    if not latest_scan or not isinstance(latest_scan, dict):
        return {
            "score_change": 0,
            "new_ports": [],
            "closed_ports": [],
            "new_vulnerabilities": [],
            "technology_changes": {"added": [], "removed": []},
        }

    latest_score = _extract_score(latest_scan)
    latest_ports = _extract_ports_from_scan(latest_scan)
    latest_vulns = set(_extract_vulnerabilities_from_scan(latest_scan))
    latest_tech = _extract_technologies_from_scan(latest_scan)

    if not previous_scan or not isinstance(previous_scan, dict):
        return {
            "score_change": 0,
            "new_ports": sorted(list(latest_ports)),
            "closed_ports": [],
            "new_vulnerabilities": sorted(list(latest_vulns)),
            "technology_changes": {
                "added": sorted(list(latest_tech)),
                "removed": [],
            },
        }

    previous_score = _extract_score(previous_scan)
    previous_ports = _extract_ports_from_scan(previous_scan)
    previous_vulns = set(_extract_vulnerabilities_from_scan(previous_scan))
    previous_tech = _extract_technologies_from_scan(previous_scan)

    # 1. Score Change
    score_change = latest_score - previous_score

    # 2. New Open Ports
    new_ports = sorted(list(latest_ports - previous_ports))

    # 3. Closed Ports
    closed_ports = sorted(list(previous_ports - latest_ports))

    # 4. New Vulnerabilities
    new_vulnerabilities = sorted(list(latest_vulns - previous_vulns))

    # 5. Technology Changes
    added_tech = sorted(list(latest_tech - previous_tech))
    removed_tech = sorted(list(previous_tech - latest_tech))

    return {
        "score_change": score_change,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "new_vulnerabilities": new_vulnerabilities,
        "technology_changes": {
            "added": added_tech,
            "removed": removed_tech,
        },
    }


def compare_latest_scans(target: str = None) -> dict:
    """
    Fetches the latest scan and immediately preceding scan from the existing
    CyberShieldAI scan history database and compares them.
    """
    from scanner.scan_snapshot import get_scan_snapshot
    conn = _get_connection()
    try:
        latest_scan = None
        previous_scan = None

        if target:
            like_target = f"%{target}%"
            # Query target in url_scan_results
            rows = conn.execute(
                """
                SELECT * FROM url_scan_results
                WHERE (ip = ? OR domain = ? OR url = ? OR url LIKE ?)
                ORDER BY id DESC
                LIMIT 2
                """,
                (target, target, target, like_target),
            ).fetchall()

            if rows and len(rows) >= 1:
                scan_id_1 = rows[0]["scan_id"]
                latest_scan = get_scan_snapshot(scan_id_1) if scan_id_1 else dict(rows[0])
                if len(rows) >= 2:
                    scan_id_2 = rows[1]["scan_id"]
                    previous_scan = get_scan_snapshot(scan_id_2) if scan_id_2 else dict(rows[1])
            else:
                # Fallback to host_status / scan_history for IP target
                host_rows = conn.execute(
                    """
                    SELECT * FROM scan_history
                    WHERE target_ip = ?
                    ORDER BY id DESC
                    LIMIT 2
                    """,
                    (target,),
                ).fetchall()
                if not host_rows:
                    host_rows = conn.execute(
                        """
                        SELECT * FROM host_status
                        WHERE target_ip = ?
                        ORDER BY id DESC
                        LIMIT 2
                        """,
                        (target,),
                    ).fetchall()

                if host_rows and len(host_rows) >= 1:
                    latest_scan = {"ip": target, "scan_time": host_rows[0]["scan_time"]}
                    if len(host_rows) >= 2:
                        previous_scan = {"ip": target, "scan_time": host_rows[1]["scan_time"]}
        else:
            # Query the 2 most recent URL scans across the entire database
            rows = conn.execute(
                """
                SELECT * FROM url_scan_results
                ORDER BY id DESC
                LIMIT 2
                """
            ).fetchall()

            if rows and len(rows) >= 1:
                scan_id_1 = rows[0]["scan_id"]
                latest_scan = get_scan_snapshot(scan_id_1) if scan_id_1 else dict(rows[0])
                if len(rows) >= 2:
                    scan_id_2 = rows[1]["scan_id"]
                    previous_scan = get_scan_snapshot(scan_id_2) if scan_id_2 else dict(rows[1])

        return compare_scans(latest_scan, previous_scan)
    finally:
        conn.close()


# Alias for direct import
scan_comparison_engine = compare_latest_scans


if __name__ == "__main__":
    print("\n--- Running Scan Comparison Engine ---")
    diff = compare_latest_scans()
    print("Result:")
    print(json.dumps(diff, indent=2))
