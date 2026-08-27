import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

DB_PATH = os.path.join(BASE_DIR, "cybershield.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _clean_date_label(timestamp_str: str) -> str:
    """Helper to convert timestamps to compact readable labels (e.g., '08/15 14:30')."""
    if not timestamp_str or str(timestamp_str).strip() in ["", "None", "null", "-"]:
        return "Scan"
    try:
        clean = str(timestamp_str).split(".")[0].strip()
        if len(clean) >= 16:
            dt = datetime.strptime(clean[:19], "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%m/%d %H:%M")
        elif len(clean) == 10:
            dt = datetime.strptime(clean, "%Y-%m-%d")
            return dt.strftime("%m/%d")
        return clean[5:16]
    except Exception:
        parts = str(timestamp_str).split(" ")
        if len(parts) == 2:
            return f"{parts[0][5:]} {parts[1][:5]}"
        return str(timestamp_str)[:10]


def get_security_score_trend(limit: int = 15) -> dict:
    """
    Chart 1: Security Score Over Time
    Aggregates historical security posture & scan assessments chronologically.
    Returns scores ranging from 0 to 100 with target and scan time labels.
    """
    conn = _get_conn()
    data_points = []
    try:
        # First priority: security_posture table
        try:
            rows = conn.execute(
                """
                SELECT COALESCE(url, ip, 'Host') AS target, url, ip, security_score, scan_time, scan_id
                FROM security_posture
                WHERE security_score IS NOT NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit * 2,),
            ).fetchall()
            for r in rows:
                target = r["url"] or r["ip"] or r["target"] or "Host"
                scan_time = str(r["scan_time"]) if r["scan_time"] else ""
                score = int(r["security_score"])
                data_points.append({"target": target, "score": score, "scan_time": scan_time})
        except Exception as e:
            print(f"[TREND ANALYTICS] security_posture query note: {e}")

        # Second priority: risk_summary table (converted: 100 - total_score)
        if len(data_points) < limit:
            try:
                rows = conn.execute(
                    """
                    SELECT ip AS target, total_score, scan_time, scan_id
                    FROM risk_summary
                    WHERE total_score IS NOT NULL
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit * 2,),
                ).fetchall()
                for r in rows:
                    target = r["target"] or "Host"
                    scan_time = str(r["scan_time"]) if r["scan_time"] else ""
                    raw_risk = int(r["total_score"])
                    score = max(0, min(100, 100 - raw_risk))
                    data_points.append({"target": target, "score": score, "scan_time": scan_time})
            except Exception as e:
                print(f"[TREND ANALYTICS] risk_summary query note: {e}")

        # Third priority: url_scan_results table
        if len(data_points) < limit:
            try:
                rows = conn.execute(
                    """
                    SELECT COALESCE(domain, url, ip, 'URL') AS target, url, score, scan_time, scan_id
                    FROM url_scan_results
                    WHERE score IS NOT NULL
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit * 2,),
                ).fetchall()
                for r in rows:
                    target = r["target"] or r["url"] or "URL"
                    scan_time = str(r["scan_time"]) if r["scan_time"] else ""
                    raw_risk = int(r["score"])
                    score = max(0, min(100, 100 - raw_risk))
                    data_points.append({"target": target, "score": score, "scan_time": scan_time})
            except Exception as e:
                print(f"[TREND ANALYTICS] url_scan_results query note: {e}")
    finally:
        conn.close()

    # Sort ascending chronologically
    data_points.sort(key=lambda x: x.get("scan_time") or "")

    # Take the latest `limit` points
    final_points = data_points[-limit:] if len(data_points) > limit else data_points

    labels = [_clean_date_label(p.get("scan_time")) for p in final_points]
    scores = [p.get("score", 100) for p in final_points]
    targets = [p.get("target", "Target") for p in final_points]

    avg_score = round(sum(scores) / len(scores), 1) if scores else 100
    latest_score = scores[-1] if scores else 100

    return {
        "labels": labels if labels else ["Initial"],
        "scores": scores if scores else [100],
        "targets": targets if targets else ["Default"],
        "average_score": avg_score,
        "latest_score": latest_score,
        "count": len(scores),
    }


def get_alert_trend(limit: int = 15) -> dict:
    """
    Chart 2: Alert Trend Over Time
    Aggregates historical alert events breakdown by severity:
    - Critical
    - High
    - Medium
    - Low / Info
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT severity, COALESCE(created_at, scan_time) as alert_time, alert_type
            FROM alerts
            WHERE COALESCE(created_at, scan_time) IS NOT NULL
            ORDER BY id ASC
            """
        ).fetchall()
    except Exception as e:
        print(f"[TREND ANALYTICS] alerts query note: {e}")
        rows = []
    finally:
        conn.close()

    if not rows:
        return {
            "labels": ["No Alerts"],
            "critical": [0],
            "high": [0],
            "medium": [0],
            "low": [0],
            "total_alerts": 0,
        }

    # Group by date or interval
    time_groups = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})

    for r in rows:
        raw_time = str(r["alert_time"] or "")
        label = _clean_date_label(raw_time)
        sev = str(r["severity"] or "medium").strip().lower()

        if "crit" in sev:
            time_groups[label]["critical"] += 1
        elif "high" in sev:
            time_groups[label]["high"] += 1
        elif "med" in sev:
            time_groups[label]["medium"] += 1
        else:
            time_groups[label]["low"] += 1

    # Format sorted arrays
    all_labels = list(time_groups.keys())
    if len(all_labels) > limit:
        all_labels = all_labels[-limit:]

    critical_data = [time_groups[lbl]["critical"] for lbl in all_labels]
    high_data = [time_groups[lbl]["high"] for lbl in all_labels]
    medium_data = [time_groups[lbl]["medium"] for lbl in all_labels]
    low_data = [time_groups[lbl]["low"] for lbl in all_labels]

    return {
        "labels": all_labels,
        "critical": critical_data,
        "high": high_data,
        "medium": medium_data,
        "low": low_data,
        "total_alerts": len(rows),
    }


def get_vulnerability_trend(limit: int = 15) -> dict:
    """
    Chart 3: Vulnerability Trend Over Time
    Tracks Critical, High, Medium, and Low vulnerabilities detected across scans.
    """
    conn = _get_conn()
    trend_entries = []
    try:
        rows = conn.execute(
            """
            SELECT critical_count, high_count, medium_count, low_count, scan_time
            FROM risk_summary
            WHERE scan_time IS NOT NULL
            ORDER BY id ASC
            """
        ).fetchall()

        for r in rows:
            label = _clean_date_label(r["scan_time"])
            trend_entries.append({
                "label": label,
                "critical": int(r["critical_count"] or 0),
                "high": int(r["high_count"] or 0),
                "medium": int(r["medium_count"] or 0),
                "low": int(r["low_count"] or 0),
            })
    except Exception as e:
        print(f"[TREND ANALYTICS] risk_summary trend query note: {e}")
    finally:
        conn.close()

    if not trend_entries:
        return {
            "labels": ["Initial"],
            "critical": [0],
            "high": [0],
            "medium": [0],
            "low": [0],
            "total_vulns": 0,
        }

    # Slice to latest `limit`
    if len(trend_entries) > limit:
        trend_entries = trend_entries[-limit:]

    labels = [e["label"] for e in trend_entries]
    crit_vals = [e["critical"] for e in trend_entries]
    high_vals = [e["high"] for e in trend_entries]
    med_vals = [e["medium"] for e in trend_entries]
    low_vals = [e["low"] for e in trend_entries]

    total_vulns = sum(crit_vals) + sum(high_vals) + sum(med_vals) + sum(low_vals)

    return {
        "labels": labels,
        "critical": crit_vals,
        "high": high_vals,
        "medium": med_vals,
        "low": low_vals,
        "total_vulns": total_vulns,
    }


def get_risk_distribution() -> dict:
    """
    Chart 4: Risk Distribution
    Aggregates overall posture distribution (Critical, High, Medium, Low, Safe)
    across all scanned assets in risk_summary, url_scan_results, and security_posture.
    """
    conn = _get_conn()
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Safe": 0}
    try:
        # IP Scans Risk Levels
        ip_rows = conn.execute(
            """
            SELECT risk_level, COUNT(*) as cnt
            FROM risk_summary
            WHERE risk_level IS NOT NULL
            GROUP BY risk_level
            """
        ).fetchall()
        for r in ip_rows:
            lvl = str(r["risk_level"]).strip().capitalize()
            if lvl in counts:
                counts[lvl] += r["cnt"]
            elif "Crit" in lvl:
                counts["Critical"] += r["cnt"]
            elif "High" in lvl:
                counts["High"] += r["cnt"]
            elif "Med" in lvl:
                counts["Medium"] += r["cnt"]
            else:
                counts["Low"] += r["cnt"]

        # URL Scans Risk Levels
        url_rows = conn.execute(
            """
            SELECT risk, COUNT(*) as cnt
            FROM url_scan_results
            WHERE risk IS NOT NULL
            GROUP BY risk
            """
        ).fetchall()
        for r in url_rows:
            lvl = str(r["risk"]).strip().capitalize()
            if lvl in counts:
                counts[lvl] += r["cnt"]
            elif "Crit" in lvl:
                counts["Critical"] += r["cnt"]
            elif "High" in lvl:
                counts["High"] += r["cnt"]
            elif "Med" in lvl:
                counts["Medium"] += r["cnt"]
            elif "Safe" in lvl or "None" in lvl or "Secure" in lvl:
                counts["Safe"] += r["cnt"]
            else:
                counts["Low"] += r["cnt"]

    except Exception as e:
        print("[ANALYTICS RISK DISTRIBUTION ERROR]", e)
    finally:
        conn.close()

    total_assets = sum(counts.values())
    if total_assets == 0:
        counts["Safe"] = 1
        total_assets = 1

    labels = ["Critical", "High", "Medium", "Low", "Safe"]
    values = [counts[l] for l in labels]
    percentages = [round((v / total_assets) * 100, 1) for v in values]

    return {
        "labels": labels,
        "counts": values,
        "percentages": percentages,
        "total_scanned_assets": total_assets,
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"],
        "safe_count": counts["Safe"],
    }


def get_all_trend_analytics(limit: int = 15) -> dict:
    """
    Consolidates all 4 security trend charts into a unified data payload.
    """
    return {
        "security_score_trend": get_security_score_trend(limit=limit),
        "alert_trend": get_alert_trend(limit=limit),
        "vulnerability_trend": get_vulnerability_trend(limit=limit),
        "risk_distribution": get_risk_distribution(),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
