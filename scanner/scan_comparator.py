"""
scanner/scan_comparator.py

Compares two scan instance snapshots (Current vs Previous) for the same target
and generates a precise, empirical change delta based strictly on persisted scan data.
No guessed thresholds or hardcoded score assumptions.
"""


def _extract_posture_score(scan_dict):
    if not scan_dict or not isinstance(scan_dict, dict):
        return None
    if scan_dict.get("status") == "INCONCLUSIVE" or scan_dict.get("assessment_status") == "INCONCLUSIVE":
        return None
    score = scan_dict.get("score")
    if score is None:
        score = scan_dict.get("security_score")
    if score is None:
        return None
    try:
        return int(score)
    except (ValueError, TypeError):
        return None


def compare_url_scans(current: dict, previous: dict) -> dict:
    """
    Compares two normalized URL scan snapshots.
    Handles INCONCLUSIVE scans cleanly without calculating false deltas.
    """
    curr_scan_id = current.get("scan_id") if current else "N/A"
    prev_scan_id = previous.get("scan_id") if previous else "N/A"
    print(f"\n[SNAPSHOT] current scan_id={curr_scan_id}")
    print(f"[SNAPSHOT] previous scan_id={prev_scan_id}")

    curr_score = _extract_posture_score(current)
    curr_grade = current.get("grade") or current.get("security_grade") or ("N/A" if curr_score is None else "A+")

    if not previous or not isinstance(previous, dict) or not previous.get("has_previous", True):
        print(f"[POSTURE] First scan detected for target. Current score: {curr_score if curr_score is not None else 'N/A'} ({curr_grade})")
        return {
            "has_previous": False,
            "score_diff": 0 if curr_score is not None else None,
            "score_direction": "same" if curr_score is not None else "inconclusive",
            "curr_score": curr_score,
            "curr_grade": curr_grade,
            "prev_score": None,
            "prev_grade": None,
            "changes": [],
            "summary_text": "Initial Security Assessment. No previous scan available for comparison."
        }

    prev_score = _extract_posture_score(previous)
    prev_grade = previous.get("grade") or previous.get("security_grade") or ("N/A" if prev_score is None else "A+")

    changes = []

    # Handle inconclusive scans cleanly
    if curr_score is None and prev_score is not None:
        return {
            "has_previous": True,
            "score_diff": None,
            "score_direction": "inconclusive",
            "prev_score": prev_score,
            "prev_grade": prev_grade,
            "curr_score": None,
            "curr_grade": "N/A",
            "prev_time": previous.get("scan_time", "Previous"),
            "curr_time": current.get("scan_time", "Current") if current else "Current",
            "changes": [{
                "category": "posture",
                "type": "neutral",
                "icon": "[i]",
                "text": "No valid current security score available."
            }],
            "summary_text": "No valid current security score available."
        }

    if prev_score is None and curr_score is not None:
        return {
            "has_previous": True,
            "score_diff": None,
            "score_direction": "inconclusive",
            "prev_score": None,
            "prev_grade": "N/A",
            "curr_score": curr_score,
            "curr_grade": curr_grade,
            "prev_time": previous.get("scan_time", "Previous"),
            "curr_time": current.get("scan_time", "Current") if current else "Current",
            "changes": [{
                "category": "posture",
                "type": "neutral",
                "icon": "[i]",
                "text": "No previous valid security posture available."
            }],
            "summary_text": "No previous valid security posture available."
        }

    if curr_score is None and prev_score is None:
        return {
            "has_previous": True,
            "score_diff": None,
            "score_direction": "inconclusive",
            "prev_score": None,
            "prev_grade": "N/A",
            "curr_score": None,
            "curr_grade": "N/A",
            "prev_time": previous.get("scan_time", "Previous"),
            "curr_time": current.get("scan_time", "Current") if current else "Current",
            "changes": [{
                "category": "posture",
                "type": "neutral",
                "icon": "[i]",
                "text": "No valid security-score comparison available."
            }],
            "summary_text": "No valid security-score comparison available."
        }

    score_diff = curr_score - prev_score

    print(f"[COMPARE] previous_score={prev_score}")
    print(f"[COMPARE] current_score={curr_score}")
    print(f"[COMPARE] score_diff={score_diff}")

    if score_diff > 0:
        score_direction = "up"
        changes.append({
            "category": "posture",
            "type": "positive",
            "icon": "[+]",
            "text": f"Security Posture improved by +{score_diff} points ({prev_score} -> {curr_score})"
        })
    elif score_diff < 0:
        score_direction = "down"
        changes.append({
            "category": "posture",
            "type": "negative",
            "icon": "[-]",
            "text": f"Security Posture deteriorated by {score_diff} points ({prev_score} -> {curr_score})"
        })
    else:
        score_direction = "same"
        changes.append({
            "category": "posture",
            "type": "neutral",
            "icon": "[=]",
            "text": f"Security Posture score unchanged ({curr_score}/100)"
        })

    # =====================================
    # 1. Compare Protocols
    # =====================================
    curr_proto = str(current.get("protocol", "")).lower()
    prev_proto = str(previous.get("protocol", "")).lower()
    if curr_proto == "https" and prev_proto == "http":
        changes.append({
            "category": "protocol",
            "type": "positive",
            "icon": "[OK]",
            "text": "HTTPS protocol upgraded (HTTP -> HTTPS)"
        })
    elif curr_proto == "http" and prev_proto == "https":
        changes.append({
            "category": "protocol",
            "type": "negative",
            "icon": "[X]",
            "text": "HTTPS protocol downgraded to plain HTTP"
        })

    # =====================================
    # 2. Compare Open Ports
    # =====================================
    curr_ports = set(current.get("open_ports") or [])
    prev_ports = set(previous.get("open_ports") or [])

    new_ports = curr_ports - prev_ports
    closed_ports = prev_ports - curr_ports

    print(f"[COMPARE] Previous ports: {sorted(list(prev_ports))}")
    print(f"[COMPARE] Current ports: {sorted(list(curr_ports))}")
    print(f"[COMPARE] New ports: {sorted(list(new_ports))}")
    print(f"[COMPARE] Closed ports: {sorted(list(closed_ports))}")

    for p in sorted(list(new_ports)):
        changes.append({
            "category": "port",
            "type": "negative",
            "icon": "[!]",
            "text": f"New port detected open: Port {p}"
        })
    for p in sorted(list(closed_ports)):
        changes.append({
            "category": "port",
            "type": "positive",
            "icon": "[OK]",
            "text": f"Port closed/secured: Port {p}"
        })

    # =====================================
    # 3. Compare Security Headers
    # =====================================
    STANDARD_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    curr_headers = current.get("headers") or {}
    prev_headers = previous.get("headers") or {}
    prev_headers_avail = previous.get("headers_available", True)

    print(f"[COMPARE] Previous headers: {prev_headers}")
    print(f"[COMPARE] Current headers: {curr_headers}")

    if not prev_headers_avail or previous.get("headers") is None:
        changes.append({
            "category": "header",
            "type": "neutral",
            "icon": "[i]",
            "text": "Previous security-header data unavailable."
        })
    else:
        for header in STANDARD_HEADERS:
            curr_present = bool(curr_headers.get(header, False))
            prev_present = bool(prev_headers.get(header, False))

            if not prev_present and curr_present:
                changes.append({
                    "category": "header",
                    "type": "positive",
                    "icon": "[OK]",
                    "text": f"Security header enabled: {header}"
                })
            elif prev_present and not curr_present:
                changes.append({
                    "category": "header",
                    "type": "negative",
                    "icon": "[X]",
                    "text": f"Security header removed: {header}"
                })

    # =====================================
    # 4. Compare SSL / TLS Configuration
    # =====================================
    curr_tls = str(current.get("tls_version") or "").strip()
    prev_tls = str(previous.get("tls_version") or "").strip()
    print(f"[COMPARE] Previous TLS: {prev_tls or 'None'}")
    print(f"[COMPARE] Current TLS: {curr_tls or 'None'}")

    if prev_tls and curr_tls:
        if ("1.3" in curr_tls and "1.3" not in prev_tls) or ("1.2" in curr_tls and ("1.0" in prev_tls or "1.1" in prev_tls)):
            changes.append({
                "category": "tls",
                "type": "positive",
                "icon": "[OK]",
                "text": f"TLS configuration improved ({prev_tls} -> {curr_tls})"
            })
        elif ("1.0" in curr_tls or "1.1" in curr_tls or "1.2" in curr_tls) and ("1.3" in prev_tls or ("1.2" in curr_tls and "1.3" in prev_tls)):
            changes.append({
                "category": "tls",
                "type": "negative",
                "icon": "[!]",
                "text": f"Warning: TLS configuration downgraded ({prev_tls} -> {curr_tls})"
            })

    curr_ssl = current.get("ssl_data") or {}
    prev_ssl = previous.get("ssl_data") or {}

    if prev_ssl and curr_ssl:
        if not prev_ssl.get("expired") and curr_ssl.get("expired"):
            changes.append({
                "category": "ssl",
                "type": "negative",
                "icon": "[X]",
                "text": "Critical: SSL certificate expired."
            })
        if not prev_ssl.get("self_signed") and curr_ssl.get("self_signed"):
            changes.append({
                "category": "ssl",
                "type": "negative",
                "icon": "[!]",
                "text": "Warning: Self-signed SSL certificate detected."
            })

    # =====================================
    # 5. Compare WAF Status
    # =====================================
    curr_waf = current.get("waf", {}) if isinstance(current.get("waf"), dict) else {}
    prev_waf = previous.get("waf", {}) if isinstance(previous.get("waf"), dict) else {}
    prev_waf_avail = previous.get("waf_available", True)

    if not prev_waf_avail or previous.get("waf") is None:
        changes.append({
            "category": "waf",
            "type": "neutral",
            "icon": "[i]",
            "text": "Historical WAF data unavailable."
        })
    else:
        curr_detected = curr_waf.get("detected", False)
        prev_detected = prev_waf.get("detected", False)
        if curr_detected and not prev_detected:
            changes.append({
                "category": "waf",
                "type": "positive",
                "icon": "[OK]",
                "text": f"Web Application Firewall (WAF) enabled ({curr_waf.get('provider', 'Active WAF')})"
            })
        elif not curr_detected and prev_detected:
            changes.append({
                "category": "waf",
                "type": "negative",
                "icon": "[X]",
                "text": "Web Application Firewall (WAF) no longer detected"
            })

    # =====================================
    # 6. Compare Technologies
    # =====================================
    curr_tech = set(current.get("technologies") or [])
    prev_tech = set(previous.get("technologies") or [])
    prev_tech_avail = previous.get("technologies_available", True)

    if not prev_tech_avail or previous.get("technologies") is None:
        changes.append({
            "category": "tech",
            "type": "neutral",
            "icon": "[i]",
            "text": "Historical technology data unavailable."
        })
    else:
        new_tech = curr_tech - prev_tech
        removed_tech = prev_tech - curr_tech

        for t in sorted(list(new_tech)):
            changes.append({
                "category": "tech",
                "type": "positive",
                "icon": "[OK]",
                "text": f"New technology detected: {t}"
            })
        for t in sorted(list(removed_tech)):
            changes.append({
                "category": "tech",
                "type": "neutral",
                "icon": "[i]",
                "text": f"Technology removed: {t}"
            })

    # =====================================
    # 7. Compare CVE Vulnerabilities
    # =====================================
    curr_cves = set(current.get("cves") or [])
    prev_cves = set(previous.get("cves") or [])

    new_cves = curr_cves - prev_cves
    fixed_cves = prev_cves - curr_cves

    for cve in sorted(list(new_cves)):
        changes.append({
            "category": "cve",
            "type": "negative",
            "icon": "[X]",
            "text": f"New CVE vulnerability: {cve}"
        })
    for cve in sorted(list(fixed_cves)):
        changes.append({
            "category": "cve",
            "type": "positive",
            "icon": "[OK]",
            "text": f"CVE vulnerability resolved: {cve}"
        })

    return {
        "has_previous": True,
        "score_diff": score_diff,
        "score_direction": score_direction,
        "prev_score": prev_score,
        "curr_score": curr_score,
        "prev_time": previous.get("scan_time", "Previous"),
        "curr_time": current.get("scan_time", "Current"),
        "changes": changes,
    }


# ==========================================================
# Direct Delta Comparison Engine (Returning Required Dict)
# ==========================================================
def compare_scans(latest_scan: dict, previous_scan: dict = None) -> dict:
    from scanner.scan_comparison_engine import compare_scans as _comp
    return _comp(latest_scan, previous_scan)


def compare_latest_scans(target: str = None) -> dict:
    from scanner.scan_comparison_engine import compare_latest_scans as _comp_latest
    return _comp_latest(target)

