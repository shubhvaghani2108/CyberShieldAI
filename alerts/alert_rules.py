# ======================================================
# CyberShieldAI Alert Rules Engine
# ======================================================


def check_risk_score(risk_summary):
    alerts = []
    if not risk_summary:
        return alerts

    score = risk_summary.get("total_score") if isinstance(risk_summary, dict) else risk_summary

    try:
        score_val = int(score)
    except (ValueError, TypeError):
        return alerts

    if score_val >= 90:
        alerts.append({
            "alert_type": "Critical Risk Score",
            "title": "Critical Risk Score",
            "severity": "Critical",
            "message": f"Total risk score is critical ({score_val}/100).",
            "description": f"Risk Score is {score_val}.",
            "recommendation": "Immediate remediation required.",
        })
    elif score_val >= 70:
        alerts.append({
            "alert_type": "High Risk Score",
            "title": "High Risk Score",
            "severity": "High",
            "message": f"Total risk score is high ({score_val}/100).",
            "description": f"Risk Score is {score_val}.",
            "recommendation": "Review vulnerabilities immediately.",
        })
    elif score_val >= 40:
        alerts.append({
            "alert_type": "Medium Risk Score",
            "title": "Medium Risk Score",
            "severity": "Medium",
            "message": f"Total risk score is elevated ({score_val}/100).",
            "description": f"Risk Score is {score_val}.",
            "recommendation": "Review open ports and services.",
        })

    return alerts


# ------------------------------------------------------
# 1. Security Score Drops Alert Rule
# ------------------------------------------------------
def check_score_drop(current_score, previous_score, target=None):
    """
    Triggers an alert when the security score drops compared to previous scan.
    """
    alerts = []
    if current_score is None or previous_score is None:
        return alerts

    try:
        curr = int(current_score)
        prev = int(previous_score)
    except (ValueError, TypeError):
        return alerts

    drop = prev - curr
    if drop > 0:
        severity = "Critical" if drop >= 20 else ("High" if drop >= 10 else "Medium")
        alerts.append({
            "target": target,
            "alert_type": "Security Score Drop",
            "title": "Security Score Dropped",
            "severity": severity,
            "message": f"Security score decreased by {drop} point(s) from {prev} down to {curr}.",
            "description": f"Security score decreased by {drop} point(s) from {prev} down to {curr}.",
            "recommendation": "Investigate recent posture degradation, newly opened ports, and vulnerabilities.",
        })

    return alerts


# ------------------------------------------------------
# 2. New Open Port Found Alert Rule
# ------------------------------------------------------
def check_new_ports(new_ports, target=None):
    """
    Triggers an alert for newly opened ports discovered on the target.
    """
    alerts = []
    if not new_ports:
        return alerts

    dangerous_ports = {
        21: "FTP (Plaintext credentials)",
        23: "Telnet (Insecure legacy protocol)",
        445: "SMB (High-risk exposure)",
        3389: "RDP (Remote Desktop exposure)",
        22: "SSH (Remote Administration)",
        1433: "MSSQL Database",
        3306: "MySQL Database",
        5432: "PostgreSQL Database",
        27017: "MongoDB Database",
        6379: "Redis (In-memory database)",
    }

    for p in new_ports:
        try:
            port_num = int(p)
        except (ValueError, TypeError):
            continue

        if port_num in dangerous_ports:
            severity = "High"
            desc = f"Dangerous port {port_num} ({dangerous_ports[port_num]}) newly opened on target."
        else:
            severity = "Medium"
            desc = f"New network port {port_num} discovered open on target."

        alerts.append({
            "target": target,
            "alert_type": "New Open Port",
            "title": "New Port Opened",
            "severity": severity,
            "message": desc,
            "description": desc,
            "recommendation": f"Verify authorization for port {port_num} and restrict firewall access rules.",
        })

    return alerts


# ------------------------------------------------------
# 3. New Vulnerability Found Alert Rule
# ------------------------------------------------------
def check_new_vulnerabilities(new_vulnerabilities, target=None):
    """
    Triggers an alert for each new vulnerability or CVE identified.
    """
    alerts = []
    if not new_vulnerabilities:
        return alerts

    for vuln in new_vulnerabilities:
        vuln_name = str(vuln).strip()
        if not vuln_name:
            continue

        lower_v = vuln_name.lower()
        if any(kw in lower_v for kw in ["critical", "rce", "remote code", "sql injection", "injection", "auth bypass"]):
            severity = "Critical"
        elif any(kw in lower_v for kw in ["high", "cve-", "exploit"]):
            severity = "High"
        else:
            severity = "High"

        alerts.append({
            "target": target,
            "alert_type": "New Vulnerability",
            "title": "New Vulnerability Found",
            "severity": severity,
            "message": f"New vulnerability detected: {vuln_name[:140]}",
            "description": f"New vulnerability detected: {vuln_name[:140]}",
            "recommendation": "Apply vendor security patches or isolate the vulnerable service.",
        })

    return alerts


# ------------------------------------------------------
# 4. SSL Certificate Near Expiry (<30 days) Alert Rule
# ------------------------------------------------------
def check_ssl_expiry(ssl_data, target=None):
    """
    Triggers an alert when an SSL/TLS certificate is expired or expiring within 30 days.
    """
    alerts = []
    if not ssl_data or not isinstance(ssl_data, dict):
        return alerts

    # Expired check
    if ssl_data.get("expired"):
        alerts.append({
            "target": target,
            "alert_type": "SSL Certificate Expiry",
            "title": "SSL Certificate Expired",
            "severity": "Critical",
            "message": "The SSL/TLS certificate for this target has expired.",
            "description": "The SSL/TLS certificate for this target has expired.",
            "recommendation": "Renew and re-deploy the SSL certificate immediately.",
        })
        return alerts

    days = ssl_data.get("days_remaining")
    if days is not None:
        try:
            days_int = int(days)
            if days_int <= 0:
                alerts.append({
                    "target": target,
                    "alert_type": "SSL Certificate Expiry",
                    "title": "SSL Certificate Expired",
                    "severity": "Critical",
                    "message": "The SSL/TLS certificate has 0 days remaining (expired).",
                    "description": "The SSL/TLS certificate has 0 days remaining (expired).",
                    "recommendation": "Renew and replace the SSL certificate immediately.",
                })
            elif days_int <= 7:
                alerts.append({
                    "target": target,
                    "alert_type": "SSL Certificate Expiry",
                    "title": "SSL Certificate Near Expiry",
                    "severity": "Critical",
                    "message": f"Critical: SSL certificate expires in {days_int} day(s) (under 7 days).",
                    "description": f"Critical: SSL certificate expires in {days_int} day(s) (under 7 days).",
                    "recommendation": "Urgent SSL renewal required within 7 days.",
                })
            elif days_int <= 30:
                alerts.append({
                    "target": target,
                    "alert_type": "SSL Certificate Expiry",
                    "title": "SSL Certificate Near Expiry",
                    "severity": "High",
                    "message": f"SSL certificate expires in {days_int} day(s) (within 30-day window).",
                    "description": f"SSL certificate expires in {days_int} day(s) (within 30-day window).",
                    "recommendation": "Schedule SSL certificate renewal before expiration.",
                })
        except (ValueError, TypeError):
            pass

    return alerts


# ------------------------------------------------------
# 5. Security Header Coverage Decreases Alert Rule
# ------------------------------------------------------
def check_header_coverage(current_headers, previous_headers, target=None):
    """
    Triggers an alert when security header coverage decreases between scans.
    """
    alerts = []
    if not current_headers or not previous_headers:
        return alerts

    curr_set = set()
    prev_set = set()

    if isinstance(current_headers, dict):
        curr_set = {k for k, v in current_headers.items() if v}
    elif isinstance(current_headers, list):
        for h in current_headers:
            if isinstance(h, dict) and str(h.get("status", "")).lower() in ["present", "true", "1"]:
                curr_set.add(h.get("header_name"))
            elif isinstance(h, str):
                curr_set.add(h)

    if isinstance(previous_headers, dict):
        prev_set = {k for k, v in previous_headers.items() if v}
    elif isinstance(previous_headers, list):
        for h in previous_headers:
            if isinstance(h, dict) and str(h.get("status", "")).lower() in ["present", "true", "1"]:
                prev_set.add(h.get("header_name"))
            elif isinstance(h, str):
                prev_set.add(h)

    dropped = prev_set - curr_set
    if dropped:
        alerts.append({
            "target": target,
            "alert_type": "Security Header Coverage Decrease",
            "title": "Security Header Coverage Decreases",
            "severity": "Medium",
            "message": f"Security header coverage decreased; missing or removed headers: {', '.join(sorted(list(dropped)))}.",
            "description": f"Previously active security headers were removed: {', '.join(sorted(list(dropped)))}.",
            "recommendation": "Re-enable missing HTTP security response headers.",
        })
    elif len(curr_set) < len(prev_set):
        alerts.append({
            "target": target,
            "alert_type": "Security Header Coverage Decrease",
            "title": "Security Header Coverage Decreases",
            "severity": "Medium",
            "message": f"Security header count decreased from {len(prev_set)} to {len(curr_set)} headers.",
            "description": f"Security header count decreased from {len(prev_set)} to {len(curr_set)}.",
            "recommendation": "Audit server response headers and restore security protections.",
        })

    return alerts


# ------------------------------------------------------
# Legacy Static Rules (Maintained for Backward Compatibility)
# ------------------------------------------------------
def check_ssl(ssl):
    alerts = []
    if not ssl:
        return alerts

    tls = ssl.get("tls_version") if isinstance(ssl, dict) else None
    if tls in ["TLSv1", "TLSv1.0", "TLSv1.1"]:
        alerts.append({
            "alert_type": "Weak TLS Version",
            "title": "Weak TLS Version",
            "severity": "High",
            "message": f"Insecure TLS version detected: {tls}",
            "description": str(tls),
            "recommendation": "Upgrade to TLS 1.3",
        })

    alerts.extend(check_ssl_expiry(ssl))
    return alerts


def check_ports(ports):
    alerts = []
    if not ports:
        return alerts

    dangerous = {
        21: "FTP (Plaintext data transmission)",
        23: "Telnet (Unencrypted remote terminal)",
        135: "Microsoft RPC (Endpoint Mapper)",
        139: "NetBIOS (Host enumeration)",
        445: "SMB (High-risk exposure & EternalBlue vector)",
        1433: "MSSQL (Database port exposed)",
        1521: "Oracle DB (Listener exposed)",
        3306: "MySQL (Database exposed to network)",
        3389: "RDP (Remote Desktop exposed)",
        5432: "PostgreSQL (Database exposed)",
        5900: "VNC (Remote GUI exposed)",
        6379: "Redis (In-memory database exposed)",
        9200: "Elasticsearch (REST API exposed)",
        27017: "MongoDB (NoSQL database exposed)",
    }

    for p in ports:
        port = p.get("port") if isinstance(p, dict) else (p["port"] if hasattr(p, "__getitem__") and not isinstance(p, str) else p)
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            continue

        if port_num in dangerous:
            sev = "Critical" if port_num in [445, 3389, 23, 6379, 27017] else "High"
            alerts.append({
                "alert_type": f"Dangerous Port {port_num}",
                "title": f"Dangerous Port {port_num} Open",
                "severity": sev,
                "message": f"Exposed high-risk service on port {port_num} ({dangerous[port_num]}).",
                "description": dangerous[port_num],
                "recommendation": f"Restrict port {port_num} behind a firewall/VPN or disable if unnecessary.",
            })

    return alerts


def check_vulnerabilities(vulnerabilities):
    alerts = []
    if not vulnerabilities:
        return alerts

    for v in vulnerabilities:
        risk = v.get("risk") if isinstance(v, dict) else (v["risk"] if hasattr(v, "__getitem__") else "")
        port = v.get("port") if isinstance(v, dict) else (v["port"] if hasattr(v, "__getitem__") else "")
        service = v.get("service") if isinstance(v, dict) else (v["service"] if hasattr(v, "__getitem__") else "")
        desc = v.get("description") if isinstance(v, dict) else (v["description"] if hasattr(v, "__getitem__") else "")
        rem = v.get("remediation") if isinstance(v, dict) else (v["remediation"] if hasattr(v, "__getitem__") else "")

        risk_str = str(risk).capitalize()
        if risk_str in ["Critical", "High"]:
            alerts.append({
                "alert_type": f"{risk_str} Vulnerability",
                "title": f"{risk_str} Vulnerability on Port {port}",
                "severity": risk_str,
                "message": desc or f"{risk_str} vulnerability identified on port {port} ({service}).",
                "description": desc or f"{service} on port {port}",
                "recommendation": rem or "Apply security patches or restrict network exposure.",
            })

    return alerts


def check_cves(cves):
    alerts = []
    if not cves:
        return alerts

    for c in cves:
        sev = c.get("severity") if isinstance(c, dict) else (c["severity"] if hasattr(c, "__getitem__") else "")
        cve_id = c.get("cve_id") if isinstance(c, dict) else (c["cve_id"] if hasattr(c, "__getitem__") else "")
        port = c.get("port") if isinstance(c, dict) else (c["port"] if hasattr(c, "__getitem__") else "")
        desc = c.get("description") if isinstance(c, dict) else (c["description"] if hasattr(c, "__getitem__") else "")

        sev_str = str(sev).capitalize()
        if sev_str in ["Critical", "High"]:
            alerts.append({
                "alert_type": f"Known CVE: {cve_id}",
                "title": f"{cve_id} Detected",
                "severity": sev_str,
                "message": desc or f"Vulnerability {cve_id} detected on port {port}.",
                "description": desc or f"CVE on port {port}",
                "recommendation": f"Update software to resolve {cve_id}.",
            })

    return alerts


def check_headers(headers):
    alerts = []
    if not headers:
        return alerts

    important = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
    ]

    found = []
    for h in headers:
        if isinstance(h, dict):
            found.append(h.get("header_name"))
        elif hasattr(h, "__getitem__") and not isinstance(h, str):
            try:
                found.append(h["header_name"])
            except Exception:
                found.append(str(h))
        elif isinstance(h, str):
            found.append(h)

    for h in important:
        if h not in found:
            alerts.append({
                "alert_type": "Missing Security Header",
                "title": f"Missing {h}",
                "severity": "Medium",
                "message": f"Essential HTTP security response header missing: {h}.",
                "description": h,
                "recommendation": f"Configure {h} in web server headers.",
            })

    return alerts


def evaluate_rules(risk=None, ssl=None, ports=None, headers=None, vulnerabilities=None, cves=None):
    alerts = []
    if risk:
        alerts.extend(check_risk_score(risk))
    if ssl:
        alerts.extend(check_ssl(ssl))
    if ports:
        alerts.extend(check_ports(ports))
    if headers:
        alerts.extend(check_headers(headers))
    if vulnerabilities:
        alerts.extend(check_vulnerabilities(vulnerabilities))
    if cves:
        alerts.extend(check_cves(cves))
    return alerts