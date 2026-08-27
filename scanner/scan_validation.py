"""
scanner/scan_validation.py

CyberShieldAI Target Scan Validation Helper.
Verifies whether a target was successfully resolved and sufficient security evidence
was collected to perform a trustworthy AI Security Posture evaluation.
"""


def validate_url_scan(
    result,
    ports=None,
    ssl_info=None,
    url_info=None,
    technology=None,
    vulnerabilities=None,
    ports_scanned=False,
    ssl_scanned=False,
    dns_scanned=False,
    technology_scanned=False,
    vulnerability_scanned=False
):
    """
    Validates a URL scan result against minimum target resolution & evidence criteria.

    Returns:
    {
        "valid": bool,
        "status": "ASSESSED" or "INCONCLUSIVE",
        "reasons": list of str,
        "evidence": dict of bool
    }
    """
    reasons = []

    # 1. Target Identification Checks
    ip = result.get("ip") if result and isinstance(result, dict) else None
    has_resolved_ip = bool(ip and str(ip).strip() not in ("Unknown", "unknown", "N/A", ""))

    protocol = str(result.get("protocol", "") if result and isinstance(result, dict) else "").lower().strip()
    protocol_verified = protocol in ("http", "https")

    remarks = result.get("remarks", []) if result and isinstance(result, dict) else []
    if isinstance(remarks, str):
        remarks = [r.strip() for r in remarks.split("|") if r.strip()]

    domain_failed = any("Domain could not be resolved" in str(r) for r in remarks)

    if not has_resolved_ip:
        reasons.append("Target IP address could not be resolved")
    if not protocol_verified:
        reasons.append("Protocol could not be verified (HTTP/HTTPS connection failed)")
    if domain_failed:
        reasons.append("Domain could not be resolved to an active network endpoint")

    # 2. Evidence Collection Status (Explicit Flags)
    has_port_evidence = bool(ports_scanned or (ports is not None and len(ports) > 0))
    has_ssl_evidence = bool(ssl_scanned or (ssl_info and isinstance(ssl_info, dict) and (ssl_info.get("has_ssl") or ssl_info.get("valid_days") is not None or ssl_info.get("tls_version"))))
    
    has_dns_evidence = False
    if dns_scanned:
        has_dns_evidence = True
    elif url_info and isinstance(url_info, dict):
        dns_dict = url_info.get("dns", {})
        if isinstance(dns_dict, dict) and any(len(v) > 0 for v in dns_dict.values() if isinstance(v, list)):
            has_dns_evidence = True

    has_tech_evidence = bool(technology_scanned or (technology is not None and len(technology) > 0 if isinstance(technology, (dict, list)) else False))
    has_vuln_evidence = bool(vulnerability_scanned or (vulnerabilities is not None and len(vulnerabilities) > 0))

    scan_evidence = {
        "resolved_ip": has_resolved_ip,
        "protocol_verified": protocol_verified,
        "ports_scanned": has_port_evidence,
        "ssl_scanned": has_ssl_evidence,
        "dns_scanned": has_dns_evidence,
        "technology_scanned": has_tech_evidence,
        "vulnerability_scanned": has_vuln_evidence
    }

    # 3. Decision Logic
    any_scan_evidence = (
        has_port_evidence or
        has_ssl_evidence or
        has_dns_evidence or
        has_tech_evidence or
        has_vuln_evidence or
        (url_info and isinstance(url_info, dict) and bool(url_info.get("whois")))
    )

    is_valid = True
    if not has_resolved_ip and not protocol_verified:
        is_valid = False
    elif not has_resolved_ip and not any_scan_evidence:
        is_valid = False
    elif domain_failed and not protocol_verified:
        is_valid = False

    if not is_valid:
        if "No network scan evidence" not in reasons and not has_port_evidence and not has_vuln_evidence:
            reasons.append("No network scan evidence collected")
        if "SSL/TLS not assessed" not in reasons and not has_ssl_evidence:
            reasons.append("SSL/TLS not assessed")
        if "HTTP security headers not assessed" not in reasons and (not url_info or not isinstance(url_info, dict) or not url_info.get("security_headers")):
            reasons.append("HTTP security headers not assessed")

    # Remove duplicates while preserving order
    dedup_reasons = []
    for r in reasons:
        if r not in dedup_reasons:
            dedup_reasons.append(r)

    status = "ASSESSED" if is_valid else "INCONCLUSIVE"

    return {
        "valid": is_valid,
        "status": status,
        "reasons": dedup_reasons,
        "evidence": scan_evidence
    }
