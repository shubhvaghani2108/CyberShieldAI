def generate_summary(
    score,
    critical=0,
    high=0,
    medium=0,
    low=0,
    deductions=None,
    positives=None,
    header_stats=None,
    waf_info=None,
    ssl_info=None
):
    if score >= 90:
        status = "Excellent Security Posture"
    elif score >= 75:
        status = "Good / Low Risk"
    elif score >= 55:
        status = "Fair / Moderate Risk"
    elif score >= 35:
        status = "Needs Improvement"
    else:
        status = "Critical Exposure"

    pos_items = [p.replace("✔ ", "") for p in (positives or [])]

    sec_features = []
    seen = set()
    for item in pos_items:
        feat = None
        if "TLS 1.3" in item and "TLS 1.3" not in seen:
            feat = "modern TLS 1.3 encryption"
            seen.add("TLS 1.3")
        elif "HSTS" in item and "HSTS" not in seen:
            feat = "HSTS enforcement"
            seen.add("HSTS")
        elif "HTTPS" in item and "HTTPS" not in seen:
            feat = "HTTPS transport security"
            seen.add("HTTPS")
        elif "SSL" in item and "SSL" not in seen:
            feat = "verified SSL trust"
            seen.add("SSL")
        if feat and feat not in sec_features:
            sec_features.append(feat)

    if sec_features:
        feat_str = f"The target demonstrates {', '.join(sec_features)}. "
    else:
        feat_str = "The target has standard web services active. "

    if critical == 0 and high == 0:
        vuln_str = "No critical network vulnerabilities were detected."
    else:
        vuln_str = f"Found {critical} Critical and {high} High vulnerability exposures requiring port restriction."

    if header_stats and isinstance(header_stats, dict):
        pres = header_stats.get("present", 0)
        tot = header_stats.get("scanned", 6)
        hdr_str = f"{pres} of {tot} recommended browser defense headers are configured."
    else:
        hdr_str = ""

    if waf_info and isinstance(waf_info, dict) and waf_info.get("detected"):
        prov = waf_info.get("provider", "Active WAF")
        waf_str = f"An active perimeter firewall ({prov}) was verified."
    else:
        waf_str = "No active perimeter Web Application Firewall (WAF) was detected."

    recs_clean = []
    if deductions:
        for d in deductions:
            d_clean = d.replace("Missing ", "").replace(" Header", "")
            if d_clean not in recs_clean and not d_clean.startswith("HTTP Port"):
                recs_clean.append(d_clean)

    if score >= 90:
        conclusion = "Overall security posture is excellent."
    elif score >= 75:
        rec_part = f" Enhancing {', '.join(recs_clean[:2])} will achieve top-tier hardening." if recs_clean else ""
        conclusion = f"Overall security posture is good.{rec_part}"
    else:
        conclusion = f"Hardening is recommended for: {', '.join(recs_clean[:3]) if recs_clean else 'identified risk factors'}."

    full_summary = f"{feat_str}{vuln_str} {hdr_str} {waf_str} {conclusion}".strip()

    return {
        "status": status,
        "summary": full_summary
    }