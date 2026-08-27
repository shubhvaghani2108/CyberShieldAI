import json
from ai.ai_summary import generate_summary
from ai.ai_recommendations import generate_ai_recommendations
from ai.ai_score import security_grade
from scanner.scan_validation import validate_url_scan


def _analyze_headers(technology, url_info):
    """
    Evaluates exact presence/absence of security headers.
    Returns (header_analysis_list, header_penalty, header_recommendations, header_stats_dict)
    """
    headers_to_check = [
        ("Strict-Transport-Security", "HSTS", "HSTS (Strict-Transport-Security)", 5),
        ("Content-Security-Policy", "CSP", "Content-Security-Policy (CSP)", 3),
        ("X-Frame-Options", "X-Frame-Options", "X-Frame-Options (Clickjacking)", 0),
        ("X-Content-Type-Options", "X-Content-Type-Options", "X-Content-Type-Options (MIME)", 0),
        ("Referrer-Policy", "Referrer-Policy", "Referrer-Policy", 0),
        ("Permissions-Policy", "Permissions-Policy", "Permissions-Policy", 0),
    ]

    header_analysis = []
    total_penalty = 0
    recs = []
    present_cnt = 0
    scanned_cnt = 0

    sec_headers = None
    if url_info and isinstance(url_info, dict):
        sec_headers = url_info.get("security_headers")

    tech_str = json.dumps(technology).lower() if technology else ""

    for h_name, short_key, display_name, penalty in headers_to_check:
        status = None

        if sec_headers and isinstance(sec_headers, dict) and sec_headers.get("scanned") is True:
            status = sec_headers.get(h_name, False)
        elif technology is not None:
            if short_key.lower() == "hsts" and ("hsts" in tech_str or "strict-transport-security" in tech_str):
                status = True
            elif short_key.lower() == "csp" and ("content security policy" in tech_str or "csp" in tech_str):
                status = True
            elif short_key.lower() == "x-frame-options" and ("clickjacking" in tech_str or "x-frame-options" in tech_str):
                status = True
            elif short_key.lower() == "x-content-type-options" and ("mime" in tech_str or "x-content-type-options" in tech_str):
                status = True
            else:
                status = None

        if status is not None:
            scanned_cnt += 1
            if status is True:
                present_cnt += 1

        header_analysis.append({
            "name": display_name,
            "key": short_key,
            "status": status
        })

        if status is False and penalty > 0:
            total_penalty += penalty
            recs.append({
                "risk": "Medium",
                "reason": f"Missing {display_name} header.",
                "recommendation": f"Configure the {h_name} HTTP response header to protect against web vulnerabilities."
            })

    scanned_total = scanned_cnt if scanned_cnt > 0 else 6
    missing_cnt = scanned_total - present_cnt

    header_stats = {
        "present": present_cnt,
        "missing": max(0, missing_cnt),
        "scanned": scanned_total,
        "total": len(headers_to_check),
        "percentage": int((present_cnt / scanned_total) * 100) if scanned_cnt > 0 else 0
    }

    return header_analysis, total_penalty, recs, header_stats


def _ssl_is_valid(ssl_info):
    """
    Determines whether the scanned SSL/TLS certificate is currently valid and trusted.

    The scanner's ssl_results table (see database/ssl_results.py) stores the
    certificate state using has_ssl / expired / self_signed / days_remaining
    columns — it never sets a "status" or "valid_days" key. The score used to
    check ssl_info.get("status") and ssl_info.get("valid_days"), which are
    never present, so a genuinely valid certificate silently failed to earn
    its "Valid Trusted SSL Certificate" bonus. This checks every field the
    scanner (or a caller/test) might realistically supply.
    """
    if not ssl_info or not isinstance(ssl_info, dict):
        return False

    # Explicit textual status, if a caller supplies one (e.g. "Valid", "Active").
    ssl_status = str(ssl_info.get("status", "")).lower()
    if "valid" in ssl_status or "active" in ssl_status:
        return True

    # Explicit failure flags take priority over everything else.
    if ssl_info.get("expired") in (1, True):
        return False
    if ssl_info.get("self_signed") in (1, True):
        return False

    # Remaining validity window, however the caller named the field.
    days_remaining = ssl_info.get("days_remaining", ssl_info.get("valid_days", 0)) or 0
    try:
        days_remaining = int(days_remaining)
    except (TypeError, ValueError):
        days_remaining = 0
    if days_remaining > 0:
        return True

    # No expiry info supplied, but the scanner confirmed SSL is present and
    # didn't flag it as expired/self-signed — treat as valid.
    if ssl_info.get("has_ssl") in (1, True) and not ssl_info.get("expired") and not ssl_info.get("self_signed"):
        return True

    return False


def _check_enterprise_infrastructure(technology, url_info, result):
    """
    Detects Enterprise CDNs and Edge Providers.
    Returns (cdn_matches, bonus_points)
    """
    cdn_matches = []

    all_text = ""
    if technology:
        all_text += " " + json.dumps(technology).lower()
    if url_info and isinstance(url_info, dict):
        all_text += " " + json.dumps(url_info).lower()
    if result and isinstance(result, dict):
        all_text += " " + str(result.get("server", "")).lower()

    ENTERPRISE_PROVIDERS = [
        ("akamai", "Akamai CDN & Edge Network"),
        ("cloudflare", "Cloudflare Global CDN & DDoS Protection"),
        ("cloudfront", "Amazon CloudFront CDN"),
        ("azure front door", "Azure Front Door WAF & Edge"),
        ("fastly", "Fastly Edge Cloud"),
        ("incapsula", "Imperva Incapsula WAF/CDN"),
        ("imperva", "Imperva Security CDN"),
    ]

    bonus = 0
    for key, name in ENTERPRISE_PROVIDERS:
        if key in all_text:
            if name not in cdn_matches:
                cdn_matches.append(name)
                bonus = 3

    return cdn_matches, bonus


def run_ai_engine(
    risk=None,
    ports=None,
    vulnerabilities=None,
    ssl_info=None,
    url_info=None,
    technology=None,
    result=None,
    ports_scanned=False,
    ssl_scanned=False,
    dns_scanned=False,
    technology_scanned=False,
    vulnerability_scanned=False
):
    """
    Enterprise AI Security Engine.
    First validates if scan evidence is sufficient.
    If INCONCLUSIVE, blocks 0-100 score posture calculation.
    """
    validation = validate_url_scan(
        result=result,
        ports=ports,
        ssl_info=ssl_info,
        url_info=url_info,
        technology=technology,
        vulnerabilities=vulnerabilities,
        ports_scanned=ports_scanned,
        ssl_scanned=ssl_scanned,
        dns_scanned=dns_scanned,
        technology_scanned=technology_scanned,
        vulnerability_scanned=vulnerability_scanned
    )

    if not validation["valid"]:
        headers_to_check = [
            ("Strict-Transport-Security", "HSTS", "HSTS (Strict-Transport-Security)"),
            ("Content-Security-Policy", "CSP", "Content-Security-Policy (CSP)"),
            ("X-Frame-Options", "X-Frame-Options", "X-Frame-Options (Clickjacking)"),
            ("X-Content-Type-Options", "X-Content-Type-Options", "X-Content-Type-Options (MIME)"),
            ("Referrer-Policy", "Referrer-Policy", "Referrer-Policy"),
            ("Permissions-Policy", "Permissions-Policy", "Permissions-Policy"),
        ]
        header_analysis = [
            {"name": display_name, "key": short_key, "status": None}
            for _, short_key, display_name in headers_to_check
        ]
        header_stats = {
            "present": 0,
            "missing": 0,
            "scanned": 0,
            "total": 6,
            "percentage": 0,
            "status_text": "Not Assessed"
        }
        inconclusive_summary_text = (
            "Security posture could not be reliably determined because the target could not be resolved or "
            "insufficient security evidence was collected. No conclusion about the target's security should be drawn from this scan."
        )
        return {
            "valid": False,
            "score": None,
            "raw_score": None,
            "grade": "N/A",
            "status": "INCONCLUSIVE",
            "posture": "Inconclusive Assessment",
            "summary": {
                "status": "Inconclusive Assessment",
                "summary": inconclusive_summary_text
            },
            "reasons": validation["reasons"],
            "recommendations": [],
            "categorized_recommendations": {
                "Transport Security": [],
                "Security Headers": [],
                "Infrastructure & WAF": [],
                "Network & Service Hardening": []
            },
            "score_breakdown": [],
            "total_bonuses": 0,
            "total_deductions": 0,
            "formula_str": "N/A — Inconclusive scan",
            "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "positives": [],
            "header_analysis": header_analysis,
            "header_stats": header_stats
        }

    base_score = 100
    total_deductions = 0
    total_bonuses = 0
    recommendations = []
    deduction_notes = []
    positives = []

    # ----------------------------------------------------
    # 1. Normalize Ports List
    # ----------------------------------------------------
    port_list = []
    if ports:
        for p in ports:
            if isinstance(p, dict):
                port_list.append(p)
            elif hasattr(p, "keys"):
                port_list.append(dict(p))
            elif isinstance(p, (int, str)):
                try:
                    port_list.append({"port": int(p)})
                except ValueError:
                    pass

    # ----------------------------------------------------
    # 2. Vulnerabilities Audit (-25 Crit, -15 High, -8 Med, -3 Low)
    # ----------------------------------------------------
    vuln_list = []
    if vulnerabilities:
        for v in vulnerabilities:
            if isinstance(v, dict):
                vuln_list.append(v)
            elif hasattr(v, "keys"):
                vuln_list.append(dict(v))

    crit_cnt = 0
    high_cnt = 0
    med_cnt = 0
    low_cnt = 0

    if vuln_list:
        for v in vuln_list:
            v_risk = str(v.get("risk", "")).lower()
            if "critical" in v_risk:
                crit_cnt += 1
            elif "high" in v_risk:
                high_cnt += 1
            elif "medium" in v_risk:
                med_cnt += 1
            elif "low" in v_risk:
                low_cnt += 1
    elif risk and isinstance(risk, dict):
        crit_cnt = risk.get("critical_count", 0) or 0
        high_cnt = risk.get("high_count", 0) or 0
        med_cnt = risk.get("medium_count", 0) or 0
        low_cnt = risk.get("low_count", 0) or 0

    total_deductions += (crit_cnt * 25 + high_cnt * 15 + med_cnt * 8 + low_cnt * 3)

    has_vuln_scanned = vulnerability_scanned or (vulnerabilities is not None and len(vulnerabilities) > 0)
    if has_vuln_scanned:
        if crit_cnt == 0:
            positives.append("✔ No Critical Vulnerabilities")

        if crit_cnt == 0 and high_cnt == 0 and med_cnt == 0 and low_cnt == 0:
            positives.append("✔ No Known CVEs / Vulnerabilities")

    if crit_cnt > 0 or high_cnt > 0:
        deduction_notes.append(f"{crit_cnt + high_cnt} Severe Vulnerabilities")

    # ----------------------------------------------------
    # 3. Ports & Protocols (HTTP Port 80: -2)
    # ----------------------------------------------------
    port_recs = generate_ai_recommendations(port_list)
    for rec in port_recs:
        if rec not in recommendations:
            recommendations.append(rec)

    has_port_443 = any(p.get("port") in (443, 8443) for p in port_list)
    has_port_80 = any(p.get("port") == 80 for p in port_list)
    if has_port_80 and not has_port_443:
        total_deductions += 2
        deduction_notes.append("HTTP Port 80 Exposed (Without HTTPS)")
    elif has_port_443:
        positives.append("✔ Secure HTTPS (Port 443) Active")


    # ----------------------------------------------------
    # 4. WAF & Enterprise CDN Infrastructure (+3 Bonus, -2 Penalty)
    # ----------------------------------------------------
    cdn_matches, cdn_bonus = _check_enterprise_infrastructure(technology, url_info, result)
    if cdn_matches:
        total_bonuses += cdn_bonus
        for cdn in cdn_matches:
            positives.append(f"✔ Enterprise CDN Detected ({cdn}) — Improves DDoS protection & availability")

    waf_detected = False
    waf_data = {}
    if url_info and isinstance(url_info, dict) and "waf" in url_info:
        waf_data = url_info.get("waf", {})
        if isinstance(waf_data, dict) and waf_data.get("detected"):
            waf_detected = True

    # Cloudflare, Akamai, CloudFront, etc. act as active WAF reverse proxies
    if not waf_detected and cdn_matches:
        waf_detected = True
        waf_data = {"detected": True, "provider": cdn_matches[0]}

    if waf_detected:
        positives.append("✔ Web Application Firewall (WAF) Active")
    elif url_info and isinstance(url_info, dict) and "waf" in url_info:
        total_deductions += 2
        deduction_notes.append("Missing WAF Protection")
        recommendations.append({
            "risk": "Medium",
            "reason": "No active Web Application Firewall (WAF) detected.",
            "recommendation": "Deploy a Web Application Firewall (e.g. Cloudflare, AWS WAF, ModSecurity) to protect against automated web exploits."
        })

    # ----------------------------------------------------
    # 5. Security Header Analysis (Burp/Nessus Standard)
    # ----------------------------------------------------
    header_analysis, header_penalty, header_recs, header_stats = _analyze_headers(technology, url_info)
    total_deductions += header_penalty
    recommendations.extend(header_recs)

    for h in header_analysis:
        if h["status"] is True:
            positives.append(f"✔ {h['key']} Header Enabled")
        elif h["status"] is False and h["key"] in ("HSTS", "CSP"):
            deduction_notes.append(f"Missing {h['key']} Header")

    # ----------------------------------------------------
    # 6. Sensitive Version Disclosure (-1)
    # ----------------------------------------------------
    server_str = str(result.get("server", "")).lower() if result and isinstance(result, dict) else ""
    if any(k in server_str for k in ["apache/2.", "nginx/1.", "php/7.", "php/8.", "openssl/"]):
        total_deductions += 1
        deduction_notes.append("Server Version Disclosed in HTTP Headers")

    # Remove duplicate positives
    positives = sorted(list(set(positives)))

    # ----------------------------------------------------
    # 7. TLS / SSL Configuration (TLS 1.3: +3, Valid SSL: +2)
    # ----------------------------------------------------
    if ssl_info and isinstance(ssl_info, dict):
        if _ssl_is_valid(ssl_info):
            total_bonuses += 2
            positives.append("✔ Valid SSL Certificate")

        tls_ver = str(ssl_info.get("tls_version", "")).upper()
        if "1.3" in tls_ver:
            total_bonuses += 3
            positives.append("✔ TLS 1.3 Protocol")
        elif "1.0" in tls_ver or "1.1" in tls_ver:
            total_deductions += 8
            deduction_notes.append(f"Deprecated TLS Version ({tls_ver})")
            recommendations.append({
                "risk": "High",
                "reason": f"Deprecated TLS version detected ({tls_ver}).",
                "recommendation": "Disable TLS 1.0 and 1.1; enforce TLS 1.2 or TLS 1.3."
            })

    if (result and isinstance(result, dict) and str(result.get("protocol", "")).lower() == "https") or (ssl_info and isinstance(ssl_info, dict)):
        if "✔ HTTPS Enabled" not in positives:
            positives.append("✔ HTTPS Enabled")

    # Deduplicate positives
    positives = sorted(list(set(positives)))

    # ----------------------------------------------------
    # 7. Construct Transparent Factor Score Breakdown
    # ----------------------------------------------------
    score_breakdown = []
    
    # Base Score
    score_breakdown.append({
        "category": "Baseline",
        "factor": "Baseline Security Rating",
        "impact": "100",
        "impact_val": 100,
        "type": "neutral"
    })

    # HTTPS & SSL Factors
    is_https = (result and isinstance(result, dict) and str(result.get("protocol", "")).lower() == "https") or (ssl_info and isinstance(ssl_info, dict))
    if is_https:
        score_breakdown.append({
            "category": "Encryption & SSL",
            "factor": "HTTPS Encrypted Protocol",
            "impact": "+2",
            "impact_val": 2,
            "type": "bonus"
        })

    if ssl_info and isinstance(ssl_info, dict):
        tls_ver = str(ssl_info.get("tls_version", "")).upper()
        if "1.3" in tls_ver:
            score_breakdown.append({
                "category": "Encryption & SSL",
                "factor": "TLS 1.3 Modern Encryption Protocol",
                "impact": "+3",
                "impact_val": 3,
                "type": "bonus"
            })
        elif "1.0" in tls_ver or "1.1" in tls_ver:
            score_breakdown.append({
                "category": "Encryption & SSL",
                "factor": f"Deprecated TLS Protocol ({tls_ver})",
                "impact": "-8",
                "impact_val": -8,
                "type": "deduction"
            })

        if _ssl_is_valid(ssl_info):
            score_breakdown.append({
                "category": "Encryption & SSL",
                "factor": "Valid Trusted SSL Certificate",
                "impact": "+2",
                "impact_val": 2,
                "type": "bonus"
            })

    # WAF & CDN Factors
    if waf_detected:
        waf_name = waf_data.get("provider", "Active WAF") if isinstance(waf_data, dict) else "Active WAF"
        score_breakdown.append({
            "category": "Infrastructure & Perimeter",
            "factor": f"Web Application Firewall ({waf_name})",
            "impact": "+3",
            "impact_val": 3,
            "type": "bonus"
        })
    elif url_info and isinstance(url_info, dict) and "waf" in url_info:
        score_breakdown.append({
            "category": "Infrastructure & Perimeter",
            "factor": "Missing Web Application Firewall (WAF)",
            "impact": "-2",
            "impact_val": -2,
            "type": "deduction"
        })

    if cdn_matches:
        score_breakdown.append({
            "category": "Infrastructure & Perimeter",
            "factor": f"Enterprise Edge CDN ({', '.join(cdn_matches)})",
            "impact": "+2",
            "impact_val": 2,
            "type": "bonus"
        })

    # Header Factors Breakdown
    for h in header_analysis:
        h_name = h["name"]
        h_key = h["key"]
        if h["status"] is True:
            score_breakdown.append({
                "category": "Browser Security Headers",
                "factor": f"{h_key} Header Present",
                "impact": "+2" if h_key in ("HSTS", "CSP") else "+1",
                "impact_val": 2 if h_key in ("HSTS", "CSP") else 1,
                "type": "bonus"
            })
        elif h["status"] is False:
            penalty = -2 if h_key in ("HSTS", "CSP") else -1
            score_breakdown.append({
                "category": "Browser Security Headers",
                "factor": f"Missing {h_key} Header",
                "impact": str(penalty),
                "impact_val": penalty,
                "type": "deduction"
            })

    # Vulnerabilities Impact
    if crit_cnt > 0:
        score_breakdown.append({
            "category": "Vulnerabilities",
            "factor": f"{crit_cnt} Critical Vulnerability Findings",
            "impact": f"-{crit_cnt * 25}",
            "impact_val": -(crit_cnt * 25),
            "type": "deduction"
        })
    if high_cnt > 0:
        score_breakdown.append({
            "category": "Vulnerabilities",
            "factor": f"{high_cnt} High Vulnerability Findings",
            "impact": f"-{high_cnt * 15}",
            "impact_val": -(high_cnt * 15),
            "type": "deduction"
        })
    if med_cnt > 0:
        score_breakdown.append({
            "category": "Vulnerabilities",
            "factor": f"{med_cnt} Medium Vulnerability Findings",
            "impact": f"-{med_cnt * 8}",
            "impact_val": -(med_cnt * 8),
            "type": "deduction"
        })
    if low_cnt > 0:
        score_breakdown.append({
            "category": "Vulnerabilities",
            "factor": f"{low_cnt} Low Vulnerability Findings",
            "impact": f"-{low_cnt * 3}",
            "impact_val": -(low_cnt * 3),
            "type": "deduction"
        })

    if has_port_80 and not has_port_443:
        score_breakdown.append({
            "category": "Infrastructure & Perimeter",
            "factor": "Unencrypted HTTP Port 80 (No HTTPS)",
            "impact": "-3",
            "impact_val": -3,
            "type": "deduction"
        })

    # Calculate exact mathematical score from score_breakdown items
    calc_bonuses = sum(item["impact_val"] for item in score_breakdown if item.get("type") == "bonus")
    calc_deductions = abs(sum(item["impact_val"] for item in score_breakdown if item.get("type") == "deduction"))
    
    raw_calculated_score = 100 + calc_bonuses - calc_deductions
    final_score = max(0, min(100, raw_calculated_score))

    if raw_calculated_score > 100:
        formula_str = f"100 (Baseline) + {calc_bonuses} (Protections) - {calc_deductions} (Risks) = {raw_calculated_score} → Capped at {final_score} / 100"
    else:
        formula_str = f"100 (Baseline) + {calc_bonuses} (Protections) - {calc_deductions} (Risks) = {final_score} / 100"

    # Categorize recommendations into groups
    categorized_recommendations = {
        "Transport Security": [],
        "Security Headers": [],
        "Infrastructure & WAF": [],
        "Network & Service Hardening": []
    }

    for rec in recommendations:
        r_text = (str(rec.get("reason", "")) + " " + str(rec.get("recommendation", ""))).lower()
        if any(k in r_text for k in ["https", "tls", "ssl", "hsts", "redirect", "port 80"]):
            categorized_recommendations["Transport Security"].append(rec)
        elif any(k in r_text for k in ["csp", "header", "x-frame", "mime", "referrer", "permission"]):
            categorized_recommendations["Security Headers"].append(rec)
        elif any(k in r_text for k in ["waf", "firewall", "cdn", "cloudflare", "proxy", "ddos"]):
            categorized_recommendations["Infrastructure & WAF"].append(rec)
        else:
            categorized_recommendations["Network & Service Hardening"].append(rec)

    # Compute severity distribution
    info_cnt = header_stats.get("missing", 0) if header_stats else 0
    risk_distribution = {
        "critical": crit_cnt,
        "high": high_cnt,
        "medium": med_cnt,
        "low": low_cnt,
        "info": info_cnt
    }

    summary = generate_summary(
        final_score,
        crit_cnt,
        high_cnt,
        med_cnt,
        low_cnt,
        deduction_notes,
        positives,
        header_stats=header_stats,
        waf_info=waf_data,
        ssl_info=ssl_info
    )

    # Human-friendly, clear control explanations
    FACTOR_MEANINGS = {
        "Baseline Security Rating": "Standard 100-point baseline score before applying security protections and risks.",
        "HTTPS Encrypted Protocol": "Protects user data and logins with end-to-end TLS encryption.",
        "TLS 1.3 Modern Encryption Protocol": "Uses the latest cryptographic ciphers for fast, uncrackable key exchange.",
        "Valid Trusted SSL Certificate": "Cryptographically verified and trusted by all major browsers.",
        "Web Application Firewall (Active WAF)": "Active perimeter firewall defending against SQLi, XSS, and automated bots.",
        "Enterprise Edge CDN": "Global edge network providing DDoS mitigation and traffic stability.",
        "HSTS Header Present": "Forces web browsers to always connect via secure HTTPS, blocking SSL stripping.",
        "CSP Header Present": "Restricts external resource execution, stopping Cross-Site Scripting (XSS).",
        "X-Frame-Options Header Present": "Prevents malicious sites from framing this page (Clickjacking defense).",
        "X-Content-Type-Options Header Present": "Blocks MIME-type sniffing and file spoofing attacks.",
        "Referrer-Policy Header Present": "Controls private URL parameters from leaking to external websites.",
        "Permissions-Policy Header Present": "Restricts browser device APIs (camera, microphone, location) from unauthorized use.",
        "Missing HSTS Header": "Recommended: Add HSTS header to ensure browsers always use encrypted connections.",
        "Missing CSP Header": "Recommended: Configure Content-Security-Policy to restrict unauthorized scripts.",
        "Missing X-Frame-Options Header": "Best Practice: Add X-Frame-Options to prevent invisible iframe clickjacking.",
        "Missing X-Content-Type-Options Header": "Best Practice: Add 'X-Content-Type-Options: nosniff' header.",
        "Missing Referrer-Policy Header": "Best Practice: Set Referrer-Policy to prevent leaking sensitive URL queries.",
        "Missing Permissions-Policy Header": "Best Practice: Explicitly configure browser hardware permissions.",
        "Missing Web Application Firewall (WAF)": "Advisory: No active perimeter Web Application Firewall (WAF) detected.",
        "Unencrypted HTTP Port 80 (No HTTPS)": "Security Risk: Plaintext HTTP port active without HTTPS enabled."
    }

    for item in score_breakdown:
        f_name = item.get("factor", "")
        if "Critical Vulnerability" in f_name:
            meaning = f"Severe vulnerability detected on target host requiring immediate security remediation."
        elif "High Vulnerability" in f_name:
            meaning = f"High-risk network service exposed on target host (e.g. unencrypted FTP on port 21 or public database on port 3306)."
        elif "Medium Vulnerability" in f_name:
            meaning = f"Medium-risk service exposure identified on target host requiring firewall restriction."
        elif "Low Vulnerability" in f_name:
            meaning = f"Minor service exposure identified on target host."
        else:
            meaning = FACTOR_MEANINGS.get(f_name)
            if not meaning:
                for k, m in FACTOR_MEANINGS.items():
                    if k in f_name or f_name.startswith(k[:15]):
                        meaning = m
                        break
        item["meaning"] = meaning or "Security control audit factor."

    return {
        "score": final_score,
        "raw_score": raw_calculated_score,
        "grade": security_grade(final_score),
        "summary": summary,
        "recommendations": recommendations,
        "categorized_recommendations": categorized_recommendations,
        "score_breakdown": score_breakdown,
        "total_bonuses": calc_bonuses,
        "total_deductions": calc_deductions,
        "formula_str": formula_str,
        "risk_distribution": risk_distribution,
        "positives": positives,
        "header_analysis": header_analysis,
        "header_stats": header_stats
    }