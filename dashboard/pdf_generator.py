import os
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import (
    get_db_connection,
    get_ip_scan_context,
    get_latest_host_status,
    get_latest_url_scan,
    get_url_scan_dashboard_context,
)

REPORT_RISK_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#0d9488"),
    "ok": colors.HexColor("#16a34a"),
}
REPORT_INK = colors.HexColor("#0f172a")
REPORT_MUTED = colors.HexColor("#64748b")
REPORT_LINE = colors.HexColor("#e2e8f0")
REPORT_HEAD_BG = colors.HexColor("#0f172a")


def _report_risk_color(level):
    return REPORT_RISK_COLORS.get(str(level or "").strip().lower(), REPORT_MUTED)


def _report_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="RTitle", fontName="Helvetica-Bold", fontSize=20, leading=24,
            textColor=REPORT_INK,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RSub", fontName="Helvetica", fontSize=10, leading=14,
            textColor=REPORT_MUTED,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RSection", fontName="Helvetica-Bold", fontSize=12.5, leading=16,
            textColor=REPORT_INK, spaceBefore=16, spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RCell", fontName="Helvetica", fontSize=8.5, leading=11.5,
            textColor=REPORT_INK,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RCellMuted", fontName="Helvetica", fontSize=8.5, leading=11.5,
            textColor=REPORT_MUTED,
        )
    )
    styles.add(
        ParagraphStyle(
            name="RBullet", fontName="Helvetica", fontSize=9.5, leading=14,
            textColor=REPORT_INK, leftIndent=12, bulletIndent=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="REmpty", fontName="Helvetica-Oblique", fontSize=9.5,
            textColor=REPORT_MUTED,
        )
    )
    return styles


def _report_data_table(header, rows, col_widths, styles, risk_col=None):
    """Builds a styled reportlab Table."""
    body_style = styles["RCell"]
    table_rows = [[Paragraph(f"<b>{h}</b>", ParagraphStyle(
        name="Head", fontName="Helvetica-Bold", fontSize=8.5, leading=11,
        textColor=colors.white,
    )) for h in header]]

    for row in rows:
        cells = []
        for idx, val in enumerate(row):
            text = "" if val is None else str(val)
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if risk_col is not None and idx == risk_col:
                color = _report_risk_color(val)
                cells.append(Paragraph(
                    f'<font color="{color.hexval()}"><b>{text or "-"}</b></font>',
                    body_style,
                ))
            else:
                cells.append(Paragraph(text or "-", body_style))
        table_rows.append(cells)

    t = Table(table_rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), REPORT_HEAD_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.5, REPORT_LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _report_kv_table(pairs, styles, col_widths):
    """A 2-column label/value info block (no header row)."""
    rows = []
    for label, value in pairs:
        rows.append([
            Paragraph(f"<b>{label}</b>", styles["RCellMuted"]),
            Paragraph(str(value) if value not in (None, "") else "-", styles["RCell"]),
        ])
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, REPORT_LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
    ]))
    return t


def _report_header_footer(canvas_obj, doc, subtitle):
    canvas_obj.saveState()
    width, height = A4
    canvas_obj.setFillColor(REPORT_HEAD_BG)
    canvas_obj.rect(0, height - 6, width, 6, fill=1, stroke=0)
    canvas_obj.setFillColor(REPORT_MUTED)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawString(36, 18, f"CyberShieldAI — {subtitle}")
    canvas_obj.drawRightString(
        width - 36, 18,
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ·  Page {doc.page}",
    )
    canvas_obj.restoreState()


def _fetch_findings_for_ip(ip):
    """Ports/services/vulnerabilities/CVEs/OS/risk for one specific IP."""
    if not ip or ip == "Unknown":
        return {
            "ports": [], "services": [], "vulnerabilities": [], "cves": [],
            "os_info": None, "risk": None,
        }
    conn = get_db_connection()
    ports = conn.execute(
        """
        SELECT * FROM ports 
        WHERE id IN (SELECT MAX(id) FROM ports WHERE ip=? GROUP BY port)
        ORDER BY port ASC
        """,
        (ip,),
    ).fetchall()
    services = conn.execute(
        """
        SELECT * FROM service_versions 
        WHERE id IN (SELECT MAX(id) FROM service_versions WHERE ip=? GROUP BY port)
        ORDER BY port ASC
        """,
        (ip,),
    ).fetchall()
    vulnerabilities = conn.execute(
        """
        SELECT * FROM vulnerabilities 
        WHERE id IN (SELECT MAX(id) FROM vulnerabilities WHERE ip=? GROUP BY port, risk, service)
        ORDER BY
            CASE LOWER(risk)
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
            END,
            port ASC
        """,
        (ip,),
    ).fetchall()
    cves = conn.execute(
        """
        SELECT * FROM cves 
        WHERE id IN (SELECT MAX(id) FROM cves WHERE ip=? GROUP BY cve_id, port)
        ORDER BY
            CASE LOWER(severity)
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
            END,
            port ASC
        """,
        (ip,),
    ).fetchall()
    os_info = conn.execute(
        "SELECT * FROM os_info WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,)
    ).fetchone()
    risk = conn.execute(
        "SELECT * FROM risk_summary WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,)
    ).fetchone()


    conn.close()
    return {
        "ports": ports,
        "services": services,
        "vulnerabilities": vulnerabilities,
        "cves": cves,
        "os_info": os_info,
        "risk": risk,
    }


def _parse_scan_time(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _determine_latest_scan_type(latest_host, latest_url):
    """Figures out whether the most recent scan action was an IP scan or a URL scan."""
    if not latest_host and not latest_url:
        return None
    if not latest_url:
        return "ip"
    if not latest_host:
        return "url"

    host_ip = latest_host["target_ip"]
    url_ip = latest_url["ip"]
    host_time = _parse_scan_time(latest_host["scan_time"])
    url_time = _parse_scan_time(latest_url["scan_time"])

    if host_ip and url_ip and host_ip == url_ip and host_time and url_time:
        gap = (host_time - url_time).total_seconds()
        if -5 <= gap <= 900:
            return "url"

    if host_time and url_time:
        return "ip" if host_time >= url_time else "url"
    return "ip" if host_time else "url"


def _findings_sections(flow, styles, findings, page_width):
    """Shared Ports / Services / Vulnerabilities / CVEs / Risk / OS section-builder."""
    ports, services = findings["ports"], findings["services"]
    vulnerabilities, cves = findings["vulnerabilities"], findings["cves"]
    os_info, risk = findings["os_info"], findings["risk"]

    flow.append(Paragraph("Operating System &amp; Risk Score", styles["RSection"]))
    os_name = os_info["os_name"] if os_info else "Not detected"
    os_details = os_info["os_details"] if os_info else "-"
    device_type = os_info["device_type"] if os_info else "-"
    risk_pairs = [
        ("Operating System", os_name),
        ("Device Type", device_type),
        ("OS Details", os_details),
    ]
    if risk:
        risk_pairs += [
            ("Risk Level", risk["risk_level"]),
            ("Risk Score", risk["total_score"]),
            ("Critical / High / Medium / Low",
             f"{risk['critical_count']} / {risk['high_count']} / {risk['medium_count']} / {risk['low_count']}"),
        ]
    flow.append(_report_kv_table(risk_pairs, styles, [page_width * 0.35, page_width * 0.65]))

    flow.append(Paragraph(f"Open Ports &amp; Services ({len(ports)})", styles["RSection"]))
    if ports:
        rows = [[p["port"], p["state"], p["service"] or "-", (p["banner"] or "-")[:80]] for p in ports]
        flow.append(_report_data_table(
            ["Port", "State", "Service", "Banner"], rows,
            [page_width * 0.10, page_width * 0.14, page_width * 0.20, page_width * 0.56],
            styles,
        ))
    else:
        flow.append(Paragraph("No open ports found.", styles["REmpty"]))

    if services:
        flow.append(Paragraph(f"Service Versions ({len(services)})", styles["RSection"]))
        rows = [[s["port"], s["service"] or "-", s["product"] or "-", s["version"] or "-"] for s in services]
        flow.append(_report_data_table(
            ["Port", "Service", "Product", "Version"], rows,
            [page_width * 0.14, page_width * 0.24, page_width * 0.34, page_width * 0.28],
            styles,
        ))

    flow.append(Paragraph(f"Vulnerabilities Audit ({len(vulnerabilities)})", styles["RSection"]))
    if vulnerabilities:
        rows = []
        for v in vulnerabilities:
            v_dict = dict(v) if hasattr(v, "keys") else v
            desc = v_dict.get("description") or "Exposed service requiring access control"
            rec = v_dict.get("remediation") or "Restrict external access and apply firewall filtering"
            cvss = v_dict.get("cvss_score") if v_dict.get("cvss_score") is not None else (7.5 if v_dict.get("risk") == "High" else (9.8 if v_dict.get("risk") == "Critical" else 5.3))
            vector = v_dict.get("cvss_vector") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            ac = v_dict.get("attack_complexity") or "Low (AC:L)"
            pr = v_dict.get("privileges_required") or "None (PR:N)"
            imp = v_dict.get("impact") or "Medium (Exposure Risk)"
            rows.append([f"{v_dict['port']}/{v_dict.get('service') or '-'}", v_dict["risk"], str(cvss), vector[:22], ac, pr, imp[:25], rec[:30]])
        flow.append(_report_data_table(
            ["Port/Service", "Severity", "CVSS v3.1", "Vector", "Complexity", "Privileges", "Impact", "Remediation"], rows,
            [page_width * 0.11, page_width * 0.09, page_width * 0.09, page_width * 0.16, page_width * 0.11, page_width * 0.10, page_width * 0.17, page_width * 0.17],
            styles, risk_col=1,
        ))
    else:
        flow.append(Paragraph("No vulnerabilities detected on scanned ports.", styles["REmpty"]))

    flow.append(Paragraph(f"CVE Findings ({len(cves)})", styles["RSection"]))
    if cves:
        rows = []
        for cv in cves:
            cv_dict = dict(cv) if hasattr(cv, "keys") else cv
            cvss = cv_dict.get("cvss_score") if cv_dict.get("cvss_score") is not None else "-"
            cwe = cv_dict.get("cwe_id") or "CWE-200"
            published = cv_dict.get("published_date") or "-"
            exploit = "Yes (⚡ PoC)" if cv_dict.get("exploit_available") else "No"
            rows.append([cv_dict["cve_id"], cwe, f"{cv_dict['port']}/{cv_dict.get('service') or '-'}", cv_dict["severity"], str(cvss), published, exploit])
        flow.append(_report_data_table(
            ["CVE ID", "CWE Weakness", "Port/Service", "Severity", "CVSS v3.1", "Published", "Exploit"], rows,
            [page_width * 0.16, page_width * 0.15, page_width * 0.14, page_width * 0.12,
             page_width * 0.10, page_width * 0.16, page_width * 0.17],
            styles, risk_col=3,
        ))
    else:
        flow.append(Paragraph("No CVEs matched.", styles["REmpty"]))


def _build_ip_scan_pdf():
    ctx = get_ip_scan_context()
    latest_ip = ctx["latest_ip"]
    styles = _report_styles()
    page_width = A4[0] - 72

    pdf_path = os.path.join(BASE_DIR, "CyberShield_IP_Scan_Report.pdf")
    doc = SimpleDocTemplate(
        pdf_path, pagesize=A4,
        leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36,
        title="CyberShieldAI IP Scan Report",
    )
    flow = []

    flow.append(Paragraph("CyberShieldAI", styles["RTitle"]))
    flow.append(Paragraph("IP / Network Vulnerability Scan Report", styles["RSub"]))
    flow.append(Spacer(1, 10))
    flow.append(HRFlowable(width="100%", color=REPORT_LINE, thickness=1))
    flow.append(Spacer(1, 12))

    if not latest_ip:
        flow.append(Paragraph(
            "No IP scan has been run yet. Run a scan from the dashboard first.",
            styles["REmpty"],
        ))
    else:
        host = ctx["host"]
        overview = [
            ("Target IP", latest_ip),
            ("Host Status", host["status"] if host else "Unknown"),
            ("Scan Time", host["scan_time"] if host else "-"),
        ]
        flow.append(Paragraph("Target Overview", styles["RSection"]))
        flow.append(_report_kv_table(overview, styles, [page_width * 0.35, page_width * 0.65]))

        findings = {
            "ports": ctx["ports_data"], "services": ctx["services"],
            "vulnerabilities": ctx["vulnerabilities_data"], "cves": ctx["cves_data"],
            "os_info": ctx["os_info"] if isinstance(ctx["os_info"], dict) else None,
            "risk": ctx["risk"],
        }
        os_dict = ctx["os_info"]

        class _OSShim(dict):
            def __getitem__(self, key):
                return dict.get(self, key)

        findings["os_info"] = _OSShim(os_dict) if os_dict else None

        _findings_sections(flow, styles, findings, page_width)

        flow.append(Paragraph("Recommended Actions", styles["RSection"]))
        recs = ctx["recommendations"]
        if recs:
            for r in recs:
                flow.append(Paragraph(f"•  {r}", styles["RBullet"]))
        else:
            flow.append(Paragraph("No recommendations available.", styles["REmpty"]))

    doc.build(
        flow,
        onFirstPage=lambda c, d: _report_header_footer(c, d, "IP Scan Report"),
        onLaterPages=lambda c, d: _report_header_footer(c, d, "IP Scan Report"),
    )
    return pdf_path, "CyberShield_IP_Scan_Report.pdf"


def _build_url_scan_pdf():
    url_ctx = get_url_scan_dashboard_context()
    raw_scan = url_ctx["url_scan"]
    url_scan = dict(raw_scan) if raw_scan else None
    styles = _report_styles()
    page_width = A4[0] - 72

    pdf_path = os.path.join(BASE_DIR, "CyberShield_URL_Scan_Report.pdf")
    doc = SimpleDocTemplate(
        pdf_path, pagesize=A4,
        leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36,
        title="CyberShieldAI URL Scan Report",
    )
    flow = []

    flow.append(Paragraph("CyberShieldAI", styles["RTitle"]))
    flow.append(Paragraph("URL Threat Scan Report", styles["RSub"]))
    flow.append(Spacer(1, 10))
    flow.append(HRFlowable(width="100%", color=REPORT_LINE, thickness=1))
    flow.append(Spacer(1, 12))

    if not url_scan:
        flow.append(Paragraph(
            "No URL scan has been run yet. Run a scan from the dashboard first.",
            styles["REmpty"],
        ))
    else:
        overview = [
            ("Scanned URL", url_scan["url"]),
            ("Domain", url_scan["domain"] or "-"),
            ("Resolved IP", url_scan["ip"] or "Unknown"),
            ("Protocol", str(url_scan["protocol"]).upper() if url_scan["protocol"] else "-"),
            ("Threat Score", f"{url_scan['score']} / 100"),
            ("Risk Level", url_scan["risk"]),
            ("Scan Time", url_scan["scan_time"]),
        ]
        flow.append(Paragraph("Target Overview", styles["RSection"]))
        flow.append(_report_kv_table(overview, styles, [page_width * 0.35, page_width * 0.65]))

        if url_ctx["url_remarks"]:
            flow.append(Paragraph("Findings / Remarks", styles["RSection"]))
            for r in url_ctx["url_remarks"]:
                flow.append(Paragraph(f"•  {r}", styles["RBullet"]))

        flow.append(Paragraph("SSL / TLS Certificate", styles["RSection"]))
        ssl_info = url_ctx["url_ssl"]
        if ssl_info:
            ssl_dict = dict(ssl_info) if hasattr(ssl_info, "keys") else ssl_info
            san_str = "-"
            if ssl_dict.get("parsed_san_names"):
                san_str = ", ".join(ssl_dict["parsed_san_names"])
            elif ssl_dict.get("san_names"):
                san_str = ", ".join(ssl_dict["san_names"]) if isinstance(ssl_dict["san_names"], list) else str(ssl_dict["san_names"])

            chain_h = ssl_dict.get("chain_hierarchy") or {}
            chain_str = f"Root: {chain_h.get('root', 'Trusted Root CA')}  ->  Interm: {chain_h.get('intermediate', ssl_dict.get('issuer') or 'Public CA')}  ->  Leaf: {chain_h.get('leaf', ssl_dict.get('subject') or '-')}"

            ssl_pairs = [
                ("HTTPS Enabled", "Yes" if ssl_dict.get("has_ssl") else "No"),
                ("TLS Version", ssl_dict.get("tls_version") or "-"),
                ("Cipher Suite", ssl_dict.get("cipher_suite") or "-"),
                ("Key Type & Algorithm", ssl_dict.get("key_type") or "-"),
                ("Key Size", ssl_dict.get("key_size") or "-"),
                ("SHA256 Fingerprint", ssl_dict.get("fingerprint_sha256") or "-"),
                ("Issuer", ssl_dict.get("issuer") or "-"),
                ("Subject", ssl_dict.get("subject") or "-"),
                ("Certificate Chain Hierarchy", chain_str),
                ("SAN Names", san_str),
                ("Valid From", ssl_dict.get("valid_from") or "-"),
                ("Valid To", ssl_dict.get("valid_to") or "-"),
                ("Days Remaining", ssl_dict.get("days_remaining") if ssl_dict.get("days_remaining") is not None else "-"),
                ("Status", "Expired" if ssl_dict.get("expired") else ("Self-Signed" if ssl_dict.get("self_signed") else "Valid Certificate")),
            ]
            flow.append(_report_kv_table(ssl_pairs, styles, [page_width * 0.35, page_width * 0.65]))
        else:
            flow.append(Paragraph("No SSL/TLS data captured.", styles["REmpty"]))

        flow.append(Paragraph("Technology Stack", styles["RSection"]))
        if url_ctx["url_tech_server"] or url_ctx["url_tech_list"]:
            tech_list = url_ctx["url_tech_list"] or []
            server_val = url_ctx["url_tech_server"] or "Unknown"

            from scanner.technology_detector import classify_technologies
            classified = classify_technologies(tech_list, server_val)

            tech_pairs = [("Server", server_val)]
            for cat, items in classified.items():
                if items:
                    tech_pairs.append((cat, ", ".join(items)))

            flow.append(_report_kv_table(tech_pairs, styles, [page_width * 0.35, page_width * 0.65]))
        else:
            flow.append(Paragraph("No technology fingerprint captured.", styles["REmpty"]))

        flow.append(Paragraph("WHOIS &amp; Network Intelligence", styles["RSection"]))
        intel = url_ctx["url_intel"]
        if intel:
            intel_dict = dict(intel) if hasattr(intel, "keys") else (intel if isinstance(intel, dict) else {})
            if url_scan["ip"] in ("Unknown", "unknown", None) or url_scan.get("protocol") == "unknown":
                waf_str = "Not Assessed"
            else:
                waf_val = intel_dict.get("waf") or "None Identified"
                if isinstance(waf_val, dict):
                    if waf_val.get("detected"):
                        waf_str = f"Active WAF Detected ({waf_val.get('provider')})"
                    else:
                        waf_str = "No WAF Detected (Low Confidence)"
                elif waf_val in ("None", "none", None):
                    waf_str = "No WAF Detected (Low Confidence)"
                else:
                    waf_str = str(waf_val)

            target_domain = url_scan.get("domain", "") or ""
            is_target_ip = False
            try:
                import ipaddress
                clean_target = target_domain.strip()
                if clean_target.startswith("["):
                    end_idx = clean_target.find("]")
                    if end_idx != -1:
                        clean_target = clean_target[1:end_idx]
                elif clean_target.count(":") == 1:
                    clean_target = clean_target.split(":")[0]
                ipaddress.ip_address(clean_target)
                is_target_ip = True
            except ValueError:
                pass

            reg_val = "N/A" if is_target_ip else (intel_dict.get("registrar") or "-")
            created_val = "N/A" if is_target_ip else (intel_dict.get("creation_date") or "-")
            expires_val = "N/A" if is_target_ip else (intel_dict.get("expiration_date") or "-")

            if url_scan.get("ip") in ("Unknown", "unknown", None):
                country_val = "Unknown (Not Assessed)"
                reg_city_val = "Unknown (Target IP could not be resolved)"
                isp_val = "Unknown"
                asn_val = "Unknown"
            else:
                country_val = intel_dict.get("country") or "-"
                reg_city_val = f"{intel_dict.get('region') or '-'} / {intel_dict.get('city') or '-'}"
                isp_val = intel_dict.get("isp") or "-"
                asn_val = intel_dict.get("asn") or "-"

            intel_pairs = [
                ("Registrar", reg_val),
                ("Domain Created", created_val),
                ("Domain Expires", expires_val),
                ("Country", country_val),
                ("Region / City", reg_city_val),
                ("ISP", isp_val),
                ("ASN", asn_val),
                ("WAF Status", waf_str),
            ]
            flow.append(_report_kv_table(intel_pairs, styles, [page_width * 0.35, page_width * 0.65]))
        else:
            flow.append(Paragraph("No WHOIS/GeoIP intelligence captured.", styles["REmpty"]))


        if url_scan["ip"] and url_scan["ip"] != "Unknown":
            findings = _fetch_findings_for_ip(url_scan["ip"])
            _findings_sections(flow, styles, findings, page_width)


    doc.build(
        flow,
        onFirstPage=lambda c, d: _report_header_footer(c, d, "URL Scan Report"),
        onLaterPages=lambda c, d: _report_header_footer(c, d, "URL Scan Report"),
    )
    return pdf_path, "CyberShield_URL_Scan_Report.pdf"


def _build_empty_state_pdf():
    styles = _report_styles()
    pdf_path = os.path.join(BASE_DIR, "CyberShield_Report.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=A4, title="CyberShieldAI Report")
    flow = [
        Paragraph("CyberShieldAI", styles["RTitle"]),
        Paragraph("No scan has been run yet.", styles["RSub"]),
        Spacer(1, 12),
        Paragraph(
            "Run an IP scan or a URL scan from the dashboard, then download the report again.",
            styles["REmpty"],
        ),
    ]
    doc.build(flow)
    return pdf_path, "CyberShield_Report.pdf"
