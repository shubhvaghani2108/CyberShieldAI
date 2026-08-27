from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch

styles = getSampleStyleSheet()

title_style = styles["Heading1"]
title_style.alignment = TA_CENTER

heading = styles["Heading2"]
normal = styles["BodyText"]


def create_pdf(report, output_file):

    doc = SimpleDocTemplate(output_file)

    story = []

    # ==========================
    # Cover
    # ==========================

    story.append(Paragraph("CyberShieldAI Enterprise Report", title_style))
    story.append(Spacer(1, 0.30 * inch))

    story.append(Paragraph("Executive Summary", heading))
    story.append(Spacer(1, 0.15 * inch))

    scan = report["url_scan"]

    story.append(
        Paragraph(
            f"<b>Target URL:</b> {scan['url']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>Target IP:</b> {scan['ip']}",
            normal
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk:</b> {scan['risk']}",
            normal
        )
    )

    story.append(Spacer(1, 0.30 * inch))

    # ==========================
    # WHOIS
    # ==========================

    story.append(Paragraph("WHOIS Information", heading))

    whois = report.get("url_intelligence") or {}
    url_target = report.get("url_scan", {}).get("domain") or report.get("url_scan", {}).get("url") or ""
    is_target_ip = False
    try:
        import ipaddress
        clean_target = str(url_target).strip()
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

    target_ip_val = report.get("url_scan", {}).get("ip") or whois.get("ip") or ""
    is_ip_unresolved = target_ip_val in ("Unknown", "unknown", None, "") or whois.get("country") == "Unknown"

    reg_val = "N/A" if is_target_ip else whois.get("registrar", "Unknown")
    created_val = "N/A" if is_target_ip else whois.get("creation_date", "Unknown")
    expires_val = "N/A" if is_target_ip else whois.get("expiration_date", "Unknown")

    country_val = "Unknown" if is_ip_unresolved else whois.get("country", "Unknown")
    city_val = "Unknown" if is_ip_unresolved else whois.get("city", "Unknown")
    isp_val = "Unknown" if is_ip_unresolved else whois.get("isp", "Unknown")
    asn_val = "Unknown" if is_ip_unresolved else whois.get("asn", "Unknown")

    table = Table(
        [
            ["Registrar", reg_val],
            ["Created", created_val],
            ["Expires", expires_val],
            ["Country", country_val],
            ["City", city_val],
            ["ISP", isp_val],
            ["ASN", asn_val]
        ]
    )

    table.setStyle(

        TableStyle([

            ("GRID",(0,0),(-1,-1),1,colors.grey),

            ("BACKGROUND",(0,0),(-1,0),colors.lightblue),

            ("FONTNAME",(0,0),(-1,-1),"Helvetica"),

            ("BOTTOMPADDING",(0,0),(-1,0),10),

        ])

    )

    story.append(table)

    story.append(Spacer(1,0.30*inch))

    # ==========================
    # Ports
    # ==========================

    story.append(Paragraph("Open Ports", heading))

    rows = [["Port","State","Service"]]

    for p in report["ports"]:

        rows.append([

            p["port"],

            p["state"],

            p["service"]

        ])

    table = Table(rows)

    table.setStyle(

        TableStyle([

            ("GRID",(0,0),(-1,-1),1,colors.black),

            ("BACKGROUND",(0,0),(-1,0),colors.lightgrey)

        ])

    )

    story.append(table)

    story.append(Spacer(1,0.30*inch))

    # ==========================
    # SSL
    # ==========================

    ssl = report["ssl"]

    if ssl:

        story.append(Paragraph("SSL Certificate", heading))

        rows = [

            ["TLS Version", ssl["tls_version"]],

            ["Issuer", ssl["issuer"]],

            ["Subject", ssl["subject"]],

            ["Valid From", ssl["valid_from"]],

            ["Valid To", ssl["valid_to"]],

            ["Grade", ssl["grade"]]

        ]

        table = Table(rows)

        table.setStyle(

            TableStyle([

                ("GRID",(0,0),(-1,-1),1,colors.black),

                ("BACKGROUND",(0,0),(-1,0),colors.lightgrey)

            ])

        )

        story.append(table)

    story.append(Spacer(1,0.30*inch))

    # ==========================
    # Vulnerabilities
    # ==========================

    story.append(Paragraph("Detected Vulnerabilities", heading))

    rows = [["Port","Service","Risk"]]

    for v in report["vulnerabilities"]:

        rows.append([

            v["port"],

            v["service"],

            v["risk"]

        ])

    table = Table(rows)

    table.setStyle(

        TableStyle([

            ("GRID",(0,0),(-1,-1),1,colors.black),

            ("BACKGROUND",(0,0),(-1,0),colors.red),

            ("TEXTCOLOR",(0,0),(-1,0),colors.white)

        ])

    )

    story.append(table)

    doc.build(story)

    print("PDF Generated:", output_file)