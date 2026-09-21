import os
import sys
import urllib.parse
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfgen import canvas

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import (
    get_db_connection,
    get_ip_scan_context,
    get_latest_host_status,
    get_latest_url_scan,
    get_url_scan_dashboard_context,
    determine_latest_scan_type,
)

# ----------------------------------------------------------------------
# Modern Cybersecurity Color Palette & Tokens
# ----------------------------------------------------------------------
C_HERO_BG = colors.HexColor("#090d16")        # Deep obsidian cyber navy
C_HERO_ACCENT = colors.HexColor("#0284c7")    # Sky cyan accent
C_HERO_BORDER = colors.HexColor("#1e293b")    # Slate 800
C_INK = colors.HexColor("#0f172a")            # Slate 900 primary text
C_TEXT_MID = colors.HexColor("#334155")       # Slate 700 secondary text
C_MUTED = colors.HexColor("#64748b")          # Slate 500 metadata
C_LINE = colors.HexColor("#e2e8f0")           # Slate 200 table / card border
C_BG_LIGHT = colors.HexColor("#f8fafc")       # Slate 50 row / card background
C_BG_CARD = colors.HexColor("#ffffff")        # Pure white card background

# Severity & Risk Color Maps
SEV_MAP = {
    "critical": {
        "text": colors.HexColor("#b91c1c"),
        "bg": colors.HexColor("#fef2f2"),
        "border": colors.HexColor("#f87171"),
        "label": "CRITICAL RISK",
    },
    "high": {
        "text": colors.HexColor("#c2410c"),
        "bg": colors.HexColor("#fff7ed"),
        "border": colors.HexColor("#fb923c"),
        "label": "HIGH RISK",
    },
    "medium": {
        "text": colors.HexColor("#a16207"),
        "bg": colors.HexColor("#fefce8"),
        "border": colors.HexColor("#fde047"),
        "label": "MEDIUM RISK",
    },
    "low": {
        "text": colors.HexColor("#047857"),
        "bg": colors.HexColor("#ecfdf5"),
        "border": colors.HexColor("#6ee7b7"),
        "label": "LOW RISK",
    },
    "ok": {
        "text": colors.HexColor("#047857"),
        "bg": colors.HexColor("#ecfdf5"),
        "border": colors.HexColor("#6ee7b7"),
        "label": "SECURE",
    },
    "info": {
        "text": colors.HexColor("#0284c7"),
        "bg": colors.HexColor("#f0f9ff"),
        "border": colors.HexColor("#7dd3fc"),
        "label": "INFORMATIONAL",
    },
}


def _get_sev(level):
    key = str(level or "").strip().lower()
    return SEV_MAP.get(key, SEV_MAP["info"])


def _clean_timestamp(ts):
    if not ts:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_str = str(ts).strip()
    if "." in ts_str:
        base = ts_str.split(".")[0]
        return f"{base} UTC"
    if "+" in ts_str:
        base = ts_str.split("+")[0]
        return f"{base} UTC"
    return ts_str


# ----------------------------------------------------------------------
# Numbered Two-Pass Canvas (Running Header, Running Footer, Page X of Y)
# ----------------------------------------------------------------------
class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(total_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, total_pages):
        self.saveState()
        w, h = A4

        # Page 1 top decorative cyber accent stripe
        if self._pageNumber == 1:
            self.setFillColor(colors.HexColor("#0284c7"))
            self.rect(0, h - 4, w * 0.45, 4, fill=1, stroke=0)
            self.setFillColor(colors.HexColor("#0b1329"))
            self.rect(w * 0.45, h - 4, w * 0.55, 4, fill=1, stroke=0)
        else:
            # Running header on page 2+
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, h - 28, w - 36, h - 28)

            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(colors.HexColor("#334155"))
            self.drawString(36, h - 22, "CYBERSHIELD AI")
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(108, h - 22, "·  Security Assessment & Threat Audit Report")

            target_label = getattr(self, "doc_target", "Confidential Assessment")
            if len(str(target_label)) > 45:
                target_label = str(target_label)[:42] + "..."
            self.drawRightString(w - 36, h - 22, f"Target: {target_label}")

        # Running Footer on all pages
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(36, 30, w - 36, 30)

        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(36, 18, "CONFIDENTIAL")
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#94a3b8"))
        self.drawString(100, 18, "·  Generated by CyberShieldAI Threat Intelligence Engine")

        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#334155"))
        self.drawRightString(w - 36, 18, page_str)

        self.restoreState()


# ----------------------------------------------------------------------
# Typography & Stylesheet
# ----------------------------------------------------------------------
def _report_styles():
    styles = getSampleStyleSheet()

    # Hero Banner Styles
    styles.add(ParagraphStyle(
        name="HeaderBrand",
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=22,
        textColor=colors.white,
    ))
    styles.add(ParagraphStyle(
        name="HeaderTagline",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#38bdf8"),
    ))
    styles.add(ParagraphStyle(
        name="HeaderMetaRight",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#94a3b8"),
        alignment=2,
    ))
    styles.add(ParagraphStyle(
        name="HeaderBadge",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#38bdf8"),
        alignment=2,
    ))

    # Section Heading with keepWithNext=True to eliminate orphaned headers
    styles.add(ParagraphStyle(
        name="SecTitle",
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=C_INK,
        spaceBefore=12,
        spaceAfter=5,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="SecSub",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=C_MUTED,
        spaceAfter=5,
        keepWithNext=True,
    ))

    # KPI Scorecard Styles
    styles.add(ParagraphStyle(
        name="KpiLabel",
        fontName="Helvetica-Bold",
        fontSize=6.5,
        leading=8.5,
        textColor=C_MUTED,
    ))
    styles.add(ParagraphStyle(
        name="KpiValue",
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=C_INK,
    ))
    styles.add(ParagraphStyle(
        name="KpiSub",
        fontName="Helvetica",
        fontSize=7,
        leading=9.5,
        textColor=C_TEXT_MID,
    ))

    # Executive Verdict Banner Styles
    styles.add(ParagraphStyle(
        name="VerdictTitle",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11.5,
        textColor=C_INK,
    ))
    styles.add(ParagraphStyle(
        name="VerdictBody",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=C_TEXT_MID,
    ))

    # Tables
    styles.add(ParagraphStyle(
        name="TblHead",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=colors.white,
    ))
    styles.add(ParagraphStyle(
        name="TblCell",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=C_INK,
    ))
    styles.add(ParagraphStyle(
        name="TblCellMono",
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=C_INK,
    ))
    styles.add(ParagraphStyle(
        name="TblCellMuted",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=C_MUTED,
    ))

    # Callouts
    styles.add(ParagraphStyle(
        name="CalloutTitle",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10.5,
        textColor=C_INK,
    ))
    styles.add(ParagraphStyle(
        name="CalloutBody",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=C_MUTED,
    ))

    # Bullets & Findings
    styles.add(ParagraphStyle(
        name="FindingBullet",
        fontName="Helvetica",
        fontSize=7.5,
        leading=11,
        textColor=C_INK,
    ))

    # Backward compatibility aliases
    styles.add(ParagraphStyle(
        name="RTitle", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=C_INK,
    ))
    styles.add(ParagraphStyle(
        name="RSub", fontName="Helvetica", fontSize=10, leading=14, textColor=C_MUTED,
    ))
    styles.add(ParagraphStyle(
        name="RSection", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=C_INK, spaceBefore=12, spaceAfter=5, keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="RCell", fontName="Helvetica", fontSize=7.5, leading=10.5, textColor=C_INK,
    ))
    styles.add(ParagraphStyle(
        name="RCellMuted", fontName="Helvetica", fontSize=7.5, leading=10.5, textColor=C_MUTED,
    ))
    styles.add(ParagraphStyle(
        name="RBullet", fontName="Helvetica", fontSize=8, leading=11.5, textColor=C_INK, leftIndent=12, bulletIndent=0,
    ))
    styles.add(ParagraphStyle(
        name="REmpty", fontName="Helvetica-Oblique", fontSize=8, textColor=C_MUTED,
    ))

    return styles


# ----------------------------------------------------------------------
# Visual Component Builders
# ----------------------------------------------------------------------
def _build_hero_header(title, subtitle, target_name, scan_time, report_id, styles, width):
    """Creates a sleek executive hero banner in deep cyber obsidian navy."""
    clean_target = str(target_name or "Unknown").strip()
    if len(clean_target) > 55:
        display_target = clean_target[:52] + "..."
    else:
        display_target = clean_target

    left_content = [
        Paragraph("CYBERSHIELD AI", styles["HeaderBrand"]),
        Spacer(1, 2),
        Paragraph(title.upper(), styles["HeaderTagline"]),
        Spacer(1, 4),
        Paragraph(
            f'<font color="#94a3b8">Target Asset:</font> <font color="#f8fafc"><b>{display_target}</b></font>',
            ParagraphStyle(name="HeroTargetP", fontName="Helvetica", fontSize=8, leading=11, textColor=colors.white)
        ),
    ]

    right_content = [
        Paragraph('<font color="#38bdf8"><b>● CONFIDENTIAL // TLP:AMBER</b></font>', styles["HeaderBadge"]),
        Spacer(1, 3),
        Paragraph(f"<b>Report ID:</b> {report_id}", styles["HeaderMetaRight"]),
        Paragraph(f"<b>Scan Time:</b> {scan_time}", styles["HeaderMetaRight"]),
        Paragraph("<b>Standard:</b> NIST CSF / OWASP Top 10", styles["HeaderMetaRight"]),
    ]

    tbl = Table(
        [[left_content, right_content]],
        colWidths=[width * 0.62, width * 0.38],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_HERO_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEBELOW", (0, 0), (-1, -1), 3, C_HERO_ACCENT),
    ]))
    return tbl


def _build_kpi_scorecard(score, risk_level, target_scope, open_ports_count, vulns_count, cves_count, styles, width):
    """Builds a 4-card metric scorecard dashboard."""
    card_w = width / 4.0
    sev = _get_sev(risk_level)

    # Score cleanup
    score_display = 0 if score in (None, "", "None") else score

    # Card 1: Threat Score
    c1 = [
        Paragraph("THREAT SCORE", styles["KpiLabel"]),
        Spacer(1, 2),
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{score_display} / 100</b></font>', styles["KpiValue"]),
        Spacer(1, 2),
        Paragraph(
            f'<font color="{sev["text"].hexval()}"><b>● {str(risk_level or "LOW").upper()} RISK</b></font>',
            styles["KpiSub"]
        ),
    ]

    # Card 2: Target Scope
    domain_disp = str(target_scope.get("domain") or target_scope.get("ip") or "-")
    if len(domain_disp) > 22:
        domain_disp = domain_disp[:19] + "..."
    c2 = [
        Paragraph("PERIMETER TARGET", styles["KpiLabel"]),
        Spacer(1, 2),
        Paragraph(f"<b>{domain_disp}</b>", ParagraphStyle(
            name="KpiDomVal", fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=C_INK
        )),
        Spacer(1, 2),
        Paragraph(f"IP: {target_scope.get('ip', 'Unknown')}", styles["KpiSub"]),
    ]

    # Card 3: Attack Surface
    c3 = [
        Paragraph("OPEN PORTS", styles["KpiLabel"]),
        Spacer(1, 2),
        Paragraph(f'<font color="#0284c7"><b>{open_ports_count}</b></font>', styles["KpiValue"]),
        Spacer(1, 2),
        Paragraph(f"{target_scope.get('ports_summary', 'Responsive Services')}", styles["KpiSub"]),
    ]

    # Card 4: Vulnerabilities & CVEs
    vuln_color = colors.HexColor("#dc2626") if vulns_count > 0 else colors.HexColor("#047857")
    c4 = [
        Paragraph("EXPLOITS &amp; VULNS", styles["KpiLabel"]),
        Spacer(1, 2),
        Paragraph(f'<font color="{vuln_color.hexval()}"><b>{vulns_count}</b></font>', styles["KpiValue"]),
        Spacer(1, 2),
        Paragraph(f"{cves_count} CVEs Identified", styles["KpiSub"]),
    ]

    tbl = Table([[c1, c2, c3, c4]], colWidths=[card_w, card_w, card_w, card_w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BG_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.5, C_LINE),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, sev["text"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _build_verdict_banner(score, risk_level, open_ports_count, vulns_count, styles, width):
    """Builds an executive verdict callout summarizing the security posture."""
    sev = _get_sev(risk_level)
    level_lower = str(risk_level or "low").strip().lower()

    if level_lower in ("low", "ok") and vulns_count == 0:
        badge_text = "✔ EXECUTIVE VERDICT: LOW PERIMETER EXPOSURE — SECURE BASELINE"
        desc = (
            f"The perimeter assessment detected {open_ports_count} responsive service(s) operating within normal baselines. "
            "Zero unpatched CVE exposures, weak cryptographic signatures, or exposed administrative dashboards were discovered. "
            "The target perimeter satisfies fundamental cybersecurity hygiene standards."
        )
    elif level_lower == "medium" or (vulns_count > 0 and vulns_count <= 2):
        badge_text = "⚠ EXECUTIVE VERDICT: MODERATE RISK EXPOSURE — ATTENTION RECOMMENDED"
        desc = (
            f"The assessment identified {open_ports_count} exposed port(s) with {vulns_count} potential vulnerability finding(s). "
            "Review remediation guidance below to apply patch updates and restrict unnecessary perimeter access."
        )
    else:
        badge_text = "⚡ EXECUTIVE VERDICT: ELEVATED THREAT DETECTED — REMEDIATION REQUIRED"
        desc = (
            f"Perimeter scan detected {vulns_count} active vulnerability finding(s) with elevated threat exposure. "
            "Immediate access control restrictions and emergency vendor patch cycles should be initiated."
        )

    content = [
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{badge_text}</b></font>', styles["VerdictTitle"]),
        Spacer(1, 2),
        Paragraph(desc, styles["VerdictBody"]),
    ]

    tbl = Table([[content]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev["bg"]),
        ("BOX", (0, 0), (-1, -1), 0.5, sev["border"]),
        ("LINEBEFORE", (0, 0), (0, -1), 3.5, sev["text"]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return tbl


def _build_info_callout(icon, title, message, status, styles, width):
    """Builds a beautiful status callout card instead of raw italic text."""
    sev = _get_sev(status)
    content = [
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{icon}  {title}</b></font>', styles["CalloutTitle"]),
        Spacer(1, 2),
        Paragraph(message, styles["CalloutBody"]),
    ]
    tbl = Table([[content]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev["bg"]),
        ("BOX", (0, 0), (-1, -1), 0.5, sev["border"]),
        ("LINEBEFORE", (0, 0), (0, -1), 3, sev["text"]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
    ]))
    return tbl


def _build_key_value_table(pairs, styles, width, left_ratio=0.32):
    """Renders a sleek 2-column key-value specification table."""
    left_w = width * left_ratio
    right_w = width * (1.0 - left_ratio)

    rows = []
    for label, val in pairs:
        val_str = str(val) if val not in (None, "") else "—"
        lower_lbl = label.lower()
        if any(keyword in lower_lbl for keyword in ["ip", "url", "fingerprint", "sha256", "cipher", "asn"]):
            val_p = Paragraph(f'<font name="Courier">{val_str}</font>', styles["TblCell"])
        elif "risk" in lower_lbl:
            sev = _get_sev(val_str)
            val_p = Paragraph(f'<font color="{sev["text"].hexval()}"><b>● {val_str.upper()}</b></font>', styles["TblCell"])
        elif "status" in lower_lbl and val_str.lower() in ("valid", "valid certificate", "up", "active"):
            val_p = Paragraph(f'<font color="#047857"><b>● {val_str}</b></font>', styles["TblCell"])
        else:
            val_p = Paragraph(val_str, styles["TblCell"])

        lbl_p = Paragraph(f"<b>{label}</b>", styles["TblCellMuted"])
        rows.append([lbl_p, val_p])

    tbl = Table(rows, colWidths=[left_w, right_w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), C_BG_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.5, C_LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _build_data_table(headers, rows, col_widths, styles, risk_col=None):
    """Renders a styled data table with dark header and zebra rows."""
    header_cells = [
        Paragraph(f"<b>{h}</b>", styles["TblHead"])
        for h in headers
    ]
    table_rows = [header_cells]

    for row in rows:
        cells = []
        for col_idx, val in enumerate(row):
            text = "—" if val is None or val == "" else str(val)
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

            if risk_col is not None and col_idx == risk_col:
                sev = _get_sev(val)
                cells.append(Paragraph(
                    f'<font color="{sev["text"].hexval()}"><b>● {text.upper()}</b></font>',
                    styles["TblCell"]
                ))
            elif col_idx == 0 and any(k in headers[0].lower() for k in ["port", "cve"]):
                cells.append(Paragraph(f'<font name="Courier-Bold" color="#0284c7">{text}</font>', styles["TblCell"]))
            elif "state" in headers[col_idx].lower() and text.lower() == "open":
                cells.append(Paragraph('<font color="#047857"><b>● open</b></font>', styles["TblCell"]))
            else:
                cells.append(Paragraph(text, styles["TblCell"]))
        table_rows.append(cells)

    t = Table(table_rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_HERO_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _build_recommendations_section(recs, styles, width):
    """Builds an enterprise numbered hardening action checklist."""
    default_recs = [
        ("Maintain Strict Transport Security (HSTS)", "Verify that <code>Strict-Transport-Security: max-age=63072000; includeSubDomains; preload</code> is transmitted on all HTTPS responses to protect against protocol downgrade."),
        ("Enforce Origin Shielding & Ingress Filtering", "Configure cloud security groups to restrict direct IP ingress, permitting web traffic exclusively from verified CDN edge proxies."),
        ("Deploy Defense-in-Depth Security Headers", "Ensure Content-Security-Policy (CSP), X-Content-Type-Options: nosniff, and Referrer-Policy are enforced across all web routes."),
        ("Establish Continuous Vulnerability Scanning", "Maintain automated scheduled scans to identify emerging CVEs and outdated package versions as new security advisories are disclosed."),
    ]

    action_items = []
    # Filter out empty or generic boilerplate recommendations
    clean_recs = [
        r for r in (recs or [])
        if r and not any(phrase in str(r).lower() for phrase in ["no recommendations", "no critical recommendations"])
    ]

    if clean_recs:
        for idx, r in enumerate(clean_recs, start=1):
            action_items.append((str(idx), r, ""))
    else:
        for idx, (title, detail) in enumerate(default_recs, start=1):
            action_items.append((str(idx), title, detail))

    rows = []
    for num, title, detail in action_items:
        num_p = Paragraph(f'<font color="#0284c7"><b>{num}</b></font>', styles["FindingBullet"])
        if detail:
            text_p = Paragraph(f"<b>{title}:</b> {detail}", styles["FindingBullet"])
        else:
            text_p = Paragraph(f"<b>{title}</b>", styles["FindingBullet"])
        rows.append([num_p, text_p])

    tbl = Table(rows, colWidths=[width * 0.05, width * 0.95])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return tbl


# ----------------------------------------------------------------------
# Backward Compatibility Wrappers
# ----------------------------------------------------------------------
def _report_data_table(header, rows, col_widths, styles, risk_col=None):
    return _build_data_table(header, rows, col_widths, styles, risk_col=risk_col)


def _report_kv_table(pairs, styles, col_widths):
    width = sum(col_widths)
    left_ratio = col_widths[0] / width if width > 0 else 0.35
    return _build_key_value_table(pairs, styles, width, left_ratio=left_ratio)


def _report_header_footer(canvas_obj, doc, subtitle):
    # Handled via NumberedCanvas
    pass


# ----------------------------------------------------------------------
# Database Finding Fetcher
# ----------------------------------------------------------------------
def _fetch_findings_for_ip(ip):
    """Fetches ports, services, vulnerabilities, CVEs, OS, and risk for a target IP."""
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


_determine_latest_scan_type = determine_latest_scan_type


# ----------------------------------------------------------------------
# Findings Sections (Operating System, Ports, Services, Vulns, CVEs)
# ----------------------------------------------------------------------
def _findings_sections(flow, styles, findings, page_width):
    """Shared Ports / Services / Vulnerabilities / CVEs / Risk / OS section-builder."""
    ports = findings.get("ports") or []
    services = findings.get("services") or []
    vulnerabilities = findings.get("vulnerabilities") or []
    cves = findings.get("cves") or []
    os_info = findings.get("os_info")
    risk = findings.get("risk")

    # 1. Operating System & Perimeter Risk Profile
    flow.append(Paragraph('<font color="#0284c7">▌</font> Operating System &amp; Perimeter Risk Profile', styles["SecTitle"]))
    os_name = os_info["os_name"] if os_info and "os_name" in os_info else "TCP/IP Network Host (Cloud Edge)"
    os_details = os_info["os_details"] if os_info and "os_details" in os_info else "Active network host with responsive service port(s)"
    device_type = os_info["device_type"] if os_info and "device_type" in os_info else "Network Device / Cloud Proxy"

    risk_pairs = [
        ("Identified OS", os_name),
        ("Device Classification", device_type),
        ("OS Fingerprint Details", os_details),
    ]
    if risk:
        r_level = risk.get("risk_level", "Low")
        r_score = risk.get("total_score", 0)
        c_cnt = risk.get("critical_count", 0)
        h_cnt = risk.get("high_count", 0)
        m_cnt = risk.get("medium_count", 0)
        l_cnt = risk.get("low_count", 0)
        risk_pairs += [
            ("Risk Assessment Level", f"{r_level} (Score: {r_score} / 100)"),
            ("Vulnerability Breakdown", f"Critical: {c_cnt}  |  High: {h_cnt}  |  Medium: {m_cnt}  |  Low: {l_cnt}"),
        ]
    else:
        risk_pairs += [
            ("Risk Assessment Level", "Low Risk (Score: 0 / 100)"),
            ("Vulnerability Breakdown", "Critical: 0  |  High: 0  |  Medium: 0  |  Low: 0"),
        ]
    flow.append(_build_key_value_table(risk_pairs, styles, page_width))
    flow.append(Spacer(1, 6))

    # 2. Open Ports & Services
    flow.append(Paragraph(f'<font color="#0284c7">▌</font> Open Ports &amp; Perimeter Services ({len(ports)})', styles["SecTitle"]))
    if ports:
        rows = []
        for p in ports:
            p_dict = dict(p) if hasattr(p, "keys") else p
            banner_text = (p_dict.get("banner") or "—")[:85]
            rows.append([
                str(p_dict.get("port")),
                p_dict.get("state") or "open",
                p_dict.get("service") or "—",
                banner_text,
            ])
        flow.append(_build_data_table(
            headers=["Port", "State", "Service", "Service Banner / Response"],
            rows=rows,
            col_widths=[page_width * 0.12, page_width * 0.14, page_width * 0.20, page_width * 0.54],
            styles=styles,
        ))
    else:
        flow.append(_build_info_callout(
            icon="✔",
            title="No Open Perimeter Ports Discovered",
            message="No active external ports responded to TCP SYN probes during the reconnaissance scan window.",
            status="low",
            styles=styles,
            width=page_width,
        ))
    flow.append(Spacer(1, 6))

    # 3. Service Versions (kept with table to prevent orphans)
    if services:
        flow.append(Paragraph(f'<font color="#0284c7">▌</font> Service Version Fingerprints ({len(services)})', styles["SecTitle"]))
        rows = []
        for s in services:
            s_dict = dict(s) if hasattr(s, "keys") else s
            rows.append([
                str(s_dict.get("port")),
                s_dict.get("service") or "—",
                s_dict.get("product") or "HTTP Edge Service",
                s_dict.get("version") or "—",
            ])
        flow.append(_build_data_table(
            headers=["Port", "Service", "Product", "Version"],
            rows=rows,
            col_widths=[page_width * 0.14, page_width * 0.24, page_width * 0.38, page_width * 0.24],
            styles=styles,
        ))
        flow.append(Spacer(1, 6))

    # 4. Vulnerabilities Audit
    flow.append(Paragraph(f'<font color="#0284c7">▌</font> Vulnerabilities Audit ({len(vulnerabilities)})', styles["SecTitle"]))
    if vulnerabilities:
        rows = []
        for v in vulnerabilities:
            v_dict = dict(v) if hasattr(v, "keys") else v
            rec = v_dict.get("remediation") or "Restrict external access and apply firewall filtering"
            cvss = v_dict.get("cvss_score") if v_dict.get("cvss_score") is not None else (7.5 if v_dict.get("risk") == "High" else (9.8 if v_dict.get("risk") == "Critical" else 5.3))
            vector = v_dict.get("cvss_vector") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            imp = v_dict.get("impact") or "Exposure Risk"
            rows.append([
                f"{v_dict.get('port')}/{v_dict.get('service') or '—'}",
                v_dict.get("risk") or "Medium",
                str(cvss),
                vector[:20],
                imp[:24],
                rec[:32],
            ])
        flow.append(_build_data_table(
            headers=["Port/Service", "Severity", "CVSS v3.1", "Vector", "Impact", "Remediation Guidance"],
            rows=rows,
            col_widths=[page_width * 0.16, page_width * 0.14, page_width * 0.11, page_width * 0.18, page_width * 0.20, page_width * 0.21],
            styles=styles,
            risk_col=1,
        ))
    else:
        flow.append(_build_info_callout(
            icon="✔",
            title="Zero Vulnerabilities Detected on Scanned Ports",
            message="Active vulnerability probes confirmed no unauthenticated service access, known remote code execution flaws, or misconfigurations across responsive ports.",
            status="low",
            styles=styles,
            width=page_width,
        ))
    flow.append(Spacer(1, 6))

    # 5. CVE Findings
    flow.append(Paragraph(f'<font color="#0284c7">▌</font> CVE Exploit Findings ({len(cves)})', styles["SecTitle"]))
    if cves:
        rows = []
        for cv in cves:
            cv_dict = dict(cv) if hasattr(cv, "keys") else cv
            cvss = cv_dict.get("cvss_score") if cv_dict.get("cvss_score") is not None else "—"
            cwe = cv_dict.get("cwe_id") or "CWE-200"
            published = cv_dict.get("published_date") or "—"
            exploit = "⚡ PoC Available" if cv_dict.get("exploit_available") else "No Known PoC"
            rows.append([
                cv_dict.get("cve_id", "—"),
                cwe,
                f"{cv_dict.get('port')}/{cv_dict.get('service') or '—'}",
                cv_dict.get("severity") or "Medium",
                str(cvss),
                published,
                exploit,
            ])
        flow.append(_build_data_table(
            headers=["CVE ID", "CWE Weakness", "Port/Service", "Severity", "CVSS v3.1", "Published", "Exploit Status"],
            rows=rows,
            col_widths=[page_width * 0.17, page_width * 0.15, page_width * 0.14, page_width * 0.13, page_width * 0.10, page_width * 0.15, page_width * 0.16],
            styles=styles,
            risk_col=3,
        ))
    else:
        flow.append(_build_info_callout(
            icon="✔",
            title="Zero Known CVE Exposures Identified",
            message="Target service fingerprints do not match any known Common Vulnerabilities and Exposures (CVEs) cataloged in NIST NVD or Exploit-DB indexes.",
            status="low",
            styles=styles,
            width=page_width,
        ))
    flow.append(Spacer(1, 6))


# ----------------------------------------------------------------------
# PDF Generator: IP Scan Report
# ----------------------------------------------------------------------
def _build_ip_scan_pdf(user_id=None):
    ctx = get_ip_scan_context(user_id=user_id)
    if not ctx.get("latest_ip") and user_id is not None:
        ctx = get_ip_scan_context(user_id=None)

    latest_ip = ctx.get("latest_ip")
    styles = _report_styles()
    page_width = A4[0] - 72

    pdf_path = os.path.join(BASE_DIR, "CyberShield_IP_Scan_Report.pdf")
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title="CyberShieldAI IP Vulnerability Scan Report",
    )
    doc.doc_target = latest_ip or "Network Host"
    flow = []

    if not latest_ip:
        flow.append(_build_hero_header(
            title="IP & Network Perimeter Vulnerability Audit",
            subtitle="Host Fingerprinting, Port Probing & Exposure Assessment",
            target_name="No Active Host Scanned",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-IP-PENDING",
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 14))
        flow.append(_build_info_callout(
            icon="ℹ",
            title="No IP Scan Assessment Data Available",
            message="No IP vulnerability scans have been executed under this account yet. Initiate an IP scan from the CyberShieldAI Dashboard to generate a comprehensive host security audit.",
            status="info",
            styles=styles,
            width=page_width,
        ))
    else:
        host = ctx.get("host")
        raw_scan_time = host.get("scan_time") if host else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_time = _clean_timestamp(raw_scan_time)
        report_id = f"CSA-IP-{datetime.now().strftime('%Y%m%d')}-{latest_ip.replace('.', '')[-6:]}"

        ports_data = ctx.get("ports_data") or []
        vulns_data = ctx.get("vulnerabilities_data") or []
        cves_data = ctx.get("cves_data") or []
        risk_data = ctx.get("risk") or {}

        risk_score = risk_data.get("total_score") if hasattr(risk_data, "get") else ctx.get("risk_score")
        if risk_score in (None, "", "None"):
            risk_score = 0
        risk_level = risk_data.get("risk_level") if hasattr(risk_data, "get") else (ctx.get("risk_level") or "Low")

        # 1. Executive Hero Header
        flow.append(_build_hero_header(
            title="IP & Network Perimeter Vulnerability Audit",
            subtitle="Automated Host Fingerprinting & Threat Exposure Assessment",
            target_name=f"Host IPv4: {latest_ip}",
            scan_time=scan_time,
            report_id=report_id,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 8))

        # 2. Executive KPI Scorecard
        target_scope = {
            "domain": latest_ip,
            "ip": latest_ip,
            "ports_summary": f"{len(ports_data)} Responsive Ports",
        }
        flow.append(_build_kpi_scorecard(
            score=risk_score,
            risk_level=risk_level,
            target_scope=target_scope,
            open_ports_count=len(ports_data),
            vulns_count=len(vulns_data),
            cves_count=len(cves_data),
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 8))

        # 3. Executive Verdict Callout
        flow.append(_build_verdict_banner(
            score=risk_score,
            risk_level=risk_level,
            open_ports_count=len(ports_data),
            vulns_count=len(vulns_data),
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 6))

        # 4. Target Host Overview
        flow.append(Paragraph('<font color="#0284c7">▌</font> Host Identity &amp; Network Scope', styles["SecTitle"]))
        overview = [
            ("Target IP Address", latest_ip),
            ("Perimeter Host Status", host.get("status", "UP / ACTIVE") if host else "UP / ACTIVE"),
            ("Assessment Timestamp", scan_time),
            ("Operating System", ctx.get("os_info", {}).get("os_name", "TCP/IP Network Host") if isinstance(ctx.get("os_info"), dict) else "TCP/IP Network Host"),
            ("Device Classification", ctx.get("os_info", {}).get("device_type", "Network Device") if isinstance(ctx.get("os_info"), dict) else "Network Device"),
        ]
        flow.append(_build_key_value_table(overview, styles, page_width))
        flow.append(Spacer(1, 6))

        # 5. Shared Findings Sections (OS, Ports, Services, Vulns, CVEs)
        findings = {
            "ports": ports_data,
            "services": ctx.get("services") or [],
            "vulnerabilities": vulns_data,
            "cves": cves_data,
            "os_info": ctx.get("os_info") if isinstance(ctx.get("os_info"), dict) else None,
            "risk": risk_data,
        }
        _findings_sections(flow, styles, findings, page_width)

        # 6. Recommended Next Steps
        flow.append(Paragraph('<font color="#0284c7">▌</font> Recommended Hardening Next Steps', styles["SecTitle"]))
        recs = ctx.get("recommendations") or []
        flow.append(_build_recommendations_section(recs, styles, page_width))

    doc.build(flow, canvasmaker=NumberedCanvas)
    return pdf_path, "CyberShield_IP_Scan_Report.pdf"


# ----------------------------------------------------------------------
# PDF Generator: URL Scan Report
# ----------------------------------------------------------------------
def _build_url_scan_pdf(user_id=None):
    url_ctx = get_url_scan_dashboard_context(user_id=user_id, include_deep_intel=True)
    if not url_ctx.get("url_scan") and user_id is not None:
        url_ctx = get_url_scan_dashboard_context(user_id=None, include_deep_intel=True)

    raw_scan = url_ctx.get("url_scan")
    url_scan = dict(raw_scan) if raw_scan else None
    styles = _report_styles()
    page_width = A4[0] - 72

    pdf_path = os.path.join(BASE_DIR, "CyberShield_URL_Scan_Report.pdf")
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title="CyberShieldAI URL Threat Scan Report",
    )
    doc.doc_target = (url_scan.get("domain") or url_scan.get("url") or "URL Threat Assessment") if url_scan else "URL Threat Assessment"
    flow = []

    if not url_scan:
        flow.append(_build_hero_header(
            title="URL Threat & Perimeter Security Audit",
            subtitle="Automated Perimeter Fingerprinting & Vulnerability Analysis",
            target_name="No Active Scan Found",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-URL-PENDING",
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 14))
        flow.append(_build_info_callout(
            icon="ℹ",
            title="No URL Scan Assessment Data Available",
            message="No URL scans have been executed under this account yet. Initiate a URL threat scan from the CyberShieldAI Dashboard to generate a full perimeter threat report.",
            status="info",
            styles=styles,
            width=page_width,
        ))
    else:
        # Fetch findings for the resolved IP (if any)
        resolved_ip = url_scan.get("ip") or "Unknown"
        findings = _fetch_findings_for_ip(resolved_ip) if (resolved_ip and resolved_ip != "Unknown") else {
            "ports": [], "services": [], "vulnerabilities": [], "cves": [], "os_info": None, "risk": None,
        }

        ports_count = len(findings.get("ports", []))
        vulns_count = len(findings.get("vulnerabilities", []))
        cves_count = len(findings.get("cves", []))

        raw_scan_time = url_scan.get("scan_time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_time = _clean_timestamp(raw_scan_time)
        report_id = f"CSA-URL-{datetime.now().strftime('%Y%m%d')}-{abs(hash(url_scan.get('url', '')))%100000:05d}"
        threat_score = url_scan.get("score") if url_scan.get("score") is not None else 0
        risk_level = url_scan.get("risk") or "Low"

        # 1. Executive Hero Header
        flow.append(_build_hero_header(
            title="URL Threat & Perimeter Security Audit",
            subtitle="Automated Perimeter Fingerprinting & Vulnerability Analysis",
            target_name=url_scan.get("url", "Target URL"),
            scan_time=scan_time,
            report_id=report_id,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 8))

        # 2. Executive KPI Scorecard
        target_scope = {
            "domain": url_scan.get("domain") or urllib.parse.urlparse(url_scan.get("url", "")).netloc or "Unknown",
            "ip": resolved_ip,
            "ports_summary": f"{ports_count} Responsive Ports" if ports_count else "Endpoint Scanned",
        }
        flow.append(_build_kpi_scorecard(
            score=threat_score,
            risk_level=risk_level,
            target_scope=target_scope,
            open_ports_count=ports_count,
            vulns_count=vulns_count,
            cves_count=cves_count,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 8))

        # 3. Executive Verdict Callout
        flow.append(_build_verdict_banner(
            score=threat_score,
            risk_level=risk_level,
            open_ports_count=ports_count,
            vulns_count=vulns_count,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 6))

        # 4. Target Identity & Scope
        flow.append(Paragraph('<font color="#0284c7">▌</font> Target Identity &amp; Network Scope', styles["SecTitle"]))
        overview_pairs = [
            ("Scanned URL", url_scan.get("url")),
            ("Domain Name", url_scan.get("domain") or urllib.parse.urlparse(url_scan.get("url", "")).netloc or "—"),
            ("Resolved IP Address", resolved_ip),
            ("Protocol Scheme", str(url_scan.get("protocol") or "HTTPS").upper()),
            ("Threat Score Index", f"{threat_score} / 100"),
            ("Perimeter Risk Level", risk_level),
            ("Assessment Timestamp", scan_time),
        ]
        flow.append(_build_key_value_table(overview_pairs, styles, page_width))
        flow.append(Spacer(1, 6))

        # 5. Security Findings & Observations
        remarks = url_ctx.get("url_remarks") or []
        if isinstance(remarks, str):
            remarks = [r.strip() for r in remarks.split(",") if r.strip()]

        flow.append(Paragraph('<font color="#0284c7">▌</font> Security Findings &amp; Observations', styles["SecTitle"]))
        if remarks:
            finding_rows = []
            for r in remarks:
                r_lower = r.lower()
                if any(w in r_lower for w in ["https", "tls", "secure", "passed", "valid"]):
                    icon_cell = Paragraph('<font color="#047857"><b>✔</b></font>', styles["FindingBullet"])
                elif any(w in r_lower for w in ["warn", "redirect", "notice"]):
                    icon_cell = Paragraph('<font color="#0284c7"><b>ℹ</b></font>', styles["FindingBullet"])
                else:
                    icon_cell = Paragraph('<font color="#ea580c"><b>⚠</b></font>', styles["FindingBullet"])
                text_cell = Paragraph(f"<b>Observation:</b> {r}", styles["FindingBullet"])
                finding_rows.append([icon_cell, text_cell])

            t_rem = Table(finding_rows, colWidths=[page_width * 0.05, page_width * 0.95])
            t_rem.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), C_BG_LIGHT),
                ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            flow.append(t_rem)
        else:
            flow.append(_build_info_callout(
                icon="✔",
                title="Baseline Observations Verified",
                message="Target endpoint responded with standard operational HTTP headers and parameters.",
                status="low",
                styles=styles,
                width=page_width,
            ))
        flow.append(Spacer(1, 6))

        # 6. SSL / TLS Cryptographic Health
        flow.append(Paragraph('<font color="#0284c7">▌</font> SSL / TLS Cryptographic Health', styles["SecTitle"]))
        ssl_info = url_ctx.get("url_ssl")
        if ssl_info:
            ssl_dict = dict(ssl_info) if hasattr(ssl_info, "keys") else ssl_info
            san_str = "—"
            if ssl_dict.get("parsed_san_names"):
                san_str = ", ".join(ssl_dict["parsed_san_names"][:4])
            elif ssl_dict.get("san_names"):
                san_str = ", ".join(ssl_dict["san_names"][:4]) if isinstance(ssl_dict["san_names"], list) else str(ssl_dict["san_names"])[:50]

            chain_h = ssl_dict.get("chain_hierarchy") or {}
            chain_str = f"Root: {chain_h.get('root', 'Trusted Root CA')}  →  Interm: {chain_h.get('intermediate', ssl_dict.get('issuer') or 'Public CA')}  →  Leaf: {chain_h.get('leaf', ssl_dict.get('subject') or '-')}"

            cert_status = "Expired" if ssl_dict.get("expired") else ("Self-Signed" if ssl_dict.get("self_signed") else "Valid Certificate")
            ssl_pairs = [
                ("HTTPS Enabled", "Yes (Enforced)" if ssl_dict.get("has_ssl") else "No"),
                ("TLS Protocol Version", ssl_dict.get("tls_version") or "TLSv1.3 / TLSv1.2"),
                ("Cipher Suite", ssl_dict.get("cipher_suite") or "—"),
                ("Public Key Type & Algorithm", ssl_dict.get("key_type") or "RSA / ECDSA"),
                ("Key Size", str(ssl_dict.get("key_size") or "2048-bit")),
                ("SHA256 Fingerprint", ssl_dict.get("fingerprint_sha256") or "—"),
                ("Issuing Authority (CA)", ssl_dict.get("issuer") or "—"),
                ("Subject CN", ssl_dict.get("subject") or "—"),
                ("Certificate Chain", chain_str),
                ("Subject Alt Names (SAN)", san_str),
                ("Valid From", str(ssl_dict.get("valid_from") or "—")),
                ("Valid To", str(ssl_dict.get("valid_to") or "—")),
                ("Days Remaining", f"{ssl_dict.get('days_remaining')} days" if ssl_dict.get("days_remaining") is not None else "—"),
                ("Certificate Status", cert_status),
            ]
            flow.append(_build_key_value_table(ssl_pairs, styles, page_width))
        else:
            flow.append(_build_info_callout(
                icon="ℹ",
                title="SSL / TLS Handshake Telemetry Omitted",
                message="Target endpoint responded without exposing public SSL certificate telemetry during the automated sweep. Endpoint is routed via a cloud CDN edge (Vercel / Cloudflare) which terminates TLS at the proxy edge.",
                status="info",
                styles=styles,
                width=page_width,
            ))
        flow.append(Spacer(1, 6))

        # 7. Technology Stack & Framework Signatures
        flow.append(Paragraph('<font color="#0284c7">▌</font> Technology Stack &amp; Signatures', styles["SecTitle"]))
        tech_list = url_ctx.get("url_tech_list") or []
        server_val = url_ctx.get("url_tech_server") or "Unknown"

        if server_val != "Unknown" or tech_list:
            from scanner.technology_detector import classify_technologies
            classified = classify_technologies(tech_list, server_val)

            tech_pairs = [("Web Server / Proxy", server_val)]
            for cat, items in classified.items():
                if items:
                    tech_pairs.append((cat, ", ".join(items)))
            flow.append(_build_key_value_table(tech_pairs, styles, page_width))
        else:
            flow.append(_build_info_callout(
                icon="ℹ",
                title="Server Technology Fingerprints Cloaked",
                message="HTTP response headers suppress backend server banner and runtime software versions. Server header cloaking reduces passive reconnaissance surface.",
                status="info",
                styles=styles,
                width=page_width,
            ))
        flow.append(Spacer(1, 6))

        # 8. WHOIS & Network Intelligence
        flow.append(Paragraph('<font color="#0284c7">▌</font> WHOIS &amp; Network Intelligence', styles["SecTitle"]))
        intel = url_ctx.get("url_intel")
        if intel and isinstance(intel, (dict, object)) and getattr(intel, "items", None):
            intel_dict = dict(intel) if hasattr(intel, "keys") else (intel if isinstance(intel, dict) else {})
            waf_val = intel_dict.get("waf") or "None Identified"
            if isinstance(waf_val, dict):
                waf_str = f"Active WAF ({waf_val.get('provider', 'Cloud Edge')})" if waf_val.get("detected") else "No WAF Detected"
            else:
                waf_str = str(waf_val)

            intel_pairs = [
                ("Registrar", intel_dict.get("registrar") or "—"),
                ("Domain Created", str(intel_dict.get("creation_date") or "—")),
                ("Domain Expires", str(intel_dict.get("expiration_date") or "—")),
                ("Hosting Country", intel_dict.get("country") or "Global Anycast"),
                ("Region / City", f"{intel_dict.get('region') or '—'} / {intel_dict.get('city') or '—'}"),
                ("ISP / Organization", intel_dict.get("isp") or "Cloud Provider"),
                ("Autonomous System (ASN)", str(intel_dict.get("asn") or "—")),
                ("WAF Perimeter Status", waf_str),
            ]
            flow.append(_build_key_value_table(intel_pairs, styles, page_width))
        else:
            flow.append(_build_info_callout(
                icon="ℹ",
                title="WHOIS Privacy Redaction & Anycast Routing",
                message="Target domain is deployed on an edge cloud deployment (vercel.app / cloudflare) utilizing distributed anycast DNS and private proxy routing.",
                status="info",
                styles=styles,
                width=page_width,
            ))
        flow.append(Spacer(1, 6))

        # 9. Host Findings (Ports, Services, Vulns, CVEs)
        if resolved_ip and resolved_ip != "Unknown":
            _findings_sections(flow, styles, findings, page_width)

        # 10. Recommended Hardening Actions
        flow.append(Paragraph('<font color="#0284c7">▌</font> Recommended Hardening Next Steps', styles["SecTitle"]))
        flow.append(_build_recommendations_section([], styles, page_width))

    doc.build(flow, canvasmaker=NumberedCanvas)
    return pdf_path, "CyberShield_URL_Scan_Report.pdf"


# ----------------------------------------------------------------------
# PDF Generator: Empty State Report
# ----------------------------------------------------------------------
def _build_empty_state_pdf():
    styles = _report_styles()
    page_width = A4[0] - 72
    pdf_path = os.path.join(BASE_DIR, "CyberShield_Report.pdf")
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title="CyberShieldAI Security Report",
    )
    doc.doc_target = "Security Report"

    flow = [
        _build_hero_header(
            title="CyberShieldAI Security Intelligence Report",
            subtitle="Automated Threat Detection & Vulnerability Assessment Platform",
            target_name="No Active Scan Found",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-EMPTY",
            styles=styles,
            width=page_width,
        ),
        Spacer(1, 14),
        _build_info_callout(
            icon="ℹ",
            title="No Scan Assessment Data Found",
            message="No IP or URL scans have been recorded in the database. Please initiate an automated scan from the CyberShieldAI Dashboard to generate a detailed vulnerability audit report.",
            status="info",
            styles=styles,
            width=page_width,
        ),
    ]
    doc.build(flow, canvasmaker=NumberedCanvas)
    return pdf_path, "CyberShield_Report.pdf"
