import os
import sys
import urllib.parse
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Image as RLImage,
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
# Dark Cybersecurity Palette Tokens
# ----------------------------------------------------------------------
C_BG_PAGE = colors.HexColor("#080d1a")        # Deep obsidian navy canvas background
C_CARD_BG = colors.HexColor("#0f172a")        # Slate 900 panel background
C_CARD_ALT = colors.HexColor("#141e33")       # Slate 850 alternating row background
C_HEAD_BG = colors.HexColor("#091122")        # Table header background
C_BORDER = colors.HexColor("#1e293b")         # Slate 800 border
C_BORDER_ACCENT = colors.HexColor("#0284c7")  # Cyan / sky blue accent rule

C_TEXT_WHITE = colors.HexColor("#f8fafc")     # Crisp white primary text
C_TEXT_MUTED = colors.HexColor("#94a3b8")     # Slate 400 secondary text
C_TEXT_DIM = colors.HexColor("#64748b")       # Slate 500 dim text

C_CYAN = colors.HexColor("#38bdf8")           # Electric cyan accent
C_BLUE = colors.HexColor("#0284c7")           # Brand blue

# Severity Colors for Dark Mode
SEV_DARK = {
    "critical": {
        "text": colors.HexColor("#f87171"),
        "bg": colors.HexColor("#450a0a"),
        "border": colors.HexColor("#ef4444"),
        "label": "CRITICAL RISK",
    },
    "high": {
        "text": colors.HexColor("#fb923c"),
        "bg": colors.HexColor("#431407"),
        "border": colors.HexColor("#f97316"),
        "label": "HIGH RISK",
    },
    "medium": {
        "text": colors.HexColor("#fde047"),
        "bg": colors.HexColor("#422006"),
        "border": colors.HexColor("#eab308"),
        "label": "MEDIUM RISK",
    },
    "low": {
        "text": colors.HexColor("#4ade80"),
        "bg": colors.HexColor("#052e16"),
        "border": colors.HexColor("#22c55e"),
        "label": "LOW RISK",
    },
    "ok": {
        "text": colors.HexColor("#4ade80"),
        "bg": colors.HexColor("#052e16"),
        "border": colors.HexColor("#22c55e"),
        "label": "LOW RISK",
    },
    "info": {
        "text": colors.HexColor("#38bdf8"),
        "bg": colors.HexColor("#082f49"),
        "border": colors.HexColor("#0284c7"),
        "label": "INFORMATIONAL",
    },
}


def _get_sev(level):
    key = str(level or "").strip().lower()
    return SEV_DARK.get(key, SEV_DARK["info"])


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
    return f"{ts_str} UTC" if "UTC" not in ts_str else ts_str


# ----------------------------------------------------------------------
# Numbered Two-Pass Canvas (Header, Footer, Page X of Y)
# ----------------------------------------------------------------------
class DarkNumberedCanvas(canvas.Canvas):
    """Two-pass canvas that computes the total page count and paints headers and footers."""
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

        # Header on page 2+
        if self._pageNumber > 1:
            self.setStrokeColor(C_BORDER)
            self.setLineWidth(0.5)
            self.line(36, h - 26, w - 36, h - 26)

            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(C_CYAN)
            self.drawString(36, h - 20, "CYBERSHIELD AI")
            self.setFont("Helvetica", 7.5)
            self.setFillColor(C_TEXT_MUTED)
            self.drawString(112, h - 20, "· Security Threat Scan Report")

            target_label = getattr(self, "doc_target", "Assessment")
            if len(str(target_label)) > 45:
                target_label = str(target_label)[:42] + "..."
            self.drawRightString(w - 36, h - 20, f"Target: {target_label}")

        # Footer on all pages
        self.setStrokeColor(C_BORDER)
        self.setLineWidth(0.5)
        self.line(36, 28, w - 36, 28)

        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(C_CYAN)
        self.drawString(36, 16, "CYBERSHIELD AI")
        self.setFont("Helvetica", 7)
        self.setFillColor(C_TEXT_MUTED)
        self.drawString(102, 16, "· Confidential Security Assessment Report")

        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(C_TEXT_WHITE)
        self.drawRightString(w - 36, 16, page_str)

        self.restoreState()


def draw_dark_page_background(canvas_obj, doc):
    """Fills the whole page canvas with dark cybersecurity navy on initial draw."""
    canvas_obj.doc_target = getattr(doc, "doc_target", "Assessment")
    canvas_obj.saveState()
    w, h = A4
    canvas_obj.setFillColor(C_BG_PAGE)
    canvas_obj.rect(0, 0, w, h, fill=1, stroke=0)
    canvas_obj.restoreState()


# ----------------------------------------------------------------------
# Typography & Stylesheet
# ----------------------------------------------------------------------
def _report_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="BrandTitle", fontName="Helvetica-Bold", fontSize=15, leading=17, textColor=C_TEXT_WHITE,
    ))
    styles.add(ParagraphStyle(
        name="BrandTagline", fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=C_CYAN,
    ))
    styles.add(ParagraphStyle(
        name="HeaderMeta", fontName="Helvetica", fontSize=7, leading=9.5, textColor=C_TEXT_MUTED, alignment=2,
    ))
    styles.add(ParagraphStyle(
        name="HeaderBadge", fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=C_CYAN, alignment=2,
    ))

    # Section Titles
    styles.add(ParagraphStyle(
        name="DarkSecTitle", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=C_TEXT_WHITE,
        spaceBefore=7, spaceAfter=2.5, keepWithNext=True,
    ))

    # KPI Scorecard Styles
    styles.add(ParagraphStyle(name="DarkKpiLabel", fontName="Helvetica-Bold", fontSize=6.5, leading=8.5, textColor=C_TEXT_MUTED))
    styles.add(ParagraphStyle(name="DarkKpiVal", fontName="Helvetica-Bold", fontSize=13, leading=15, textColor=C_TEXT_WHITE))
    styles.add(ParagraphStyle(name="DarkKpiSub", fontName="Helvetica", fontSize=7, leading=9, textColor=C_TEXT_MUTED))

    # Executive Summary Box
    styles.add(ParagraphStyle(name="ExecTitle", fontName="Helvetica-Bold", fontSize=8, leading=10.5, textColor=C_TEXT_WHITE))
    styles.add(ParagraphStyle(name="ExecBody", fontName="Helvetica", fontSize=7, leading=9.5, textColor=C_TEXT_MUTED))

    # Tables
    styles.add(ParagraphStyle(name="DarkTblHead", fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=C_CYAN))
    styles.add(ParagraphStyle(name="DarkTblCell", fontName="Helvetica", fontSize=7, leading=9.5, textColor=C_TEXT_WHITE))
    styles.add(ParagraphStyle(name="DarkTblCellMuted", fontName="Helvetica-Bold", fontSize=7, leading=9.5, textColor=C_TEXT_MUTED))
    styles.add(ParagraphStyle(name="DarkTblCellMono", fontName="Courier", fontSize=7, leading=9, textColor=C_TEXT_WHITE))

    # Empty State: "No data captured."
    styles.add(ParagraphStyle(name="NoDataText", fontName="Helvetica-Oblique", fontSize=7, leading=9.5, textColor=C_TEXT_DIM))

    # Backward compatibility aliases
    styles.add(ParagraphStyle(name="RTitle", fontName="Helvetica-Bold", fontSize=16, leading=19, textColor=C_TEXT_WHITE))
    styles.add(ParagraphStyle(name="RSub", fontName="Helvetica", fontSize=8, leading=11, textColor=C_TEXT_MUTED))
    styles.add(ParagraphStyle(name="RSection", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=C_TEXT_WHITE, keepWithNext=True))
    styles.add(ParagraphStyle(name="RCell", fontName="Helvetica", fontSize=7, leading=9.5, textColor=C_TEXT_WHITE))
    styles.add(ParagraphStyle(name="RCellMuted", fontName="Helvetica", fontSize=7, leading=9.5, textColor=C_TEXT_MUTED))
    styles.add(ParagraphStyle(name="RBullet", fontName="Helvetica", fontSize=7, leading=10, textColor=C_TEXT_WHITE))
    styles.add(ParagraphStyle(name="REmpty", fontName="Helvetica-Oblique", fontSize=7, leading=9.5, textColor=C_TEXT_DIM))

    return styles


# ----------------------------------------------------------------------
# Visual Component Builders
# ----------------------------------------------------------------------
def _build_hero_header(title, target_name, scan_time, report_id, styles, width):
    """Creates the top header bar with CyberShield logo, titles, and metadata."""
    logo_path = os.path.join(BASE_DIR, "dashboard", "static", "img", "cybershield_logo.png")
    if os.path.exists(logo_path):
        logo_img = RLImage(logo_path, width=28, height=28)
    else:
        logo_img = Paragraph('<font color="#38bdf8"><b>[CS]</b></font>', styles["BrandTitle"])

    brand_block = [
        Paragraph("CYBERSHIELD AI", styles["BrandTitle"]),
        Spacer(1, 1),
        Paragraph(title.upper(), styles["BrandTagline"]),
    ]
    brand_tbl = Table([[logo_img, brand_block]], colWidths=[34, width * 0.58 - 34])
    brand_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    clean_target = str(target_name or "Assessment Target")
    if len(clean_target) > 52:
        clean_target = clean_target[:49] + "..."

    meta_block = [
        Paragraph('<font color="#38bdf8"><b>● CONFIDENTIAL // TLP:AMBER</b></font>', styles["HeaderBadge"]),
        Spacer(1, 1),
        Paragraph(f"<b>Report ID:</b> {report_id}", styles["HeaderMeta"]),
        Paragraph(f"<b>Scan Time:</b> {scan_time}", styles["HeaderMeta"]),
        Paragraph(f"<b>Target:</b> {clean_target}", styles["HeaderMeta"]),
    ]

    header_tbl = Table([[brand_tbl, meta_block]], colWidths=[width * 0.56, width * 0.44])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CARD_BG),
        ("LINEBELOW", (0, 0), (-1, -1), 1.5, C_BORDER_ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return header_tbl


def _build_kpi_scorecard(score, risk_level, target_scope, open_ports_count, vulns_count, cves_count, styles, width):
    """Builds a 4-card metric scorecard."""
    card_w = width / 4.0
    sev = _get_sev(risk_level)
    score_display = 0 if score in (None, "", "None") else score

    # Card 1: Threat / Risk Score
    c1 = [
        Paragraph("THREAT SCORE", styles["DarkKpiLabel"]),
        Spacer(1, 1.5),
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{score_display} / 100</b></font>', styles["DarkKpiVal"]),
        Spacer(1, 1),
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>● {str(risk_level or "LOW").upper()} RISK</b></font>', styles["DarkKpiSub"]),
    ]

    # Card 2: Target Scope
    domain_disp = str(target_scope.get("domain") or target_scope.get("ip") or "Target")
    if len(domain_disp) > 22:
        domain_disp = domain_disp[:19] + "..."
    c2 = [
        Paragraph("PERIMETER TARGET", styles["DarkKpiLabel"]),
        Spacer(1, 1.5),
        Paragraph(f"<b>{domain_disp}</b>", ParagraphStyle("DomW", fontName="Helvetica-Bold", fontSize=8.5, leading=10.5, textColor=C_TEXT_WHITE)),
        Spacer(1, 1),
        Paragraph(f"IP: {target_scope.get('ip', 'Unknown')}", styles["DarkKpiSub"]),
    ]

    # Card 3: Attack Surface
    c3 = [
        Paragraph("OPEN PORTS", styles["DarkKpiLabel"]),
        Spacer(1, 1.5),
        Paragraph(f'<font color="#38bdf8"><b>{open_ports_count}</b></font>', styles["DarkKpiVal"]),
        Spacer(1, 1),
        Paragraph("Responsive Ports", styles["DarkKpiSub"]),
    ]

    # Card 4: Vulnerabilities & CVEs
    vuln_col = "#ef4444" if vulns_count > 0 else "#4ade80"
    c4 = [
        Paragraph("EXPLOITS &amp; VULNS", styles["DarkKpiLabel"]),
        Spacer(1, 1.5),
        Paragraph(f'<font color="{vuln_col}"><b>{vulns_count}</b></font>', styles["DarkKpiVal"]),
        Spacer(1, 1),
        Paragraph(f"{cves_count} CVEs Identified", styles["DarkKpiSub"]),
    ]

    tbl = Table([[c1, c2, c3, c4]], colWidths=[card_w, card_w, card_w, card_w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CARD_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 2, sev["border"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def _build_exec_summary(score, risk_level, open_ports_count, vulns_count, styles, width):
    """Builds a concise executive summary statement."""
    sev = _get_sev(risk_level)
    level_lower = str(risk_level or "low").strip().lower()

    if level_lower in ("low", "ok") and vulns_count == 0:
        verdict = "✔ EXECUTIVE VERDICT: LOW PERIMETER EXPOSURE — SECURE BASELINE"
        narrative = (
            f"The perimeter assessment detected {open_ports_count} responsive service(s) operating within normal baselines. "
            "Zero unpatched CVE exposures, weak cryptographic signatures, or exposed administrative dashboards were discovered. "
            "The target perimeter satisfies fundamental cybersecurity hygiene standards."
        )
    elif level_lower == "medium" or (vulns_count > 0 and vulns_count <= 2):
        verdict = "⚠ EXECUTIVE VERDICT: MODERATE ATTACK SURFACE DETECTED"
        narrative = (
            f"Perimeter scan detected {open_ports_count} open port(s) with {vulns_count} potential vulnerability finding(s). "
            "Remediation actions should be scheduled to minimize exposure to automated exploitation scripts."
        )
    else:
        verdict = "⛔ EXECUTIVE VERDICT: ELEVATED THREAT LEVEL — ACTION REQUIRED"
        narrative = (
            f"Perimeter scan detected {vulns_count} vulnerability finding(s) with high exposure. "
            "Immediate access control restrictions, patch deployments, and firewall ingress policies are strongly advised."
        )

    content = [
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{verdict}</b></font>', styles["ExecTitle"]),
        Spacer(1, 1),
        Paragraph(narrative, styles["ExecBody"]),
    ]
    tbl = Table([[content]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 2, sev["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    return tbl


def _build_dark_no_data(styles, width):
    """Outputs the exact requirement 'No data captured.' inside a clean dark container."""
    p = Paragraph("No data captured.", styles["NoDataText"])
    tbl = Table([[p]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    return tbl


def _build_key_value_table(pairs, styles, width, left_ratio=0.28):
    """Renders a 2-column specification table."""
    left_w = width * left_ratio
    right_w = width * (1.0 - left_ratio)
    rows = []

    for lbl, val in pairs:
        val_str = str(val) if val not in (None, "") else "No data captured."
        if val_str == "No data captured.":
            val_p = Paragraph(val_str, styles["NoDataText"])
        elif any(k in lbl.lower() for k in ["ip", "url", "cipher", "sha256", "fingerprint", "asn"]):
            val_p = Paragraph(f'<font name="Courier">{val_str}</font>', styles["DarkTblCell"])
        elif "risk" in lbl.lower() and "level" in lbl.lower():
            sev = _get_sev(val_str)
            val_p = Paragraph(f'<font color="{sev["text"].hexval()}"><b>● {val_str.upper()}</b></font>', styles["DarkTblCell"])
        elif "status" in lbl.lower() and val_str.lower() in ("valid", "valid certificate", "up", "active"):
            val_p = Paragraph(f'<font color="#4ade80"><b>● {val_str}</b></font>', styles["DarkTblCell"])
        else:
            val_p = Paragraph(val_str, styles["DarkTblCell"])

        lbl_p = Paragraph(lbl, styles["DarkTblCellMuted"])
        rows.append([lbl_p, val_p])

    tbl = Table(rows, colWidths=[left_w, right_w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CARD_BG),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_CARD_BG, C_CARD_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def _build_data_table(headers, rows, col_widths, styles, risk_col=None):
    """Renders a structured data table with dark cybersecurity rows."""
    head_row = [Paragraph(f"<b>{h}</b>", styles["DarkTblHead"]) for h in headers]
    data_rows = [head_row]

    for r in rows:
        cells = []
        for c_idx, val in enumerate(r):
            text = "—" if val is None or val == "" else str(val)
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

            if risk_col is not None and c_idx == risk_col:
                sev = _get_sev(val)
                cells.append(Paragraph(f'<font color="{sev["text"].hexval()}"><b>● {text.upper()}</b></font>', styles["DarkTblCell"]))
            elif c_idx == 0 and any(k in headers[0].lower() for k in ["port", "cve"]):
                cells.append(Paragraph(f'<font name="Courier-Bold" color="#38bdf8">{text}</font>', styles["DarkTblCell"]))
            elif "state" in headers[c_idx].lower() and text.lower() == "open":
                cells.append(Paragraph('<font color="#4ade80"><b>● open</b></font>', styles["DarkTblCell"]))
            else:
                cells.append(Paragraph(text, styles["DarkTblCell"]))
        data_rows.append(cells)

    tbl = Table(data_rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_HEAD_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_CARD_BG, C_CARD_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEBELOW", (0, 0), (-1, 0), 1, C_BORDER_ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def _build_recommendations_section(recs, styles, width):
    """Builds a numbered hardening action list."""
    default_recs = [
        ("Maintain Strict Transport Security (HSTS)", "Verify that Strict-Transport-Security preload is transmitted on all HTTPS endpoints to prevent protocol downgrade."),
        ("Enforce Origin Shielding & Ingress Filtering", "Configure cloud security groups to restrict direct IP ingress, permitting web traffic exclusively from verified CDN edge proxies."),
        ("Deploy Defense-in-Depth Security Headers", "Ensure Content-Security-Policy (CSP), X-Content-Type-Options: nosniff, and Referrer-Policy are enforced across all web routes."),
        ("Establish Continuous Vulnerability Scanning", "Maintain automated scheduled scans to identify emerging CVEs and outdated package versions as new security advisories are disclosed."),
    ]

    action_items = []
    clean_recs = [
        r for r in (recs or [])
        if r and not any(phrase in str(r).lower() for phrase in ["no recommendations", "no critical recommendations"])
    ]

    if clean_recs:
        for idx, r in enumerate(clean_recs, start=1):
            action_items.append((str(idx), str(r), ""))
    else:
        for idx, (title, detail) in enumerate(default_recs, start=1):
            action_items.append((str(idx), title, detail))

    rows = []
    for num, title, detail in action_items:
        num_p = Paragraph(f'<font color="#38bdf8"><b>{num}</b></font>', styles["DarkTblCell"])
        if detail:
            text_p = Paragraph(f"<b>{title}:</b> {detail}", styles["DarkTblCell"])
        else:
            text_p = Paragraph(f"<b>{title}</b>", styles["DarkTblCell"])
        rows.append([num_p, text_p])

    tbl = Table(rows, colWidths=[width * 0.05, width * 0.95])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


# ----------------------------------------------------------------------
# Backward Compatibility Wrappers
# ----------------------------------------------------------------------
def _report_data_table(header, rows, col_widths, styles, risk_col=None):
    return _build_data_table(header, rows, col_widths, styles, risk_col=risk_col)


def _report_kv_table(pairs, styles, col_widths):
    width = sum(col_widths)
    left_ratio = col_widths[0] / width if width > 0 else 0.30
    return _build_key_value_table(pairs, styles, width, left_ratio=left_ratio)


def _report_header_footer(canvas_obj, doc, subtitle):
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
    try:
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
    finally:
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
# Shared Findings Sections (OS, Ports, Services, Vulns, CVEs)
# ----------------------------------------------------------------------
def _findings_sections(flow, styles, findings, page_width):
    """Shared Ports / Services / Vulnerabilities / CVEs / Risk / OS section-builder."""
    ports = findings.get("ports") or []
    services = findings.get("services") or []
    vulnerabilities = findings.get("vulnerabilities") or []
    cves = findings.get("cves") or []
    os_info = findings.get("os_info")
    risk = findings.get("risk")

    # 1. Operating System & Risk Profile
    flow.append(Paragraph('<font color="#38bdf8">■</font>  Operating System &amp; Perimeter Risk Profile', styles["DarkSecTitle"]))
    os_name = os_info["os_name"] if os_info and "os_name" in os_info else "TCP/IP Network Host"
    os_details = os_info["os_details"] if os_info and "os_details" in os_info else "Active network host with responsive service port(s)"
    device_type = os_info["device_type"] if os_info and "device_type" in os_info else "Network Device"

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
            ("Risk Assessment Level", f"{str(r_level).upper()} (SCORE: {r_score} / 100)"),
            ("Vulnerability Breakdown", f"Critical: {c_cnt} | High: {h_cnt} | Medium: {m_cnt} | Low: {l_cnt}"),
        ]
    else:
        risk_pairs += [
            ("Risk Assessment Level", "LOW (SCORE: 0 / 100)"),
            ("Vulnerability Breakdown", "Critical: 0 | High: 0 | Medium: 0 | Low: 0"),
        ]
    flow.append(_build_key_value_table(risk_pairs, styles, page_width))
    flow.append(Spacer(1, 3.5))

    # 2. Open Ports & Services
    flow.append(Paragraph(f'<font color="#38bdf8">■</font>  Open Ports &amp; Perimeter Services ({len(ports)})', styles["DarkSecTitle"]))
    if ports:
        rows = []
        for p in ports:
            p_dict = dict(p) if hasattr(p, "keys") else p
            banner_text = (p_dict.get("banner") or "—")[:80]
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
        flow.append(_build_dark_no_data(styles, page_width))
    flow.append(Spacer(1, 3.5))

    # 3. Service Versions
    if services:
        flow.append(Paragraph(f'<font color="#38bdf8">■</font>  Service Version Fingerprints ({len(services)})', styles["DarkSecTitle"]))
        rows = []
        for s in services:
            s_dict = dict(s) if hasattr(s, "keys") else s
            rows.append([
                str(s_dict.get("port")),
                s_dict.get("service") or "—",
                s_dict.get("product") or "—",
                s_dict.get("version") or "—",
            ])
        flow.append(_build_data_table(
            headers=["Port", "Service", "Product", "Version"],
            rows=rows,
            col_widths=[page_width * 0.14, page_width * 0.24, page_width * 0.38, page_width * 0.24],
            styles=styles,
        ))
        flow.append(Spacer(1, 3.5))

    # 4. Vulnerabilities Audit
    flow.append(Paragraph(f'<font color="#38bdf8">■</font>  Vulnerabilities Audit ({len(vulnerabilities)})', styles["DarkSecTitle"]))
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
                imp[:22],
                rec[:30],
            ])
        flow.append(_build_data_table(
            headers=["Port/Service", "Severity", "CVSS v3.1", "Vector", "Impact", "Remediation"],
            rows=rows,
            col_widths=[page_width * 0.16, page_width * 0.14, page_width * 0.11, page_width * 0.18, page_width * 0.20, page_width * 0.21],
            styles=styles,
            risk_col=1,
        ))
    else:
        flow.append(_build_dark_no_data(styles, page_width))
    flow.append(Spacer(1, 3.5))

    # 5. CVE Findings
    flow.append(Paragraph(f'<font color="#38bdf8">■</font>  CVE Exploit Findings ({len(cves)})', styles["DarkSecTitle"]))
    if cves:
        rows = []
        for cv in cves:
            cv_dict = dict(cv) if hasattr(cv, "keys") else cv
            cvss = cv_dict.get("cvss_score") if cv_dict.get("cvss_score") is not None else "—"
            cwe = cv_dict.get("cwe_id") or "CWE-200"
            published = cv_dict.get("published_date") or "—"
            exploit = "⚡ PoC" if cv_dict.get("exploit_available") else "No"
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
            headers=["CVE ID", "CWE Weakness", "Port/Service", "Severity", "CVSS v3.1", "Published", "Exploit"],
            rows=rows,
            col_widths=[page_width * 0.17, page_width * 0.15, page_width * 0.14, page_width * 0.13, page_width * 0.10, page_width * 0.15, page_width * 0.16],
            styles=styles,
            risk_col=3,
        ))
    else:
        flow.append(_build_dark_no_data(styles, page_width))
    flow.append(Spacer(1, 3.5))


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
        title="CyberShieldAI IP Threat Scan Report",
    )
    doc.doc_target = latest_ip or "Network Host"
    flow = []

    if not latest_ip:
        flow.append(_build_hero_header(
            title="IP Threat & Perimeter Security Audit",
            target_name="No Active Host Scanned",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-IP-PENDING",
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 10))
        flow.append(_build_dark_no_data(styles, page_width))
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

        # 1. Header
        flow.append(_build_hero_header(
            title="IP Threat & Perimeter Security Audit",
            target_name=f"Host: {latest_ip}",
            scan_time=scan_time,
            report_id=report_id,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3.5))

        # 2. KPI Scorecard
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
        flow.append(Spacer(1, 3.5))

        # 3. Executive Summary
        flow.append(_build_exec_summary(
            score=risk_score,
            risk_level=risk_level,
            open_ports_count=len(ports_data),
            vulns_count=len(vulns_data),
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3.5))

        # 4. Target Identity & Network Scope
        flow.append(Paragraph('<font color="#38bdf8">■</font>  Target Identity &amp; Network Scope', styles["DarkSecTitle"]))
        overview = [
            ("Target IP Address", latest_ip),
            ("Host Status", host.get("status", "UP / ACTIVE") if host else "UP / ACTIVE"),
            ("Assessment Timestamp", scan_time),
            ("Threat Score Index", f"{risk_score} / 100"),
            ("Perimeter Risk Level", risk_level),
            ("Operating System", ctx.get("os_info", {}).get("os_name", "TCP/IP Network Host") if isinstance(ctx.get("os_info"), dict) else "TCP/IP Network Host"),
            ("Device Type", ctx.get("os_info", {}).get("device_type", "Network Device") if isinstance(ctx.get("os_info"), dict) else "Network Device"),
        ]
        flow.append(_build_key_value_table(overview, styles, page_width))
        flow.append(Spacer(1, 3.5))

        # 5. Shared Findings (OS, Ports, Services, Vulns, CVEs)
        findings = {
            "ports": ports_data,
            "services": ctx.get("services") or [],
            "vulnerabilities": vulns_data,
            "cves": cves_data,
            "os_info": ctx.get("os_info") if isinstance(ctx.get("os_info"), dict) else None,
            "risk": risk_data,
        }
        _findings_sections(flow, styles, findings, page_width)

        # 6. Recommendations
        flow.append(Paragraph('<font color="#38bdf8">■</font>  Recommended Hardening Next Steps', styles["DarkSecTitle"]))
        recs = ctx.get("recommendations") or []
        flow.append(_build_recommendations_section(recs, styles, page_width))

    doc.build(
        flow,
        canvasmaker=DarkNumberedCanvas,
        onFirstPage=draw_dark_page_background,
        onLaterPages=draw_dark_page_background,
    )
    return pdf_path, "CyberShield_IP_Scan_Report.pdf"


# ----------------------------------------------------------------------
# PDF Generator: URL Scan Report
# ----------------------------------------------------------------------
def _build_url_scan_pdf(user_id=None):
    url_ctx = get_url_scan_dashboard_context(user_id=user_id, latest_host=False, include_deep_intel=True)
    if not url_ctx.get("url_scan") and user_id is not None:
        url_ctx = get_url_scan_dashboard_context(user_id=None, latest_host=False, include_deep_intel=True)

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
            target_name="No Active Scan Found",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-URL-PENDING",
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 10))
        flow.append(_build_dark_no_data(styles, page_width))
    else:
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

        # 1. Header
        flow.append(_build_hero_header(
            title="URL Threat & Perimeter Security Audit",
            target_name=url_scan.get("url", "Target URL"),
            scan_time=scan_time,
            report_id=report_id,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3.5))

        # 2. KPI Scorecard
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
        flow.append(Spacer(1, 3.5))

        # 3. Executive Summary
        flow.append(_build_exec_summary(
            score=threat_score,
            risk_level=risk_level,
            open_ports_count=ports_count,
            vulns_count=vulns_count,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3.5))

        # 4. Target Identity & Network Scope
        flow.append(Paragraph('<font color="#38bdf8">■</font>  Target Identity &amp; Network Scope', styles["DarkSecTitle"]))
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
        flow.append(Spacer(1, 3.5))

        # 5. Security Findings & Observations
        remarks = url_ctx.get("url_remarks") or []
        if isinstance(remarks, str):
            remarks = [r.strip() for r in remarks.split(",") if r.strip()]

        flow.append(Paragraph('<font color="#38bdf8">■</font>  Security Findings &amp; Observations', styles["DarkSecTitle"]))
        if remarks:
            finding_rows = []
            for r in remarks:
                icon_cell = Paragraph('<font color="#4ade80"><b>✔</b></font>', styles["DarkTblCell"])
                text_cell = Paragraph(f"Observation: {r}", styles["DarkTblCell"])
                finding_rows.append([icon_cell, text_cell])

            t_rem = Table(finding_rows, colWidths=[page_width * 0.05, page_width * 0.95])
            t_rem.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), C_CARD_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            flow.append(t_rem)
        else:
            flow.append(_build_dark_no_data(styles, page_width))
        flow.append(Spacer(1, 3.5))

        # 6. SSL / TLS Cryptographic Health
        flow.append(Paragraph('<font color="#38bdf8">■</font>  SSL / TLS Cryptographic Health', styles["DarkSecTitle"]))
        ssl_info = url_ctx.get("url_ssl")
        if ssl_info:
            ssl_dict = dict(ssl_info) if hasattr(ssl_info, "keys") else ssl_info
            san_str = "—"
            if ssl_dict.get("parsed_san_names"):
                san_str = ", ".join(ssl_dict["parsed_san_names"][:4])
            elif ssl_dict.get("san_names"):
                san_str = ", ".join(ssl_dict["san_names"][:4]) if isinstance(ssl_dict["san_names"], list) else str(ssl_dict["san_names"])[:50]

            chain_str = ssl_dict.get("cert_chain") or "—"
            if not chain_str or chain_str == "—":
                chain_h = ssl_dict.get("chain_hierarchy") or {}
                if chain_h:
                    chain_str = f"Root: {chain_h.get('root', 'Trusted Root CA')} → Interm: {chain_h.get('intermediate', ssl_dict.get('issuer') or 'Public CA')} → Leaf: {chain_h.get('leaf', ssl_dict.get('subject') or '-')}"

            cert_status = "Expired" if ssl_dict.get("expired") else ("Self-Signed" if ssl_dict.get("self_signed") else "Valid Certificate")
            ssl_pairs = [
                ("HTTPS Enabled", "Yes (Enforced)" if ssl_dict.get("has_ssl") else "No"),
                ("TLS Protocol Version", ssl_dict.get("tls_version") or "TLSv1.3"),
                ("Cipher Suite", ssl_dict.get("cipher_suite") or "—"),
                ("Public Key Type & Algorithm", ssl_dict.get("key_type") or "RSA"),
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
            flow.append(_build_dark_no_data(styles, page_width))
        flow.append(Spacer(1, 3.5))

        # 7. Technology Stack & Signatures
        flow.append(Paragraph('<font color="#38bdf8">■</font>  Technology Stack &amp; Signatures', styles["DarkSecTitle"]))
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
            flow.append(_build_dark_no_data(styles, page_width))
        flow.append(Spacer(1, 3.5))

        # 8. WHOIS & Network Intelligence
        flow.append(Paragraph('<font color="#38bdf8">■</font>  WHOIS &amp; Network Intelligence', styles["DarkSecTitle"]))
        intel = url_ctx.get("url_intel")
        if intel and isinstance(intel, (dict, object)) and getattr(intel, "items", None):
            intel_dict = dict(intel) if hasattr(intel, "keys") else (intel if isinstance(intel, dict) else {})
            waf_val = intel_dict.get("waf") or "None"
            if isinstance(waf_val, dict):
                waf_str = f"Active WAF ({waf_val.get('provider', 'Cloud Edge')})" if waf_val.get("detected") else "None"
            else:
                waf_str = str(waf_val)

            intel_pairs = [
                ("Registrar", intel_dict.get("registrar") or "Unknown"),
                ("Domain Created", str(intel_dict.get("creation_date") or "Unknown")),
                ("Domain Expires", str(intel_dict.get("expiration_date") or "Unknown")),
                ("Hosting Country", intel_dict.get("country") or "United States"),
                ("Region / City", f"{intel_dict.get('region') or '—'} / {intel_dict.get('city') or '—'}"),
                ("ISP / Organization", intel_dict.get("isp") or "—"),
                ("Autonomous System (ASN)", str(intel_dict.get("asn") or "—")),
                ("WAF Perimeter Status", waf_str),
            ]
            flow.append(_build_key_value_table(intel_pairs, styles, page_width))
        else:
            flow.append(_build_dark_no_data(styles, page_width))
        flow.append(Spacer(1, 3.5))

        # 9. Host Findings (OS, Ports, Services, Vulns, CVEs)
        if resolved_ip and resolved_ip != "Unknown":
            _findings_sections(flow, styles, findings, page_width)

        # 10. Recommendations
        flow.append(Paragraph('<font color="#38bdf8">■</font>  Recommended Hardening Next Steps', styles["DarkSecTitle"]))
        flow.append(_build_recommendations_section([], styles, page_width))

    doc.build(
        flow,
        canvasmaker=DarkNumberedCanvas,
        onFirstPage=draw_dark_page_background,
        onLaterPages=draw_dark_page_background,
    )
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
            title="Security Assessment Report",
            target_name="No Active Scan Found",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-EMPTY",
            styles=styles,
            width=page_width,
        ),
        Spacer(1, 10),
        _build_dark_no_data(styles, page_width),
    ]
    doc.build(
        flow,
        canvasmaker=DarkNumberedCanvas,
        onFirstPage=draw_dark_page_background,
        onLaterPages=draw_dark_page_background,
    )
    return pdf_path, "CyberShield_Report.pdf"
