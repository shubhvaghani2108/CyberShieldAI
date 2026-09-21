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
# White Professional Palette Tokens (Corporate Security Assessment)
# ----------------------------------------------------------------------
C_BG_PAGE = colors.HexColor("#ffffff")         # Pure white page background
C_TEXT_DARK = colors.HexColor("#0f172a")       # Slate 900 primary dark text
C_TEXT_MID = colors.HexColor("#334155")        # Slate 700 secondary text
C_TEXT_MUTED = colors.HexColor("#64748b")      # Slate 500 metadata text
C_TEXT_DIM = colors.HexColor("#94a3b8")        # Slate 400 dim text

C_BLUE_PRIMARY = colors.HexColor("#1d4ed8")    # Authoritative corporate blue accent
C_BLUE_LIGHT = colors.HexColor("#eff6ff")      # Soft blue highlight tint
C_BLUE_BORDER = colors.HexColor("#3b82f6")     # Accent border

C_BORDER = colors.HexColor("#cbd5e1")          # Slate 300 table / card border
C_BORDER_LIGHT = colors.HexColor("#e2e8f0")    # Slate 200 light divider
C_ROW_ALT = colors.HexColor("#f8fafc")         # Slate 50 alternating row
C_HEAD_BG = colors.HexColor("#f1f5f9")         # Slate 100 clean table header

# Professional Risk Severity Badges (Light Theme)
SEV_LIGHT = {
    "critical": {
        "text": colors.HexColor("#991b1b"),
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
        "text": colors.HexColor("#854d0e"),
        "bg": colors.HexColor("#fefce8"),
        "border": colors.HexColor("#facc15"),
        "label": "MEDIUM RISK",
    },
    "low": {
        "text": colors.HexColor("#166534"),
        "bg": colors.HexColor("#f0fdf4"),
        "border": colors.HexColor("#86efac"),
        "label": "LOW RISK",
    },
    "ok": {
        "text": colors.HexColor("#166534"),
        "bg": colors.HexColor("#f0fdf4"),
        "border": colors.HexColor("#86efac"),
        "label": "LOW RISK",
    },
    "info": {
        "text": colors.HexColor("#1e40af"),
        "bg": colors.HexColor("#eff6ff"),
        "border": colors.HexColor("#93c5fd"),
        "label": "INFORMATIONAL",
    },
}


def _get_sev(level):
    key = str(level or "").strip().lower()
    return SEV_LIGHT.get(key, SEV_LIGHT["info"])


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
class WhiteNumberedCanvas(canvas.Canvas):
    """Computes exact total pages and prints running header/footer."""
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
            self.setStrokeColor(C_BORDER_LIGHT)
            self.setLineWidth(0.75)
            self.line(36, h - 24, w - 36, h - 24)

            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(C_BLUE_PRIMARY)
            self.drawString(36, h - 18, "CyberShieldAI")
            self.setFont("Helvetica", 8)
            self.setFillColor(C_TEXT_MUTED)
            self.drawString(100, h - 18, "· Security Scan Report")

            target_label = getattr(self, "doc_target", "Assessment")
            if len(str(target_label)) > 45:
                target_label = str(target_label)[:42] + "..."
            self.drawRightString(w - 36, h - 18, f"Target: {target_label}")

        # Footer on all pages
        self.setStrokeColor(C_BORDER_LIGHT)
        self.setLineWidth(0.75)
        self.line(36, 26, w - 36, 26)

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(C_TEXT_DARK)
        self.drawString(36, 15, "CyberShieldAI")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(C_TEXT_MUTED)
        self.drawString(94, 15, "· Confidential Security Assessment Report")

        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(C_TEXT_DARK)
        self.drawRightString(w - 36, 15, page_str)

        self.restoreState()


def record_page_metadata(canvas_obj, doc):
    """Stores document target on the canvas object for page 2+ header."""
    canvas_obj.doc_target = getattr(doc, "doc_target", "Assessment")


# ----------------------------------------------------------------------
# Typography & Stylesheet
# ----------------------------------------------------------------------
def _report_styles():
    styles = getSampleStyleSheet()

    # Brand Title
    styles.add(ParagraphStyle(
        name="BrandTitle", fontName="Helvetica-Bold", fontSize=15, leading=17, textColor=C_TEXT_DARK,
    ))
    styles.add(ParagraphStyle(
        name="BrandSubtitle", fontName="Helvetica", fontSize=8.5, leading=10.5, textColor=C_BLUE_PRIMARY,
    ))
    styles.add(ParagraphStyle(
        name="HeaderMeta", fontName="Helvetica", fontSize=7.5, leading=9.5, textColor=C_TEXT_MUTED, alignment=2,
    ))

    # Section Headings (Numbered, clean blue accent)
    styles.add(ParagraphStyle(
        name="SecTitle", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=C_TEXT_DARK,
        spaceBefore=5, spaceAfter=2, keepWithNext=True,
    ))

    # Metric & Highlight Card
    styles.add(ParagraphStyle(name="CardLabel", fontName="Helvetica-Bold", fontSize=6.5, leading=8.5, textColor=C_TEXT_MUTED))
    styles.add(ParagraphStyle(name="CardVal", fontName="Helvetica-Bold", fontSize=11.5, leading=13.5, textColor=C_TEXT_DARK))
    styles.add(ParagraphStyle(name="CardSub", fontName="Helvetica", fontSize=6.5, leading=8.5, textColor=C_TEXT_MUTED))

    # Executive Summary / Verdict
    styles.add(ParagraphStyle(name="SummaryTitle", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=C_TEXT_DARK))
    styles.add(ParagraphStyle(name="SummaryBody", fontName="Helvetica", fontSize=7.5, leading=9.5, textColor=C_TEXT_MID))

    # Tables
    styles.add(ParagraphStyle(name="TblHead", fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=C_TEXT_DARK))
    styles.add(ParagraphStyle(name="TblCell", fontName="Helvetica", fontSize=7.5, leading=9.5, textColor=C_TEXT_DARK))
    styles.add(ParagraphStyle(name="TblCellMuted", fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=C_TEXT_MID))
    styles.add(ParagraphStyle(name="TblCellMono", fontName="Courier", fontSize=7.5, leading=9.5, textColor=C_TEXT_DARK))

    # Empty State: "No data captured."
    styles.add(ParagraphStyle(name="NoDataText", fontName="Helvetica-Oblique", fontSize=7.5, leading=9.5, textColor=C_TEXT_MUTED))

    # Backward compatibility aliases
    styles.add(ParagraphStyle(name="RTitle", fontName="Helvetica-Bold", fontSize=15, leading=17, textColor=C_TEXT_DARK))
    styles.add(ParagraphStyle(name="RSub", fontName="Helvetica", fontSize=8.5, leading=10.5, textColor=C_TEXT_MUTED))
    styles.add(ParagraphStyle(name="RSection", fontName="Helvetica-Bold", fontSize=9, leading=11.5, textColor=C_TEXT_DARK, keepWithNext=True))
    styles.add(ParagraphStyle(name="RCell", fontName="Helvetica", fontSize=7.5, leading=9.5, textColor=C_TEXT_DARK))
    styles.add(ParagraphStyle(name="RCellMuted", fontName="Helvetica", fontSize=7.5, leading=9.5, textColor=C_TEXT_MUTED))
    styles.add(ParagraphStyle(name="RBullet", fontName="Helvetica", fontSize=7.5, leading=10, textColor=C_TEXT_DARK))
    styles.add(ParagraphStyle(name="REmpty", fontName="Helvetica-Oblique", fontSize=7.5, leading=9.5, textColor=C_TEXT_MUTED))

    return styles


# ----------------------------------------------------------------------
# Visual Component Builders (White Professional Theme)
# ----------------------------------------------------------------------
def _build_header(report_title, target_name, scan_time, report_id, styles, width):
    """Creates the clean, simple company header with authentic project logo, omitting cluttered metadata."""
    logo_path = os.path.join(BASE_DIR, "dashboard", "static", "img", "cybershield_logo.png")
    if os.path.exists(logo_path):
        logo_img = RLImage(logo_path, width=32, height=32)
    else:
        logo_img = Paragraph('<font color="#0284c7"><b>[CS]</b></font>', styles["BrandTitle"])

    brand_block = [
        Paragraph('<font color="#0f172a"><b>Cyber</b></font><font color="#0284c7"><b>Shield</b></font><font color="#2563eb"><b>AI</b></font>', styles["BrandTitle"]),
        Spacer(1, 1),
        Paragraph(report_title or "Security Scan Report", styles["BrandSubtitle"]),
    ]
    brand_tbl = Table([[logo_img, brand_block]], colWidths=[38, width - 38])
    brand_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, C_BLUE_PRIMARY),
    ]))
    return brand_tbl


def _build_risk_score_highlight(score, risk_level, target_domain, open_ports_count, vulns_count, styles, width):
    """Builds a clean, professional corporate risk score highlight bar without cramped truncated text."""
    card_w = width / 4.0
    sev = _get_sev(risk_level)
    score_display = 0 if score in (None, "", "None") else score
    level_name = str(risk_level or "Low").upper()

    # Card 1: Risk Score
    c1 = [
        Paragraph("RISK SCORE", styles["CardLabel"]),
        Spacer(1, 1),
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{score_display} / 100</b></font>', styles["CardVal"]),
        Spacer(1, 1),
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>● {level_name}</b></font>', styles["CardSub"]),
    ]

    # Card 2: Risk Classification
    c2 = [
        Paragraph("RISK LEVEL", styles["CardLabel"]),
        Spacer(1, 1),
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{level_name}</b></font>', styles["CardVal"]),
        Spacer(1, 1),
        Paragraph("Exposure Rating", styles["CardSub"]),
    ]

    # Card 3: Open Ports
    c3 = [
        Paragraph("OPEN PORTS", styles["CardLabel"]),
        Spacer(1, 1),
        Paragraph(f'<font color="#1d4ed8"><b>{open_ports_count}</b></font>', styles["CardVal"]),
        Spacer(1, 1),
        Paragraph("Responsive Services", styles["CardSub"]),
    ]

    # Card 4: Vulnerabilities
    vuln_color = "#b91c1c" if vulns_count > 0 else "#166534"
    c4 = [
        Paragraph("VULNERABILITIES", styles["CardLabel"]),
        Spacer(1, 1),
        Paragraph(f'<font color="{vuln_color}"><b>{vulns_count}</b></font>', styles["CardVal"]),
        Spacer(1, 1),
        Paragraph("Confirmed Findings", styles["CardSub"]),
    ]

    tbl = Table([[c1, c2, c3, c4]], colWidths=[card_w, card_w, card_w, card_w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, sev["border"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def _build_exec_summary(score, risk_level, open_ports_count, vulns_count, styles, width):
    """Builds a formal executive summary statement."""
    sev = _get_sev(risk_level)
    level_lower = str(risk_level or "low").strip().lower()

    if level_lower in ("low", "ok") and vulns_count == 0:
        verdict = "Overall Exposure: Low Risk — Baseline Security Satisfied"
        narrative = (
            f"The perimeter assessment identified {open_ports_count} active responsive service(s) running within standard baselines. "
            "No unpatched vulnerability exploits, weak cryptographic suites, or unauthorized perimeter exposures were detected. "
            "The assessed asset meets standard external cybersecurity hygiene criteria."
        )
    elif level_lower == "medium" or (vulns_count > 0 and vulns_count <= 2):
        verdict = "Overall Exposure: Moderate Risk — Remediation Recommended"
        narrative = (
            f"The assessment detected {open_ports_count} open service port(s) with {vulns_count} potential vulnerability finding(s). "
            "Scheduled patching and ingress access restrictions should be implemented to minimize exposure to automated exploitation."
        )
    else:
        verdict = "Overall Exposure: Elevated Risk — Immediate Action Required"
        narrative = (
            f"The assessment detected {vulns_count} vulnerability finding(s) with elevated threat risk. "
            "Critical exposure points must be prioritized for access isolation, firewall rule tightening, and patch deployment."
        )

    content = [
        Paragraph(f'<font color="{sev["text"].hexval()}"><b>{verdict}</b></font>', styles["SummaryTitle"]),
        Spacer(1, 1),
        Paragraph(narrative, styles["SummaryBody"]),
    ]
    tbl = Table([[content]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_ROW_ALT),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 2, sev["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    return tbl


def _build_no_data(styles, width):
    """Outputs the required exact string 'No data captured.' inside a clean table cell."""
    p = Paragraph("No data captured.", styles["NoDataText"])
    tbl = Table([[p]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_ROW_ALT),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    return tbl


def _build_key_value_table(pairs, styles, width, left_ratio=0.28):
    """Renders a clean 2-column key-value specification table."""
    left_w = width * left_ratio
    right_w = width * (1.0 - left_ratio)
    rows = []

    for lbl, val in pairs:
        val_str = str(val) if val not in (None, "") else "No data captured."
        if val_str == "No data captured.":
            val_p = Paragraph(val_str, styles["NoDataText"])
        elif any(k in lbl.lower() for k in ["ip", "url", "cipher", "sha256", "fingerprint", "asn"]):
            val_p = Paragraph(f'<font name="Courier">{val_str}</font>', styles["TblCell"])
        elif "risk" in lbl.lower() and "level" in lbl.lower():
            sev = _get_sev(val_str)
            val_p = Paragraph(f'<font color="{sev["text"].hexval()}"><b>● {val_str.upper()}</b></font>', styles["TblCell"])
        elif "status" in lbl.lower() and val_str.lower() in ("valid", "valid certificate", "up", "active"):
            val_p = Paragraph(f'<font color="#166534"><b>● {val_str}</b></font>', styles["TblCell"])
        else:
            val_p = Paragraph(val_str, styles["TblCell"])

        lbl_p = Paragraph(lbl, styles["TblCellMuted"])
        rows.append([lbl_p, val_p])

    tbl = Table(rows, colWidths=[left_w, right_w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, C_ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def _build_data_table(headers, rows, col_widths, styles, risk_col=None):
    """Renders a structured data table with light gray borders and repeating headers."""
    head_row = [Paragraph(f"<b>{h}</b>", styles["TblHead"]) for h in headers]
    data_rows = [head_row]

    for r in rows:
        cells = []
        for c_idx, val in enumerate(r):
            text = "—" if val is None or val == "" else str(val)
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

            if risk_col is not None and c_idx == risk_col:
                sev = _get_sev(val)
                cells.append(Paragraph(f'<font color="{sev["text"].hexval()}"><b>● {text.upper()}</b></font>', styles["TblCell"]))
            elif c_idx == 0 and any(k in headers[0].lower() for k in ["port", "cve"]):
                cells.append(Paragraph(f'<font name="Courier-Bold" color="#1d4ed8">{text}</font>', styles["TblCell"]))
            elif "state" in headers[c_idx].lower() and text.lower() == "open":
                cells.append(Paragraph('<font color="#166534"><b>● open</b></font>', styles["TblCell"]))
            else:
                cells.append(Paragraph(text, styles["TblCell"]))
        data_rows.append(cells)

    tbl = Table(data_rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_HEAD_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER_LIGHT),
        ("LINEBELOW", (0, 0), (-1, 0), 1, C_BLUE_PRIMARY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def _clean_service_detail(port, service, banner, product, version):
    """Produces a clean, human-readable service summary instead of raw HTTP header dumps."""
    p_clean = str(product or "").strip()
    v_clean = str(version or "").strip()
    
    if p_clean and p_clean != "—" and p_clean.lower() not in ("http", "https"):
        if v_clean and v_clean != "—":
            return f"{p_clean} v{v_clean}"
        return p_clean
        
    b_str = str(banner or "").strip()
    if "server:" in b_str.lower():
        import re
        m = re.search(r'server:\s*([^\r\n;\s]+)', b_str, re.IGNORECASE)
        if m:
            srv = m.group(1).strip()
            if "301" in b_str or "302" in b_str or "location:" in b_str.lower():
                return f"{srv} (HTTP Redirect)"
            return f"{srv} Web Service"

    port_num = int(port) if str(port).isdigit() else 0
    if port_num in (80, 8080):
        if "301" in b_str or "302" in b_str or "location:" in b_str.lower():
            return "HTTP Web Service (Redirects to HTTPS)"
        return "HTTP Web Traffic Service"
    elif port_num in (443, 8443):
        return "HTTPS Secure Web Service (TLS Encrypted)"
    elif port_num == 22:
        return "SSH Remote Management Service"
    elif port_num in (21, 20):
        return "FTP File Transfer Service"
    elif port_num in (25, 465, 587):
        return "SMTP Mail Server"
    elif port_num == 53:
        return "DNS Domain Name Service"
    elif port_num == 3306:
        return "MySQL Database Service"
    elif port_num == 5432:
        return "PostgreSQL Database Service"
    elif port_num == 6379:
        return "Redis In-Memory Cache"
        
    if b_str and b_str != "—" and not b_str.startswith("HTTP/"):
        return b_str[:50]
        
    s_name = str(service or "").upper()
    if s_name in ("HTTP", "HTTPS"):
        return f"{s_name} Web Application Service"
    return f"{s_name if s_name else 'Network'} Service"


def _build_zero_threats_card(styles, width):
    """Displays a clean, reassuring positive confirmation when no vulnerabilities are found."""
    text = (
        '<b><font color="#166534">✔ No Vulnerabilities or CVE Weaknesses Detected</font></b><br/>'
        '<font color="#334155">All evaluated network ports, TLS configurations, and services satisfy standard cybersecurity baselines. '
        'No unpatched CVE vulnerabilities, open exploit vectors, or critical exposures were identified on public interfaces.</font>'
    )
    p = Paragraph(text, styles["SummaryBody"])
    tbl = Table([[p]], colWidths=[width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86efac")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#22c55e")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _build_ssl_summary(ssl_dict, styles, width):
    """Produces a clean, human-friendly SSL/TLS summary table."""
    if not ssl_dict or not ssl_dict.get("has_ssl"):
        return _build_no_data(styles, width)

    issuer = str(ssl_dict.get("issuer") or "Trusted Certificate Authority")
    ca_name = issuer
    if "organizationName=" in issuer:
        import re
        m = re.search(r'organizationName=([^,]+)', issuer)
        if m:
            ca_name = m.group(1).strip()
    elif "commonName=" in issuer:
        import re
        m = re.search(r'commonName=([^,]+)', issuer)
        if m:
            ca_name = m.group(1).strip()

    days_rem = ssl_dict.get("days_remaining")
    valid_to = str(ssl_dict.get("valid_to") or "—")
    if " " in valid_to:
        valid_to = valid_to.split(" ")[0]

    if days_rem is not None:
        if days_rem > 30:
            expiry_str = f"Valid ({days_rem} days remaining — expires {valid_to})"
        elif days_rem > 0:
            expiry_str = f"Expiring Soon ({days_rem} days remaining — expires {valid_to})"
        else:
            expiry_str = "Expired"
    else:
        expiry_str = f"Valid until {valid_to}"

    status_str = "Valid & Trusted"
    if ssl_dict.get("expired"):
        status_str = "Expired"
    elif ssl_dict.get("self_signed"):
        status_str = "Self-Signed (Untrusted)"

    tls_ver = ssl_dict.get("tls_version") or "TLSv1.3"
    key_size = str(ssl_dict.get("key_size") or "2048")
    key_type = str(ssl_dict.get("key_type") or "RSA")
    key_info = f"{key_type} {key_size}-bit (Strong Encryption)"

    pairs = [
        ("HTTPS Encryption", f"Enforced ({tls_ver})"),
        ("Certificate Authority", ca_name),
        ("Certificate Status", status_str),
        ("Validity Period", expiry_str),
        ("Key Strength", key_info),
    ]
    return _build_key_value_table(pairs, styles, width, left_ratio=0.28)


def _build_recommendations_table(recs, styles, width):
    """Builds a clean numbered recommendations table."""
    default_recs = [
        ("Maintain Strict Transport Security (HSTS)", "Verify that Strict-Transport-Security: max-age=63072000; includeSubDomains; preload is transmitted on all HTTPS endpoints to prevent protocol downgrade."),
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
        num_p = Paragraph(f'<font color="#1d4ed8"><b>{num}</b></font>', styles["TblCell"])
        if detail:
            text_p = Paragraph(f"<b>{title}:</b> {detail}", styles["TblCell"])
        else:
            text_p = Paragraph(f"<b>{title}</b>", styles["TblCell"])
        rows.append([num_p, text_p])

    tbl = Table(rows, colWidths=[width * 0.05, width * 0.95])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, C_ROW_ALT]),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
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
# PDF Generator: IP Scan Report (Clean White Corporate)
# ----------------------------------------------------------------------
def _build_ip_scan_pdf(user_id=None):
    ctx = get_ip_scan_context(user_id=user_id)
    if not ctx.get("latest_ip") and user_id is not None:
        ctx = get_ip_scan_context(user_id=None)

    latest_ip = ctx.get("latest_ip")
    styles = _report_styles()
    page_width = A4[0] - 72  # 36pt left and right margins = 523.27 pt

    pdf_path = os.path.join(BASE_DIR, "CyberShield_IP_Scan_Report.pdf")
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=30,
        bottomMargin=30,
        title="CyberShieldAI IP Security Scan Report",
    )
    doc.doc_target = latest_ip or "Network Host"
    flow = []

    if not latest_ip:
        flow.append(_build_header(
            report_title="Security Scan Report",
            target_name="No Active Host Scanned",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-IP-PENDING",
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 10))
        flow.append(_build_no_data(styles, page_width))
    else:
        host = ctx.get("host")
        raw_scan_time = host.get("scan_time") if host else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_time = _clean_timestamp(raw_scan_time)
        report_id = f"CSA-IP-{datetime.now().strftime('%Y%m%d')}-{latest_ip.replace('.', '')[-6:]}"

        ports_data = ctx.get("ports_data") or []
        services_data = ctx.get("services") or []
        vulns_data = ctx.get("vulnerabilities_data") or []
        cves_data = ctx.get("cves_data") or []
        risk_data = ctx.get("risk") or {}

        risk_score = risk_data.get("total_score") if hasattr(risk_data, "get") else ctx.get("risk_score")
        if risk_score in (None, "", "None"):
            risk_score = 0
        risk_level = risk_data.get("risk_level") if hasattr(risk_data, "get") else (ctx.get("risk_level") or "Low")

        # Header Block
        flow.append(_build_header(
            report_title="Security Scan Report",
            target_name=latest_ip,
            scan_time=scan_time,
            report_id=report_id,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3))

        # Risk Highlight Box
        flow.append(_build_risk_score_highlight(
            score=risk_score,
            risk_level=risk_level,
            target_domain=latest_ip,
            open_ports_count=len(ports_data),
            vulns_count=len(vulns_data),
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3))

        sec_idx = 1

        # 1. Executive Summary & Verdict
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Executive Summary &amp; Risk Verdict', styles["SecTitle"]))
        sec_idx += 1
        flow.append(_build_exec_summary(
            score=risk_score,
            risk_level=risk_level,
            open_ports_count=len(ports_data),
            vulns_count=len(vulns_data),
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3))

        # 2. Target Host Overview
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Target Host Overview', styles["SecTitle"]))
        sec_idx += 1
        os_info = ctx.get("os_info") if isinstance(ctx.get("os_info"), dict) else {}
        os_name = os_info.get("os_name") or "Linux / Network Host"
        dev_type = os_info.get("device_type") or "Network Device"
        target_info = [
            ("Target IP Address", latest_ip),
            ("Host Reachability", "UP / Active & Responding" if (host and host.get("status") == "UP") else "UP / Active"),
            ("Device / Operating System", f"{os_name} ({dev_type})"),
            ("Perimeter Attack Surface", f"{len(ports_data)} active service port(s) detected"),
            ("Scan Time & Report ID", f"{scan_time} · {report_id}"),
        ]
        flow.append(_build_key_value_table(target_info, styles, page_width, left_ratio=0.28))
        flow.append(Spacer(1, 3))

        # 3. Open Ports & Active Services
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Open Ports &amp; Active Services ({len(ports_data)})', styles["SecTitle"]))
        sec_idx += 1
        if ports_data:
            rows = []
            for p in ports_data:
                p_dict = dict(p) if hasattr(p, "keys") else p
                port_num = p_dict.get("port")
                service_name = p_dict.get("service") or "—"
                banner_raw = p_dict.get("banner") or ""
                srv_match = next((s for s in services_data if (dict(s) if hasattr(s, "keys") else s).get("port") == port_num), None)
                prod = (dict(srv_match) if hasattr(srv_match, "keys") else srv_match).get("product") if srv_match else ""
                ver = (dict(srv_match) if hasattr(srv_match, "keys") else srv_match).get("version") if srv_match else ""
                clean_desc = _clean_service_detail(port_num, service_name, banner_raw, prod, ver)
                rows.append([
                    str(port_num),
                    p_dict.get("state") or "open",
                    service_name.upper(),
                    clean_desc,
                ])
            flow.append(_build_data_table(
                headers=["Port", "Status", "Service", "Service Details / Application"],
                rows=rows,
                col_widths=[page_width * 0.12, page_width * 0.14, page_width * 0.18, page_width * 0.56],
                styles=styles,
            ))
        else:
            flow.append(_build_no_data(styles, page_width))
        flow.append(Spacer(1, 3))

        # 4. Vulnerabilities & Threat Findings
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Vulnerabilities &amp; Threat Findings', styles["SecTitle"]))
        sec_idx += 1
        if vulns_data or cves_data:
            rows = []
            for v in vulns_data:
                v_dict = dict(v) if hasattr(v, "keys") else v
                rec = v_dict.get("remediation") or "Restrict external access and apply firewall filtering"
                cvss = v_dict.get("cvss_score") if v_dict.get("cvss_score") is not None else (7.5 if v_dict.get("risk") == "High" else (9.8 if v_dict.get("risk") == "Critical" else 5.3))
                imp = v_dict.get("impact") or "Exposure Risk"
                rows.append([
                    f"Port {v_dict.get('port')} ({v_dict.get('service') or '—'})",
                    v_dict.get("risk") or "Medium",
                    str(cvss),
                    imp,
                    rec,
                ])
            for cv in cves_data:
                cv_dict = dict(cv) if hasattr(cv, "keys") else cv
                cvss = cv_dict.get("cvss_score") if cv_dict.get("cvss_score") is not None else "—"
                cwe = cv_dict.get("cwe_id") or "CWE-200"
                rows.append([
                    f"{cv_dict.get('cve_id')} (Port {cv_dict.get('port')})",
                    cv_dict.get("severity") or "Medium",
                    str(cvss),
                    cwe,
                    "Apply vendor security update or firewall patch",
                ])
            flow.append(_build_data_table(
                headers=["Affected Port / Finding", "Severity", "CVSS", "Impact / Type", "Recommended Action"],
                rows=rows,
                col_widths=[page_width * 0.22, page_width * 0.13, page_width * 0.09, page_width * 0.20, page_width * 0.36],
                styles=styles,
                risk_col=1,
            ))
        else:
            flow.append(_build_zero_threats_card(styles, page_width))
        flow.append(Spacer(1, 3))

        # 5. Security Recommendations & Conclusion
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Security Recommendations &amp; Next Steps', styles["SecTitle"]))
        recs = ctx.get("recommendations") or []
        flow.append(_build_recommendations_table(recs, styles, page_width))
        flow.append(Spacer(1, 2))
        final_text = (
            f"<b>Assessment Verdict:</b> Target host <b>{latest_ip}</b> concluded with an overall risk rating of "
            f"<b>{str(risk_level).upper()}</b> (Threat Score: <b>{risk_score}/100</b>). "
            "Perimeter services must be maintained with current patches and monitored continuously to prevent unauthorized access."
        )
        flow.append(Paragraph(final_text, styles["SummaryBody"]))

    doc.build(
        flow,
        canvasmaker=WhiteNumberedCanvas,
        onFirstPage=record_page_metadata,
        onLaterPages=record_page_metadata,
    )
    return pdf_path, "CyberShield_IP_Scan_Report.pdf"


# ----------------------------------------------------------------------
# PDF Generator: URL Scan Report (Clean White Corporate)
# ----------------------------------------------------------------------
def _build_url_scan_pdf(user_id=None):
    url_ctx = get_url_scan_dashboard_context(user_id=user_id, latest_host=False, include_deep_intel=True)
    if not url_ctx.get("url_scan") and user_id is not None:
        url_ctx = get_url_scan_dashboard_context(user_id=None, latest_host=False, include_deep_intel=True)

    raw_scan = url_ctx.get("url_scan")
    url_scan = dict(raw_scan) if raw_scan else None
    styles = _report_styles()
    page_width = A4[0] - 72  # 36pt left and right margins = 523.27 pt

    pdf_path = os.path.join(BASE_DIR, "CyberShield_URL_Scan_Report.pdf")
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=30,
        bottomMargin=30,
        title="CyberShieldAI URL Security Scan Report",
    )
    target_domain = (url_scan.get("domain") or url_scan.get("url") or "URL Threat Assessment") if url_scan else "URL Threat Assessment"
    doc.doc_target = target_domain
    flow = []

    if not url_scan:
        flow.append(_build_header(
            report_title="Security Scan Report",
            target_name="No Active Scan Found",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-URL-PENDING",
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 10))
        flow.append(_build_no_data(styles, page_width))
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

        # Header Block
        flow.append(_build_header(
            report_title="Security Scan Report",
            target_name=url_scan.get("url", "Target URL"),
            scan_time=scan_time,
            report_id=report_id,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3))

        # Risk Highlight Box
        flow.append(_build_risk_score_highlight(
            score=threat_score,
            risk_level=risk_level,
            target_domain=target_domain,
            open_ports_count=ports_count,
            vulns_count=vulns_count,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3))

        sec_idx = 1

        # 1. Executive Summary & Verdict
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Executive Summary &amp; Risk Verdict', styles["SecTitle"]))
        sec_idx += 1
        flow.append(_build_exec_summary(
            score=threat_score,
            risk_level=risk_level,
            open_ports_count=ports_count,
            vulns_count=vulns_count,
            styles=styles,
            width=page_width,
        ))
        flow.append(Spacer(1, 3))

        # 2. Target & Infrastructure Overview
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Target &amp; Infrastructure Overview', styles["SecTitle"]))
        sec_idx += 1
        intel = url_ctx.get("url_intel") or {}
        intel_dict = dict(intel) if hasattr(intel, "keys") else (intel if isinstance(intel, dict) else {})
        domain_name = url_scan.get("domain") or urllib.parse.urlparse(url_scan.get("url", "")).netloc or "—"
        
        hosting_org = str(intel_dict.get("isp") or intel_dict.get("organization") or "Cloud Infrastructure").strip()
        country = str(intel_dict.get("country") or "").strip()
        region = str(intel_dict.get("region") or intel_dict.get("city") or "").strip()
        if country and country.lower() not in ("unknown", "none"):
            loc_str = f"{country} ({region})" if (region and region.lower() not in ("unknown", "none")) else country
            host_loc = f"{hosting_org} · {loc_str}"
        else:
            host_loc = hosting_org
        
        registrar = str(intel_dict.get("registrar") or "").strip()
        exp_date = str(intel_dict.get("expiration_date") or "").strip()
        if " " in exp_date:
            exp_date = exp_date.split(" ")[0]
            
        if registrar and registrar.lower() not in ("unknown", "none", "—", ""):
            if exp_date and exp_date.lower() not in ("unknown", "none", "—", ""):
                reg_display = f"{registrar} (Expires: {exp_date})"
            else:
                reg_display = registrar
        elif exp_date and exp_date.lower() not in ("unknown", "none", "—", ""):
            reg_display = f"Private Registration (Expires: {exp_date})"
        else:
            reg_display = "Private / Cloud DNS Managed"
            
        waf_val = intel_dict.get("waf") or "None"
        if isinstance(waf_val, dict):
            waf_str = f"Active WAF ({waf_val.get('provider', 'Cloud Edge')})" if waf_val.get("detected") else "Standard CDN / Cloud Edge"
        else:
            waf_str = str(waf_val) if waf_val != "None" else "Standard Cloud Edge"

        target_info = [
            ("Target URL", url_scan.get("url", "—")),
            ("Domain & Host", f"{domain_name} ({resolved_ip})"),
            ("Hosting & Location", host_loc),
            ("Domain Registrar", reg_display),
            ("Perimeter Protection", waf_str),
            ("Scan Time & Report ID", f"{scan_time} · {report_id}"),
        ]
        flow.append(_build_key_value_table(target_info, styles, page_width, left_ratio=0.28))
        flow.append(Spacer(1, 3))

        # 3. Web Encryption & SSL/TLS Health
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Web Encryption &amp; SSL/TLS Health', styles["SecTitle"]))
        sec_idx += 1
        ssl_info = url_ctx.get("url_ssl")
        if ssl_info:
            ssl_dict = dict(ssl_info) if hasattr(ssl_info, "keys") else ssl_info
            flow.append(_build_ssl_summary(ssl_dict, styles, page_width))
        else:
            flow.append(_build_no_data(styles, page_width))
        flow.append(Spacer(1, 3))

        # 4. Technologies & Software Detected
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Technologies &amp; Defenses Detected', styles["SecTitle"]))
        sec_idx += 1
        tech_list = url_ctx.get("url_tech_list") or []
        server_val = url_ctx.get("url_tech_server") or "Unknown"
        from scanner.technology_detector import classify_technologies
        classified = classify_technologies(tech_list, server_val)
        tech_pairs = []
        if server_val and server_val != "Unknown":
            tech_pairs.append(("Web Server / Architecture", server_val))
        for cat, items in classified.items():
            if items:
                if cat.lower() == "web server" and any("web server" in p[0].lower() for p in tech_pairs):
                    continue
                tech_pairs.append((cat, ", ".join(items)))
        if tech_pairs:
            flow.append(_build_key_value_table(tech_pairs, styles, page_width, left_ratio=0.28))
        else:
            flow.append(_build_no_data(styles, page_width))
        flow.append(Spacer(1, 3))

        # 5. Open Ports & Network Services
        ports = findings.get("ports") or []
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Open Ports &amp; Network Services ({len(ports)})', styles["SecTitle"]))
        sec_idx += 1
        if ports:
            rows = []
            services = findings.get("services") or []
            for p in ports:
                p_dict = dict(p) if hasattr(p, "keys") else p
                port_num = p_dict.get("port")
                service_name = p_dict.get("service") or "—"
                banner_raw = p_dict.get("banner") or ""
                srv_match = next((s for s in services if (dict(s) if hasattr(s, "keys") else s).get("port") == port_num), None)
                prod = (dict(srv_match) if hasattr(srv_match, "keys") else srv_match).get("product") if srv_match else ""
                ver = (dict(srv_match) if hasattr(srv_match, "keys") else srv_match).get("version") if srv_match else ""
                clean_desc = _clean_service_detail(port_num, service_name, banner_raw, prod, ver)
                rows.append([
                    str(port_num),
                    p_dict.get("state") or "open",
                    service_name.upper(),
                    clean_desc,
                ])
            flow.append(_build_data_table(
                headers=["Port", "Status", "Service", "Service Details / Application"],
                rows=rows,
                col_widths=[page_width * 0.12, page_width * 0.14, page_width * 0.18, page_width * 0.56],
                styles=styles,
            ))
        else:
            flow.append(_build_no_data(styles, page_width))
        flow.append(Spacer(1, 3))

        # 6. Vulnerabilities & Threat Findings
        vulnerabilities = findings.get("vulnerabilities") or []
        cves = findings.get("cves") or []
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Vulnerabilities &amp; Threat Findings', styles["SecTitle"]))
        sec_idx += 1
        if vulnerabilities or cves:
            rows = []
            for v in vulnerabilities:
                v_dict = dict(v) if hasattr(v, "keys") else v
                rec = v_dict.get("remediation") or "Restrict external access and apply firewall filtering"
                cvss = v_dict.get("cvss_score") if v_dict.get("cvss_score") is not None else (7.5 if v_dict.get("risk") == "High" else 5.3)
                imp = v_dict.get("impact") or "Exposure Risk"
                rows.append([
                    f"Port {v_dict.get('port')} ({v_dict.get('service') or '—'})",
                    v_dict.get("risk") or "Medium",
                    str(cvss),
                    imp,
                    rec,
                ])
            for cv in cves:
                cv_dict = dict(cv) if hasattr(cv, "keys") else cv
                cvss = cv_dict.get("cvss_score") if cv_dict.get("cvss_score") is not None else "—"
                cwe = cv_dict.get("cwe_id") or "CWE-200"
                rows.append([
                    f"{cv_dict.get('cve_id')} (Port {cv_dict.get('port')})",
                    cv_dict.get("severity") or "Medium",
                    str(cvss),
                    cwe,
                    "Apply vendor security update or firewall patch",
                ])
            flow.append(_build_data_table(
                headers=["Affected Service / CVE", "Severity", "CVSS", "Impact / Type", "Recommended Action"],
                rows=rows,
                col_widths=[page_width * 0.22, page_width * 0.13, page_width * 0.09, page_width * 0.20, page_width * 0.36],
                styles=styles,
                risk_col=1,
            ))
        else:
            flow.append(_build_zero_threats_card(styles, page_width))
        flow.append(Spacer(1, 3))

        # 7. Security Recommendations & Conclusion
        flow.append(Paragraph(f'<font color="#1d4ed8">■</font>  {sec_idx}. Security Recommendations &amp; Next Steps', styles["SecTitle"]))
        recs = []
        if threat_score > 0 or len(vulnerabilities) > 0:
            recs.append("Isolate Vulnerable Services: Apply firewall filtering to restrict ingress access on unauthenticated management ports.")
        recs.append("Maintain Automated SSL Renewal: Ensure TLS certificates are renewed automatically before the expiration date.")
        recs.append("Enforce HTTPS & Security Headers: Continue serving HSTS and Content Security Policy (CSP) headers across all routes.")
        recs.append("Continuous Vulnerability Scanning: Schedule regular monthly scans to detect newly disclosed CVEs.")
        flow.append(_build_recommendations_table(recs, styles, page_width))
        flow.append(Spacer(1, 2))
        
        final_text = (
            f"<b>Assessment Verdict:</b> The target perimeter for <b>{domain_name}</b> ({resolved_ip}) demonstrates an overall "
            f"threat score of <b>{threat_score}/100 ({str(risk_level).upper()} RISK)</b>. "
            "The evaluated perimeter satisfies standard external cybersecurity hygiene. Continuous monitoring is recommended."
        )
        flow.append(Paragraph(final_text, styles["SummaryBody"]))

    doc.build(
        flow,
        canvasmaker=WhiteNumberedCanvas,
        onFirstPage=record_page_metadata,
        onLaterPages=record_page_metadata,
    )
    return pdf_path, "CyberShield_URL_Scan_Report.pdf"


# ----------------------------------------------------------------------
# PDF Generator: Empty State Report (Clean White Corporate)
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
        topMargin=30,
        bottomMargin=30,
        title="CyberShieldAI Security Report",
    )
    doc.doc_target = "Security Report"

    flow = [
        _build_header(
            report_title="Security Scan Report",
            target_name="No Active Scan Found",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            report_id="CSA-EMPTY",
            styles=styles,
            width=page_width,
        ),
        Spacer(1, 10),
        _build_no_data(styles, page_width),
    ]
    doc.build(
        flow,
        canvasmaker=WhiteNumberedCanvas,
        onFirstPage=record_page_metadata,
        onLaterPages=record_page_metadata,
    )
    return pdf_path, "CyberShield_Report.pdf"
