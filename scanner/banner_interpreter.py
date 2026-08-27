"""
scanner/banner_interpreter.py

Translates raw service banners (the text your port scanner grabs
straight off the wire — HTTP headers, FTP welcome lines, SSH version
strings, SMTP greetings, etc.) into a short, plain-English explanation
a non-technical reader (or a client in a report) can actually
understand.

This does NOT replace the raw banner — it's meant to sit alongside it.
The raw banner is the evidence; interpret_banner() is the caption.

Usage:
    from scanner.banner_interpreter import interpret_banner
    summary = interpret_banner(port_row["service"], port_row["banner"])
"""

import re


def _explain_http_status(code: str) -> str:
    explanations = {
        "200": "The server responded normally (200 OK) — this page/service is reachable.",
        "301": "The server is permanently redirecting requests elsewhere (301).",
        "302": "The server is temporarily redirecting requests elsewhere (302).",
        "400": "The server rejected the request as malformed (400 Bad Request) — often happens when a scanner probes without a proper hostname; not necessarily a problem.",
        "401": "This requires a login (401 Unauthorized).",
        "403": "Access to this is blocked (403 Forbidden) — the server is refusing the request, often intentionally (a firewall, WAF, or access rule).",
        "404": "Nothing was found at this path (404 Not Found).",
        "500": "The server hit an internal error (500) while handling the request.",
        "502": "The server acted as a gateway/proxy and got a bad response from whatever is behind it (502 Bad Gateway).",
        "503": "The service is temporarily unavailable (503), often due to overload or maintenance.",
    }
    return explanations.get(code, f"The server responded with HTTP status {code}.")


def _explain_server_header(server_value: str) -> str:
    server_value_lower = server_value.lower()

    known = [
        ("cloudflare", "This site is sitting behind Cloudflare, a CDN/security proxy — you're talking to Cloudflare's edge server, not the real backend server directly."),
        ("akamai", "This site is sitting behind Akamai, a CDN/security proxy — similar to Cloudflare, it shields the real backend server."),
        ("apache", "The web server software is Apache."),
        ("nginx", "The web server software is Nginx."),
        ("iis", "The web server software is Microsoft IIS (Windows-based)."),
        ("openssh", "This is an SSH server, used for secure remote login/admin access."),
        ("pure-ftpd", "This is a Pure-FTPd FTP server, used for file transfers."),
        ("exim", "This is an Exim mail server, used for sending/receiving email (SMTP)."),
        ("dovecot", "This is a Dovecot mail server, used for retrieving email (IMAP/POP3)."),
    ]

    for keyword, explanation in known:
        if keyword in server_value_lower:
            return explanation

    return f"The server identifies itself as \"{server_value}\"."


def interpret_banner(service: str, banner: str) -> str:
    """
    Returns a short, plain-English explanation of a raw banner string.
    Falls back to a generic "couldn't identify" message rather than
    crashing on unexpected formats.
    """
    if not banner or banner.strip().lower() in ("no banner", "none", ""):
        return "No banner was returned — the port is open, but the service didn't identify itself. This is common when a firewall strips banners, or the service requires a specific handshake before responding."

    parts = []

    # --- HTTP status line, e.g. "HTTP/1.1 403 Forbidden ..." ---
    status_match = re.search(r"HTTP/1\.[01]\s+(\d{3})", banner)
    if status_match:
        parts.append(_explain_http_status(status_match.group(1)))

    # --- Server header, e.g. "Server: cloudflare" or "Server: Apache" ---
    server_match = re.search(r"Server:\s*([^\s;]+(?:\s[^\s;]+)?)", banner)
    if server_match:
        parts.append(_explain_server_header(server_match.group(1)))

    # --- FTP welcome banner ---
    if service and service.lower() == "ftp":
        if "pure-ftpd" in banner.lower():
            parts.append("This is a Pure-FTPd FTP server, used for file transfers.")
        if "[TLS]" in banner:
            parts.append("It supports encrypted (TLS) FTP connections.")

    # --- SMTP greeting, e.g. "220-server ESMTP Exim 4.99.4 ..." ---
    if service and service.lower() == "smtp":
        if "ESMTP" in banner:
            parts.append("This is a mail server accepting outgoing/incoming email (SMTP).")
        product_match = re.search(r"ESMTP\s+([A-Za-z]+)", banner)
        if product_match:
            parts.append(f"Mail server software: {product_match.group(1)}.")

    # --- IMAP/POP3 ready banners ---
    if service and service.lower() in ("imap", "pop3"):
        if "dovecot" in banner.lower():
            parts.append("This is a Dovecot mail server used for retrieving email.")
        if "ready" in banner.lower():
            parts.append("The service is up and accepting connections.")

    # --- SSH version string, e.g. "SSH-2.0-OpenSSH_9.9" ---
    ssh_match = re.search(r"SSH-(\d\.\d)-([A-Za-z]+)_?([\d.]+)?", banner)
    if ssh_match:
        version, product, product_version = ssh_match.groups()
        line = f"This is an SSH server (protocol {version}) running {product}"
        if product_version:
            line += f" version {product_version}"
        line += " — used for secure remote login/admin access."
        parts.append(line)

    # --- Cloudflare-specific marker even without a Server header match ---
    if "cf-ray" in banner.lower() and not any("cloudflare" in p.lower() for p in parts):
        parts.append("The \"CF-RAY\" header confirms this request passed through Cloudflare's network.")

    if not parts:
        return "The service responded, but this scanner couldn't automatically identify what it is from the banner text — you may want to inspect it manually or search the raw text online."

    return " ".join(parts)