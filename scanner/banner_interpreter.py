

"""
scanner/banner_interpreter.py

Translates raw service banners (the text your port scanner grabs
straight off the wire — HTTP headers, FTP welcome lines, SSH version
strings, SMTP greetings, database handshakes, etc.) into a short,
plain-English explanation a non-technical reader (or a client in a report)
can actually understand.

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
        "302": "The server is temporarily redirecting requests elsewhere (302 Found).",
        "400": "The server rejected the request as malformed (400 Bad Request) — often happens when a scanner probes without a proper hostname; not necessarily a problem.",
        "401": "This endpoint requires authentication (401 Unauthorized).",
        "403": "Access to this service is restricted (403 Forbidden) — the server is refusing the request, commonly enforced by a web firewall, access control list, or web server rule.",
        "404": "Nothing was found at this default path (404 Not Found).",
        "500": "The server encountered an internal error (500 Internal Server Error).",
        "502": "The server acted as a gateway or proxy and received an invalid response from upstream (502 Bad Gateway).",
        "503": "The service is temporarily unavailable (503 Service Unavailable), typically due to maintenance or rate limiting.",
    }
    return explanations.get(code, f"The server responded with HTTP status {code}.")


def _explain_server_header(server_value: str) -> str:
    server_value_lower = server_value.lower()

    known = [
        ("cloudflare", "This site is sitting behind Cloudflare, a CDN/security proxy — you're talking to Cloudflare's edge server, not the real backend server directly."),
        ("akamai", "This site is sitting behind Akamai, a CDN/security proxy — shielding the real backend server."),
        ("apache", "The web server software is Apache."),
        ("nginx", "The web server software is Nginx."),
        ("litespeed", "The web server software is LiteSpeed."),
        ("caddy", "The web server software is Caddy."),
        ("gunicorn", "The Python WSGI application server is Gunicorn."),
        ("uvicorn", "The Python ASGI application server is Uvicorn."),
        ("werkzeug", "The Python WSGI development server is Werkzeug."),
        ("envoy", "This service is running behind Envoy Proxy."),
        ("traefik", "This service is running behind Traefik Cloud Native Proxy."),
        ("openresty", "The web server software is OpenResty (Nginx-based)."),
        ("iis", "The web server software is Microsoft IIS (Windows-based)."),
        ("microsoft-iis", "The web server software is Microsoft IIS (Windows-based)."),
        ("openssh", "This is an SSH server, used for secure remote login/admin access."),
        ("pure-ftpd", "This is a Pure-FTPd FTP server, used for file transfers."),
        ("vsftpd", "This is a vsftpd FTP server, used for file transfers."),
        ("proftpd", "This is a ProFTPD FTP server, used for file transfers."),
        ("exim", "This is an Exim mail server, used for sending/receiving email (SMTP)."),
        ("postfix", "This is a Postfix mail server, used for sending/receiving email (SMTP)."),
        ("dovecot", "This is a Dovecot mail server, used for retrieving email (IMAP/POP3)."),
    ]

    for keyword, explanation in known:
        if keyword in server_value_lower:
            return explanation

    return f"The server identifies itself as \"{server_value.strip()}\"."


def interpret_banner(service: str, banner: str) -> str:
    """
    Returns a short, plain-English explanation of a raw banner string.
    Falls back to a generic "couldn't identify" message rather than
    crashing on unexpected formats.
    """
    if not banner or banner.strip().lower() in ("no banner", "none", "unknown", "-", ""):
        return "No banner was returned — the port is open, but the service didn't identify itself. This is common when a firewall strips banners, or the service requires a specific handshake before responding."

    parts = []

    # --- HTTP status line, e.g. "HTTP/1.1 403 Forbidden ..." or "HTTP/1.0 400 Bad Request" ---
    status_match = re.search(r"HTTP/1\.[01]\s+(\d{3})", banner, re.IGNORECASE)
    if status_match:
        parts.append(_explain_http_status(status_match.group(1)))
    elif "400 bad request" in banner.lower():
        if "https is required" in banner.lower():
            parts.append("The server returned a 400 Bad Request error indicating that an encrypted HTTPS connection is required on this port.")
        else:
            parts.append("The server returned an HTTP 400 Bad Request response.")

    # --- Server header, e.g. "Server: nginx/1.18.0 (Ubuntu)" or "Server: LiteSpeed" ---
    server_match = re.search(r"Server:\s*([^\r\n;]+)", banner, re.IGNORECASE)
    if server_match:
        parts.append(_explain_server_header(server_match.group(1)))
    elif "litespeed" in banner.lower() and not any("litespeed" in p.lower() for p in parts):
        parts.append("The web server software is LiteSpeed.")
    elif "nginx" in banner.lower() and not any("nginx" in p.lower() for p in parts):
        parts.append("The web server software is Nginx.")
    elif "apache" in banner.lower() and not any("apache" in p.lower() for p in parts):
        parts.append("The web server software is Apache.")

    # --- FTP welcome banner ---
    if (service and service.lower() == "ftp") or "ftp" in banner.lower():
        if "proftpd" in banner.lower() or "knftpd" in banner.lower():
            parts.append("This is a ProFTPD/KnFTPD FTP server, used for file transfers.")
        elif "vsftpd" in banner.lower():
            parts.append("This is a vsftpd FTP server, used for unencrypted file transfers.")
        elif "pure-ftpd" in banner.lower():
            parts.append("This is a Pure-FTPd FTP server, used for file transfers.")
        elif "ftp server ready" in banner.lower() or banner.startswith("220 "):
            parts.append("This is an FTP server used for unencrypted file transfers — credentials and data can be sniffed in transit.")
        if "[tls]" in banner.lower():
            parts.append("It supports encrypted (TLS) FTP connections.")

    # --- SMTP greeting, e.g. "220-server ESMTP Exim 4.99.4 ..." ---
    if (service and service.lower() == "smtp") or "esmtp" in banner.lower():
        if "esmtp" in banner.lower() and not any("mail server" in p.lower() for p in parts):
            parts.append("This is a mail server accepting outgoing/incoming email (SMTP).")
        product_match = re.search(r"ESMTP\s+([A-Za-z]+)", banner, re.IGNORECASE)
        if product_match:
            parts.append(f"Mail server software: {product_match.group(1)}.")

    # --- IMAP/POP3 ready banners ---
    if service and service.lower() in ("imap", "pop3", "imaps", "pop3s"):
        if "dovecot" in banner.lower():
            parts.append("This is a Dovecot mail server used for retrieving email.")
        elif "ready" in banner.lower():
            parts.append("The mail retrieval service is up and accepting client connections.")

    # --- SSH version string, e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.16" ---
    ssh_match = re.search(r"SSH-(\d\.\d)-([A-Za-z]+)_?([\d.]+)?", banner)
    if ssh_match:
        version, product, product_version = ssh_match.groups()
        line = f"This is an SSH server (protocol {version}) running {product}"
        if product_version:
            line += f" version {product_version}"
        line += " — used for secure remote login/admin access."
        parts.append(line)

    # --- MySQL / MariaDB database banner ---
    if "mariadb" in banner.lower():
        ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)-MariaDB", banner, re.IGNORECASE)
        ver_str = f" version {ver_match.group(1)}" if ver_match else ""
        parts.append(f"This is a MariaDB database server{ver_str} — exposing database ports directly to the public internet carries a high security risk.")
    elif "mysql" in banner.lower() or (service and service.lower() == "mysql"):
        ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)(?:-log)?", banner)
        ver_str = f" version {ver_match.group(1)}" if ver_match else ""
        parts.append(f"This is a MySQL database server{ver_str} — direct database exposure allows potential credential brute-forcing and unauthorized data exfiltration.")

    # --- PostgreSQL database banner ---
    elif "postgresql" in banner.lower() or (service and service.lower() == "postgresql"):
        parts.append("This is a PostgreSQL database server — exposing database ports to the public internet carries a high security risk.")

    # --- Redis in-memory store ---
    elif "redis" in banner.lower() or (service and service.lower() == "redis"):
        parts.append("This is a Redis in-memory data store — unauthenticated Redis exposure can lead to remote code execution.")

    # --- MongoDB NoSQL database ---
    elif "mongodb" in banner.lower() or (service and service.lower() == "mongodb"):
        parts.append("This is a MongoDB NoSQL database — public accessibility creates serious data exposure risks.")

    # --- MS-SQL database ---
    elif (service and service.lower() in ("ms-sql", "ms-sql-s", "mssql")) or "microsoft sql server" in banner.lower():
        parts.append("This is a Microsoft SQL Server (MS-SQL) database endpoint.")

    # --- RDP / Remote Desktop ---
    elif (service and service.lower() in ("rdp", "ms-wbt-server")) or "remote desktop" in banner.lower():
        parts.append("This is a Microsoft Remote Desktop (RDP) service — direct internet exposure is a primary vector for ransomware attacks.")

    # --- VNC ---
    elif (service and service.lower() == "vnc") or "rfb " in banner.lower():
        parts.append("This is a VNC remote desktop service used for graphical screen sharing and management.")

    # --- Telnet ---
    elif (service and service.lower() == "telnet"):
        parts.append("This is an unencrypted Telnet service — all commands and credentials are sent in cleartext across the network.")

    # --- Cloudflare-specific marker even without a Server header match ---
    if "cf-ray" in banner.lower() and not any("cloudflare" in p.lower() for p in parts):
        parts.append("The \"CF-RAY\" header confirms this request passed through Cloudflare's network.")

    if not parts:
        return "The service responded, but this scanner couldn't automatically identify what it is from the banner text — you may want to inspect it manually or search the raw text online."

    return " ".join(parts)