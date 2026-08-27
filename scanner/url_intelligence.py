import os
import sys
import socket
from urllib.parse import urlparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scanner.whois_lookup import get_whois
from scanner.geoip_lookup import get_geoip
from scanner.dns_lookup import get_dns_records
from scanner.waf_detector import detect_waf
from scanner.security_headers import analyze_security_headers
from database.security_headers_db import save_security_headers


def get_domain(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    netloc = parsed.netloc.strip()
    if netloc.startswith("["):
        end_idx = netloc.find("]")
        if end_idx != -1:
            return netloc[1:end_idx]
    elif netloc.count(":") == 1:
        return netloc.split(":")[0]
    return netloc


def get_ip(domain):
    if not domain:
        return "Unknown"
    import ipaddress
    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        pass
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unknown"


def analyze_url_intelligence(url, scan_id=None):
    domain = get_domain(url)
    ip = get_ip(domain)
    whois_info = get_whois(domain)
    geoip_info = get_geoip(ip)
    dns_info = get_dns_records(domain)
    waf_info = detect_waf(url)
    security_headers = analyze_security_headers(url)

    save_security_headers(
        ip,
        url,
        security_headers,
        scan_id=scan_id
    )

    return {
        "url": url,
        "domain": domain,
        "ip": ip,
        "whois": whois_info,
        "geoip": geoip_info,
        "dns": dns_info,
        "waf": waf_info,
        "security_headers": security_headers
    }


if __name__ == "__main__":
    from pprint import pprint
    pprint(analyze_url_intelligence("https://google.com"))