import ipaddress
import whois
from datetime import datetime
import concurrent.futures


def _is_ip_address(target_str):
    if not target_str:
        return False
    target_str = str(target_str).strip()
    if target_str.startswith("["):
        end_idx = target_str.find("]")
        if end_idx != -1:
            target_str = target_str[1:end_idx]
    elif target_str.count(":") == 1:
        target_str = target_str.split(":")[0]
    
    try:
        ipaddress.ip_address(target_str)
        return True
    except ValueError:
        return False


def _format_date(value):
    """Convert whois date objects to string."""
    if isinstance(value, list):
        value = value[0]

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")

    return str(value) if value else "Unknown"


def get_whois(domain):
    """
    Returns WHOIS information as a dictionary with a strict 5s timeout guard.
    If domain is an IPv4 or IPv6 address, domain WHOIS lookup is skipped entirely
    and N/A values are returned.
    """
    if not domain:
        return {
            "registrar": "N/A",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "updated_date": "N/A",
            "name_servers": "N/A",
            "status": "N/A",
            "emails": "N/A",
            "dnssec": "N/A",
            "is_ip": True,
            "reason": "Target is empty."
        }

    if _is_ip_address(domain):
        return {
            "registrar": "N/A",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "updated_date": "N/A",
            "name_servers": "N/A",
            "status": "N/A",
            "emails": "N/A",
            "dnssec": "N/A",
            "is_ip": True,
            "reason": "Target is an IP address. Domain WHOIS data is not applicable."
        }

    def _query():
        return whois.whois(domain)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_query)
            w = future.result(timeout=5.0)

        return {
            "registrar": w.registrar or "Unknown",
            "creation_date": _format_date(w.creation_date),
            "expiration_date": _format_date(w.expiration_date),
            "updated_date": _format_date(w.updated_date),
            "name_servers": ", ".join(w.name_servers) if w.name_servers else "Unknown",
            "status": ", ".join(w.status) if isinstance(w.status, list) else (w.status or "Unknown"),
            "emails": ", ".join(w.emails) if isinstance(w.emails, list) else (w.emails or "Unknown"),
            "dnssec": getattr(w, "dnssec", "Unknown"),
            "is_ip": False,
            "reason": None
        }

    except Exception as e:
        return {
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "updated_date": "Unknown",
            "name_servers": "Unknown",
            "status": "Unknown",
            "emails": "Unknown",
            "dnssec": "Unknown",
            "is_ip": False,
            "reason": None,
            "error": str(e)
        }


if __name__ == "__main__":

    from pprint import pprint

    pprint(get_whois("google.com"))