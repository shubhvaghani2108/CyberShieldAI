import ipaddress
import requests


def _is_valid_ip(ip_str):
    if not ip_str or not isinstance(ip_str, str):
        return False
    ip_str = ip_str.strip()
    if ip_str in ("Unknown", "unknown", "N/A", "n/a", "None", "none", ""):
        return False
    if ip_str.startswith("["):
        end_idx = ip_str.find("]")
        if end_idx != -1:
            ip_str = ip_str[1:end_idx]
    elif ip_str.count(":") == 1:
        ip_str = ip_str.split(":")[0]
    
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def get_geoip(ip):
    """
    Get GeoIP information using ip-api.com.
    If ip is Unknown, invalid, or DNS resolution failed, skip remote HTTP lookup.
    """
    if not _is_valid_ip(ip):
        return {
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "timezone": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "organization": "Unknown",
            "is_assessed": False,
            "reason": "Target IP address could not be resolved."
        }

    clean_ip = str(ip).strip()
    if clean_ip.startswith("["):
        end_idx = clean_ip.find("]")
        if end_idx != -1:
            clean_ip = clean_ip[1:end_idx]

    try:
        url = f"http://ip-api.com/json/{clean_ip}"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") != "success":
            return {
                "country": "Unknown",
                "region": "Unknown",
                "city": "Unknown",
                "latitude": None,
                "longitude": None,
                "timezone": "Unknown",
                "isp": "Unknown",
                "asn": "Unknown",
                "organization": "Unknown",
                "is_assessed": False,
                "reason": data.get("message", "GeoIP lookup failed")
            }

        return {
            "country": data.get("country") or "Unknown",
            "region": data.get("regionName") or "Unknown",
            "city": data.get("city") or "Unknown",
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone") or "Unknown",
            "isp": data.get("isp") or "Unknown",
            "asn": data.get("as") or "Unknown",
            "organization": data.get("org") or "Unknown",
            "is_assessed": True,
            "reason": None
        }

    except Exception as e:
        return {
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "timezone": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "organization": "Unknown",
            "is_assessed": False,
            "reason": str(e),
            "error": str(e)
        }


if __name__ == "__main__":

    from pprint import pprint

    pprint(get_geoip("8.8.8.8"))