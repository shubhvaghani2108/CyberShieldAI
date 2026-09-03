import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def analyze_security_headers(url):
    """
    Fetches HTTP response headers for a URL and explicitly verifies security headers.
    Returns dict mapping header keys to boolean status (True = Present, False = Missing, None = Unchecked).
    """
    result = {
        "Strict-Transport-Security": False,
        "Content-Security-Policy": False,
        "X-Frame-Options": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
        "Permissions-Policy": False,
        "scanned": False
    }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/137 Safari/537.36"
    }

    try:
        from scanner.config import SCAN_CONNECT_TIMEOUT, SCAN_READ_TIMEOUT
        response = requests.get(
            url,
            headers=headers,
            timeout=(SCAN_CONNECT_TIMEOUT, SCAN_READ_TIMEOUT),
            allow_redirects=True,
            verify=False
        )
        res_headers = {k.lower(): v for k, v in response.headers.items()}
        result["scanned"] = True

        result["Strict-Transport-Security"] = "strict-transport-security" in res_headers
        result["Content-Security-Policy"] = "content-security-policy" in res_headers
        result["X-Frame-Options"] = "x-frame-options" in res_headers
        result["X-Content-Type-Options"] = "x-content-type-options" in res_headers
        result["Referrer-Policy"] = "referrer-policy" in res_headers
        result["Permissions-Policy"] = ("permissions-policy" in res_headers or "feature-policy" in res_headers)

    except Exception as e:
        print("[Security Header Scan Warning]", e)
        result["scanned"] = False

    return result
