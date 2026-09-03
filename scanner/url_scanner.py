import socket
import re
import requests
from urllib.parse import urlparse


def score_to_risk_level(score):
    """Shared score->label mapping so any code that adjusts the score
    later (e.g. a domain-age check) stays consistent with scan_url()."""
    if score >= 40:
        return "Critical"
    elif score >= 25:
        return "High"
    elif score >= 10:
        return "Medium"
    return "Low"


# =========================================================
# CHECK WHETHER URL RESPONDS
# =========================================================
def check_protocol(test_url):
    """
    Try opening URL and detect whether protocol works.
    Returns:
        (True, final_url, final_scheme)  -> if URL responds
        (False, test_url, "unknown")     -> if failed
    """

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    from scanner.config import SCAN_CONNECT_TIMEOUT, SCAN_READ_TIMEOUT
    try:
        response = requests.get(
            test_url,
            timeout=(SCAN_CONNECT_TIMEOUT, SCAN_READ_TIMEOUT),
            allow_redirects=True,
            headers=headers
        )

        # If website responded, treat it as valid
        final_url = response.url
        parsed = urlparse(final_url)

        if parsed.scheme:
            return True, final_url, parsed.scheme.lower()

    except Exception:
        pass

    return False, test_url, "unknown"


# =========================================================
# AUTO DETECT REAL PROTOCOL
# =========================================================
def detect_real_protocol(user_input):
    """
    Auto-detects real live protocol and follows redirects to the canonical target URL.
    Rules:
    1. If user gives full http:// or https:// URL -> follow redirects to canonical final URL
    2. If user gives only domain -> test https first, then http, following redirects to canonical final URL
    """

    user_input = user_input.strip()

    if not user_input:
        raise ValueError("URL cannot be empty")

    # -----------------------------------------------------
    # CASE 1: USER ALREADY GAVE FULL URL
    # -----------------------------------------------------
    if user_input.startswith(("http://", "https://")):
        parsed = urlparse(user_input)

        if not parsed.netloc:
            raise ValueError("Invalid URL format")

        ok, final_url, final_scheme = check_protocol(user_input)
        if ok:
            return final_url, final_scheme

        return user_input, parsed.scheme.lower()

    # -----------------------------------------------------
    # CASE 2: USER GAVE ONLY DOMAIN
    # -----------------------------------------------------
    https_url = "https://" + user_input
    http_url = "http://" + user_input

    # Try HTTPS first (following any 301/302 canonical redirects e.g. google.com -> https://www.google.com/)
    https_ok, https_final_url, https_scheme = check_protocol(https_url)
    if https_ok:
        return https_final_url, https_scheme

    # Then try HTTP
    http_ok, http_final_url, http_scheme = check_protocol(http_url)
    if http_ok:
        return http_final_url, http_scheme

    # If both failed
    return https_url, "unknown"


# =========================================================
# MAIN URL SCAN FUNCTION
# =========================================================
def scan_url(user_input):
    """
    Scan URL and return result dictionary.

    IMPORTANT:
    This function DOES NOT save to database.
    Database INSERT must be done only inside dashboard/app.py
    """

    print("\n[+] Scanning URL:", user_input)

    # =====================================================
    # 1) Detect protocol + final URL
    # =====================================================
    url, protocol = detect_real_protocol(user_input)

    parsed = urlparse(url)
    domain = parsed.netloc.strip()
    path = parsed.path.lower()

    # clean domain for DNS resolve (handles IPv4, IPv6 literals, and host:port)
    clean_domain = domain.strip()
    if clean_domain.startswith("["):
        end_idx = clean_domain.find("]")
        if end_idx != -1:
            clean_domain = clean_domain[1:end_idx]
    elif clean_domain.count(":") == 1:
        clean_domain = clean_domain.split(":")[0]

    # =====================================================
    # 2) Resolve IP
    # =====================================================
    is_raw_ip = False
    try:
        import ipaddress
        ipaddress.ip_address(clean_domain)
        ip = clean_domain
        is_raw_ip = True
    except ValueError:
        try:
            if clean_domain:
                ip = socket.gethostbyname(clean_domain)
            else:
                ip = "Unknown"
        except Exception:
            ip = "Unknown"

    # =====================================================
    # 3) Risk scoring
    #
    # IMPORTANT: this deliberately scores URL STRUCTURE, not URL
    # CONTENT/WORDING. A keyword blacklist (login/verify/account/
    # bank/secure/...) inherently flags almost every real website,
    # because virtually every real site — a bank, a shop, an email
    # provider, a SaaS app — legitimately has a login page, an
    # "account" page, a "verify your email" page, etc. That produced
    # false positives on ANY normal website, not just banks. These
    # rules instead look for how phishing/malicious URLs are actually
    # built, which generalizes to any site regardless of topic.
    # =====================================================
    score = 0
    remarks = []

    # Rule 1: protocol risk
    #
    # HTTPS is the secure, expected baseline for a modern website - it
    # should not itself cost points, or a perfectly clean site could
    # never score below 5 even with zero actual risk signals. Only the
    # worse-than-baseline cases (plain HTTP, or a protocol that
    # couldn't even be verified) add risk points.
    if protocol == "http":
        score += 15
        remarks.append("Website is using HTTP (not secure)")
    elif protocol == "https":
        remarks.append("Website is using HTTPS")
    else:
        score += 20
        remarks.append("Protocol could not be verified")

    # Rule 2: raw IP address used instead of a domain name (e.g.
    # http://185.23.45.10/login or https://[2600:140f::1]). Legitimate sites
    # practically never present a bare IP as the URL a user is meant to visit -
    # this is one of the strongest, most universal red flags there is.
    host_only = clean_domain
    if is_raw_ip:
        score += 25
        remarks.append("URL uses a raw IP address instead of a domain name")
    else:
        ip_literal_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if host_only and ip_literal_pattern.match(host_only):
            score += 25
            remarks.append("URL uses a raw IP address instead of a domain name")

    # Rule 3: punycode / IDN domain (xn--...). Used for homograph
    # attacks (lookalike characters that render like a trusted brand).
    if "xn--" in domain.lower():
        score += 20
        remarks.append("Domain uses punycode encoding (possible lookalike/homograph domain)")

    # Rule 4: known URL shortener - hides the real destination behind
    # a redirect, which is topic-agnostic and applies to any URL.
    shortener_domains = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    }
    if host_only.lower() in shortener_domains:
        score += 10
        remarks.append("URL shortener detected - real destination is hidden")

    # Rule 5: unusually deep subdomain nesting (e.g.
    # secure.login.account.example.com.verify-user.tk). Phishing kits
    # often bury a fake domain under many subdomain labels to push the
    # real (malicious) domain out of view on a small screen.
    if host_only:
        label_count = len([p for p in host_only.split(".") if p])
        if label_count >= 5:
            score += 10
            remarks.append("Unusually deep subdomain structure")

    # Rule 6: @ symbol - classic URL-obfuscation trick (browsers ignore
    # everything before the @, so "https://real-bank.com@evil.tk" opens
    # evil.tk while looking like real-bank.com).
    if "@" in url:
        score += 15
        remarks.append("Contains @ symbol (possible redirect/obfuscation trick)")

    # Rule 7: excessive hyphens in the domain itself (not the path) -
    # a common pattern for disposable lookalike domains
    # (e.g. "my-secure-login-verify.tk").
    if host_only.count("-") > 3:
        score += 10
        remarks.append("Unusually high number of hyphens in the domain")

    # Rule 8: overly long URL - long, parameter-stuffed URLs are more
    # commonly used to obscure a redirect chain or a tracking payload.
    if len(url) > 100:
        score += 10
        remarks.append("URL is unusually long")

    # Rule 9: domain resolution failed - the domain doesn't even point
    # anywhere, which is unusual for a legitimate, currently-operating site.
    if ip == "Unknown":
        score += 15
        remarks.append("Domain could not be resolved")

    # If nothing found
    if not remarks:
        remarks.append("No obvious URL threat indicators found")

    # =====================================================
    # 4) Final risk level
    # =====================================================
    risk = score_to_risk_level(score)

    # =====================================================
    # 5) Terminal output
    # =====================================================
    print("\n=== URL SCAN RESULT ===")
    print("URL:", url)
    print("Domain:", domain)
    print("IP:", ip)
    print("Protocol:", protocol.upper())
    print("Score:", score)
    print("Risk:", risk)
    print("Remarks:", remarks)

    # =====================================================
    # 6) Return result to app.py
    # =====================================================
    return {
    "url": url,
    "domain": domain,
    "ip": ip,
    "protocol": protocol,
    "score": score,
    "risk": risk,
    "remarks": remarks
}

# =========================================================
# TEST RUN
# =========================================================
if __name__ == "__main__":
    user_url = input("Enter URL or Domain: ").strip()
    result = scan_url(user_url)

    print("\nReturned Result:")
    for key, value in result.items():
        print(f"{key}: {value}")