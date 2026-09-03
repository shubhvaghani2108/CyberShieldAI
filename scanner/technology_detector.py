import os
import socket
from datetime import datetime
from database.db_engine import get_db_connection

import requests
import urllib3
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================================
# DATABASE PATH
# ==========================================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


# ==========================================================
# SAVE TECHNOLOGY
# ==========================================================

def save_technology(url, server, technologies):

    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(hostname)

    except Exception:
        ip = "Unknown"

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO technology_detection
        (
            ip,
            url,
            server,
            technologies,
            scan_time
        )
        VALUES
        (?, ?, ?, ?, ?)
        """, (
            ip,
            url,
            server,
            ", ".join(technologies),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()

        print("[+] Technology saved successfully.")

    except Exception as e:
        print("[Database Error]", e)


# ==========================================================
# TECHNOLOGY DETECTOR
# ==========================================================

def classify_technologies(tech_list, server="Unknown"):
    classified = {
        "Backend": [],
        "Frontend": [],
        "Web Server": [],
        "CDN / Infrastructure": [],
        "Security & Protocols": [],
        "Other / Libraries": []
    }

    if server and server != "Unknown" and server not in classified["Web Server"]:
        classified["Web Server"].append(server)

    if not tech_list:
        return classified

    for tech in tech_list:
        t_lower = str(tech).lower()
        if any(k in t_lower for k in ["iis", "asp.net", "php", "express", "laravel", "django", "wordpress", "drupal", "joomla", "python", "java", "ruby"]):
            if tech not in classified["Backend"]:
                classified["Backend"].append(tech)

        elif any(k in t_lower for k in ["react", "bootstrap", "jquery", "vue", "angular", "next.js", "tailwind", "javascript"]):
            if tech not in classified["Frontend"]:
                classified["Frontend"].append(tech)

        elif any(k in t_lower for k in ["apache", "nginx", "litespeed", "caddy", "gunicorn"]):
            if tech not in classified["Web Server"]:
                classified["Web Server"].append(tech)
            
        elif any(k in t_lower for k in ["cloudflare", "akamai", "cloudfront", "fastly", "proxy", "cdn", "cache"]):
            if tech not in classified["CDN / Infrastructure"]:
                classified["CDN / Infrastructure"].append(tech)
        elif any(k in t_lower for k in ["hsts", "csp", "content security policy", "clickjacking", "mime", "http/1", "http/2"]):
            if tech not in classified["Security & Protocols"]:
                classified["Security & Protocols"].append(tech)
        else:
            if tech not in classified["Other / Libraries"]:
                classified["Other / Libraries"].append(tech)

    return classified


def detect_technology(url):

    result = {
        "server": "Unknown",
        "technologies": [],
        "classified": {}
    }

    headers = {
        "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/137 Safari/537.36"
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=8,
            allow_redirects=True,
            verify=False
        )

        html = response.text.lower()
        soup = BeautifulSoup(html, "html.parser")

        technologies = []

        # ======================================================
        # SERVER HEADER
        # ======================================================

        server = response.headers.get("Server", "Unknown")
        result["server"] = server

        server_lower = server.lower()

        if "apache" in server_lower:
            technologies.append("Apache Web Server")

        if "nginx" in server_lower:
            technologies.append("Nginx")

        if "iis" in server_lower:
            technologies.append("Microsoft IIS")

        if "cloudfront" in server_lower:
            technologies.append("Amazon CloudFront CDN")

        if "cloudflare" in server_lower:
            technologies.append("Cloudflare CDN")

        if "akamai" in server_lower:
            technologies.append("Akamai CDN")

        # ======================================================
        # POWERED BY
        # ======================================================

        powered = response.headers.get("X-Powered-By")

        if powered:
            technologies.append(powered)

            if "php" in powered.lower():
                technologies.append("PHP")

            if "express" in powered.lower():
                technologies.append("Express.js")

        # ======================================================
        # SECURITY HEADERS
        # ======================================================

        if response.headers.get("Strict-Transport-Security"):
            technologies.append("HSTS Enabled")

        if response.headers.get("Content-Security-Policy"):
            technologies.append("Content Security Policy")

        if response.headers.get("X-Frame-Options"):
            technologies.append("Clickjacking Protection")

        if response.headers.get("X-Content-Type-Options"):
            technologies.append("MIME Type Protection")

        # ======================================================
        # HTTP VERSION
        # ======================================================

        try:
            if response.raw.version == 11:
                technologies.append("HTTP/1.1")
            elif response.raw.version == 20:
                technologies.append("HTTP/2")
        except Exception:
            pass

        # ======================================================
        # CDN / CACHE
        # ======================================================

        if response.headers.get("Via"):
            technologies.append("Proxy / CDN")

        if response.headers.get("X-Cache"):
            technologies.append("Cache Enabled")

        # ======================================================
        # ASP.NET
        # ======================================================

        if response.headers.get("X-AspNet-Version"):
            technologies.append("ASP.NET")

        # ======================================================
        # COOKIE DETECTION
        # ======================================================

        if "laravel_session" in response.cookies:
            technologies.append("Laravel")

        if "csrftoken" in response.cookies:
            technologies.append("Django")

        # ======================================================
        # HTML DETECTION
        # ======================================================

        if "wordpress" in html or "wp-content" in html:
            technologies.append("WordPress")

        if "drupal" in html:
            technologies.append("Drupal")

        if "joomla" in html:
            technologies.append("Joomla")

        if "bootstrap" in html:
            technologies.append("Bootstrap")

        if "jquery" in html:
            technologies.append("jQuery")

        if "react" in html:
            technologies.append("React")

        if "angular" in html:
            technologies.append("Angular")

        if "vue" in html:
            technologies.append("Vue.js")

        if "cloudflare" in html:
            technologies.append("Cloudflare")

        if "__next" in html:
            technologies.append("Next.js")

        # ======================================================
        # META GENERATOR
        # ======================================================

        generator = soup.find("meta", attrs={"name": "generator"})

        if generator:

            content = generator.get("content")

            if content:
                technologies.append(content)

        # ======================================================
        # REMOVE DUPLICATES
        # ======================================================

        technologies = sorted(list(set(technologies)))

        result["technologies"] = technologies

    except requests.exceptions.Timeout:

        print("[Technology Detection] Request Timed Out")

        result["server"] = "Unknown"
        result["technologies"] = []

    except requests.exceptions.ConnectionError:

        print("[Technology Detection] Connection Error")

        result["server"] = "Unknown"
        result["technologies"] = []

    except Exception as e:

        print("[Technology Detection Error]", e)

        result["server"] = "Unknown"
        result["technologies"] = []

    result["classified"] = classify_technologies(result["technologies"], result["server"])

    # ======================================================
    # SAVE TO DATABASE
    # ======================================================

    if result["server"] != "Unknown" or result["technologies"]:

        save_technology(
            url,
            result["server"],
            result["technologies"]
        )

    return result


# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    url = input("Enter URL: ").strip()

    result = detect_technology(url)

    print("\nTechnology Detection Result")
    print("=" * 60)
    print("Server:", result["server"])
    print("\nDetected Technologies:")
    for tech in result["technologies"]:
        print(" -", tech)
    print("\nClassified Technologies:")
    for cat, items in result["classified"].items():
        print(f" {cat}: {', '.join(items) if items else 'None'}")
