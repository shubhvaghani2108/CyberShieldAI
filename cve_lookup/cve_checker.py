import os
import sys
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from scanner.cve_scanner import get_cve_info
except ImportError:
    def get_cve_info(port, service=""):
        return {
            "cve_id": f"CVE-GENERIC-P{port}",
            "severity": "Medium",
            "description": f"Exposed open service on port {port} ({service})."
        }

DB_FILE = os.path.join(BASE_DIR, "cybershield.db")
if not os.path.exists(DB_FILE):
    DB_FILE = "cybershield.db"

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Query ports table first, falling back to vulnerabilities table
try:
    cursor.execute("SELECT ip, port, service FROM ports")
    rows = cursor.fetchall()
except sqlite3.OperationalError:
    rows = []

if not rows:
    try:
        cursor.execute("SELECT ip, port, service FROM vulnerabilities")
        rows = cursor.fetchall()
    except sqlite3.OperationalError:
        rows = []

print("\nCVE REPORT — ALL SCANNABLE PORTS")
print("=" * 75)

if not rows:
    print("No open ports or vulnerabilities recorded in database.")
else:
    for ip, port, service in rows:
        cve_data = get_cve_info(port, service)
        cve_id = cve_data.get("cve_id", f"CVE-GENERIC-P{port}")
        desc = cve_data.get("description", "Exposed port service")
        severity = cve_data.get("severity", "Info")
        print(f"IP:{ip:<15} | Port:{port:<5} | Service:{service:<12} | Severity:{severity:<8} | {cve_id:<18} | {desc}")

conn.close()