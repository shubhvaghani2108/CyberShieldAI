import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from datetime import datetime
import nmap
from database.db_engine import get_db_connection

from scanner.nmap_utils import get_nmap_path

DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


# ==========================================================
# SERVICE VERSION DETECTOR
# ==========================================================
def detect_services(target_ip, scan_id=None):

    print(f"\n[+] Detecting Service Versions for {target_ip} [scan_id={scan_id}]...")

    scanner = nmap.PortScanner(
        nmap_search_path=(get_nmap_path(),)
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    # -------------------------------------------------------
    # Ensure table exists with correct schema
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_versions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id   TEXT,
            ip        TEXT,
            port      INTEGER,
            service   TEXT,
            product   TEXT,
            version   TEXT,
            extra_info TEXT,
            scan_time TEXT
        )
    """)
    cursor.execute("PRAGMA table_info(service_versions)")
    cols = [r[1] for r in cursor.fetchall()]
    if "scan_id" not in cols:
        try:
            cursor.execute("ALTER TABLE service_versions ADD COLUMN scan_id TEXT")
        except Exception:
            pass
    conn.commit()

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        scanner.scan(
            target_ip,
            arguments="-sV --version-light -Pn -T4"
            )

        if not scanner.all_hosts():
            print("[!] No host found.")
            conn.close()
            return []

        results = []

        for host in scanner.all_hosts():

            print(f"\nHost : {host}")

            for proto in scanner[host].all_protocols():

                ports = sorted(scanner[host][proto].keys())

                for port in ports:

                    service_data = scanner[host][proto][port]

                    if service_data["state"] != "open":
                        continue

                    service = service_data.get("name", "")
                    product = service_data.get("product", "")
                    version = service_data.get("version", "")
                    extra   = service_data.get("extrainfo", "")

                    print("=" * 60)
                    print("Port      :", port)
                    print("Service   :", service)
                    print("Product   :", product)
                    print("Version   :", version)
                    print("Extra Info:", extra)

                    cursor.execute("""
                        INSERT INTO service_versions
                        (
                            scan_id,
                            ip,
                            port,
                            service,
                            product,
                            version,
                            extra_info,
                            scan_time
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        host,
                        port,
                        service,
                        product,
                        version,
                        extra,
                        scan_time
                    ))

                    results.append({
                        "scan_id":    scan_id,
                        "ip":         host,
                        "port":       port,
                        "service":    service,
                        "product":    product,
                        "version":    version,
                        "extra_info": extra
                    })

        conn.commit()
        conn.close()

        print("\n[+] Service Version Detection Completed.")
        print("[+] Data Saved Successfully.")

        return results

    except Exception as e:

        conn.close()
        print("[!] Service Detection Error:", e)
        return []


# ==========================================================
# TEST
# ==========================================================
if __name__ == "__main__":

    target = input("Enter Target IP : ").strip()
    result = detect_services(target)

    print("\nReturned Result:\n")
    for item in result:
        print(item)