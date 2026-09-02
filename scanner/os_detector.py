import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import subprocess
from datetime import datetime
from database.db_engine import get_db_connection

from scanner.nmap_utils import get_nmap_path

DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


# ==========================================================
# OPERATING SYSTEM DETECTOR
# ==========================================================
def detect_os(target_ip, scan_id=None):

    print(f"\n[+] Detecting Operating System for {target_ip} [scan_id={scan_id}]...\n")

    try:
        nmap_path = get_nmap_path()

        # --------------------------------------------------
        # Quick Host Check
        # --------------------------------------------------
        ping = subprocess.run(
            [
                nmap_path,
                "-sn",
                "-Pn",
                target_ip
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

        if "Host is up" not in ping.stdout:
            print("[!] Host is not reachable.")
            return None

        # --------------------------------------------------
        # Fast OS Detection
        # --------------------------------------------------
        result = subprocess.run(
            [
                nmap_path,
                "-O",
                "-Pn",
                "-T4",
                "--max-retries", "1",
                "--host-timeout", "15s",
                target_ip
            ],
            capture_output=True,
            text=True,
            timeout=25
        )

        output = result.stdout

        os_name = "Unknown"
        device_type = "Unknown"
        os_details = "Unknown"

        for line in output.splitlines():

            line = line.strip()

            if line.startswith("Running:"):
                os_name = line.replace("Running:", "").strip()

            elif line.startswith("Device type:"):
                device_type = line.replace("Device type:", "").strip()

            elif line.startswith("OS details:"):
                os_details = line.replace("OS details:", "").strip()

        print("Device Type :", device_type)
        print("OS Name     :", os_name)
        print("OS Details  :", os_details)

        # --------------------------------------------------
        # Database
        # --------------------------------------------------
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS os_info(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            ip TEXT,
            os_name TEXT,
            device_type TEXT,
            os_details TEXT,
            scan_time TEXT
        )
        """)
        cursor.execute("PRAGMA table_info(os_info)")
        cols = [r[1] for r in cursor.fetchall()]
        if "scan_id" not in cols:
            try:
                cursor.execute("ALTER TABLE os_info ADD COLUMN scan_id TEXT")
            except Exception:
                pass

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
        INSERT INTO os_info
        (
            scan_id,
            ip,
            os_name,
            device_type,
            os_details,
            scan_time
        )
        VALUES
        (?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            target_ip,
            os_name,
            device_type,
            os_details,
            scan_time
        ))

        conn.commit()
        conn.close()

        print("\n[+] Operating System saved successfully.")

        return {
            "scan_id": scan_id,
            "ip": target_ip,
            "os_name": os_name,
            "device_type": device_type,
            "os_details": os_details,
            "scan_time": scan_time
        }

    except Exception as e:

        print("[!] OS Detection Error:", e)

        return None


# ==========================================================
# TEST
# ==========================================================
if __name__ == "__main__":

    target = input("Enter Target IP : ").strip()

    result = detect_os(target)

    print("\nResult\n")

    print(result)