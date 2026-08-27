import os
import platform
import sqlite3
import subprocess
import socket
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def check_host_alive(target, scan_id=None):
    print(f"\n[+] Checking host availability for {target} [scan_id={scan_id}]...")

    alive = False
    status = "Unreachable"

    # ----------------------------------------------------
    # 1. ICMP PING PROBE
    # ----------------------------------------------------
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"

    try:
        cmd = ["ping", count_flag, "1", timeout_flag, "1500", target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout.lower()

        if "ttl=" in output or ("bytes=" in output and "destination host unreachable" not in output and "request timed out" not in output and result.returncode == 0):
            alive = True
            status = "Alive"
            print(f"[+] Host {target} is ALIVE (ICMP Response)")
    except Exception as e:
        print(f"[!] ICMP ping error: {e}")

    # ----------------------------------------------------
    # 2. MULTI-PORT TCP SOCKET PROBE (Bypasses ICMP Ping Firewalls)
    # ----------------------------------------------------
    if not alive:
        print(f"[+] ICMP ping un-responsive for {target}, testing TCP socket probes...")
        probe_ports = [80, 443, 22, 445, 8080, 53, 3389, 135, 3306, 8081, 8443, 21, 25, 1433, 5432, 27017]
        for port in probe_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.2)
            try:
                s.connect((target, port))
                s.close()
                alive = True
                status = "Alive"
                print(f"[+] Host {target} is ALIVE (TCP Port {port} Connected)")
                break
            except socket.timeout:
                s.close()
            except Exception as e:
                s.close()
                err_str = str(e).lower()
                # Connection refused means target network stack actively responded with RST — Host IS Alive!
                if "10061" in err_str or "refused" in err_str:
                    alive = True
                    status = "Alive"
                    print(f"[+] Host {target} is ALIVE (TCP Port {port} Refused)")
                    break

    # ----------------------------------------------------
    # 3. FAST NMAP SYN/DISCOVERY PROBE FALLBACK
    # ----------------------------------------------------
    if not alive:
        try:
            print(f"[+] TCP probes un-responsive, trying Nmap discovery for {target}...")
            import nmap
            from scanner.nmap_utils import get_nmap_path

            nm = nmap.PortScanner(nmap_search_path=(get_nmap_path(),))
            nm.scan(target, arguments="-Pn -F --host-timeout 5s")
            if nm.all_hosts():
                for h in nm.all_hosts():
                    for proto in nm[h].all_protocols():
                        for p in nm[h][proto]:
                            if nm[h][proto][p]["state"] in ["open", "closed"]:
                                alive = True
                                status = "Alive (Service Detected)"
                                print(f"[+] Host {target} is ALIVE (Nmap Service Detected on Port {p})")
                                break
                        if alive:
                            break
        except Exception as e:
            print(f"[!] Nmap discovery fallback error: {e}")

    if not alive:
        print(f"[!] Host {target} is NOT reachable via ICMP, TCP, or Nmap probes.")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS host_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            target_ip TEXT,
            status TEXT,
            scan_time TEXT
        )
    """)
    cursor.execute("PRAGMA table_info(host_status)")
    cols = [r[1] for r in cursor.fetchall()]
    if "scan_id" not in cols:
        try:
            cursor.execute("ALTER TABLE host_status ADD COLUMN scan_id TEXT")
        except Exception:
            pass

    cursor.execute("""
        INSERT INTO host_status (scan_id, target_ip, status, scan_time)
        VALUES (?, ?, ?, ?)
    """, (scan_id, target, status, scan_time))

    conn.commit()
    conn.close()

    return {
        "scan_id": scan_id,
        "alive": alive,
        "status": status,
        "scan_time": scan_time
    }


if __name__ == "__main__":
    target = input("Enter Target IP: ").strip()
    print(check_host_alive(target))