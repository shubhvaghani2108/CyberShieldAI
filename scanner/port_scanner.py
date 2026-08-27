import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import sqlite3
import socket
from datetime import datetime
import nmap

from scanner.nmap_utils import get_nmap_path
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1.5)
        s.connect((ip, port))

        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass

        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()

        if banner:
            return banner[:200]
        return "No banner"
    except:
        return "No banner"


COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    27017: "mongodb",
}


def scan_target(target, ports="1-65535", progress_callback=None, scan_id=None):
    """
    Two-phase full port scan preserving historical data linked via scan_id.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def report(msg):
        print(f"[+] {msg}")
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    report(f"Starting scan for {target} (ports={ports}) [scan_id={scan_id}]")

    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()

    try:
        # =====================================================
        # PHASE 1: FAST DISCOVERY (no -sV, no -O)
        # =====================================================
        report("Phase 1/2: Discovering open ports (fast sweep)...")

        discovery_scanner = nmap.PortScanner(nmap_search_path=(get_nmap_path(),))
        discovery_args = "-Pn -T4 --min-rate 1000 --max-retries 2 --host-timeout 45s --max-rtt-timeout 600ms"

        if ports.startswith("top-"):
            top_n = ports.split("-")[1]
            discovery_scanner.scan(
                target, arguments=f"{discovery_args} --top-ports {top_n}"
            )
        else:
            discovery_scanner.scan(target, ports, arguments=discovery_args)

        if not discovery_scanner.all_hosts():
            report("No host found / no open ports detected.")
            conn.close()
            return {
                "target_ip": target,
                "host_status": "Scanned",
                "scan_time": scan_time,
                "ports_count": 0,
            }

        open_ports_dict = {}
        for host in discovery_scanner.all_hosts():
            for proto in discovery_scanner[host].all_protocols():
                p_keys = discovery_scanner[host][proto].keys()
                for p in p_keys:
                    p_info = discovery_scanner[host][proto][p]
                    if p_info.get("state") == "open":
                        p_service = p_info.get("name", "unknown")
                        if not p_service or p_service == "unknown":
                            p_service = COMMON_PORTS.get(p, "unknown")
                        open_ports_dict[p] = {
                            "proto": proto,
                            "service": p_service,
                            "product": p_info.get("product", ""),
                            "version": p_info.get("version", ""),
                            "extra_info": p_info.get("extrainfo", ""),
                            "state": "open",
                        }

        if not open_ports_dict:
            report("Phase 1 complete: no open ports found.")
            conn.close()
            return {
                "target_ip": target,
                "host_status": "Scanned",
                "scan_time": scan_time,
                "ports_count": 0,
            }

        open_ports = sorted(list(open_ports_dict.keys()))
        report(f"Phase 1 complete: {len(open_ports)} open port(s) found -> {open_ports}")

        # =====================================================
        # PHASE 2: TARGETED DETAIL SCAN (only on open ports)
        # =====================================================
        report("Phase 2/2: Running service/version + OS detection on open ports...")

        os_saved = False
        try:
            cursor.execute("PRAGMA table_info(os_info)")
            os_cols = [r[1] for r in cursor.fetchall()]
            if "scan_id" not in os_cols:
                try:
                    cursor.execute("ALTER TABLE os_info ADD COLUMN scan_id TEXT")
                except Exception:
                    pass

            detail_scanner = nmap.PortScanner(nmap_search_path=(get_nmap_path(),))
            port_list = ",".join(str(p) for p in open_ports)
            detail_args = "-Pn -T4 -sV --version-intensity 2 --host-timeout 45s --max-rtt-timeout 800ms"

            detail_scanner.scan(target, port_list, arguments=detail_args)

            for host in detail_scanner.all_hosts():
                # ---------------- OS INFO ----------------
                os_matches = detail_scanner[host].get("osmatch", [])
                if os_matches:
                    best = os_matches[0]
                    os_name = best.get("name", "Unknown")
                    accuracy = best.get("accuracy", "")
                    osclass = best.get("osclass", [{}])
                    device_type = osclass[0].get("type", "Unknown") if osclass else "Unknown"
                    os_details = f"Accuracy: {accuracy}%"
                else:
                    os_name = "Unknown"
                    device_type = "Unknown"
                    os_details = "OS could not be determined"

                cursor.execute(
                    """
                    INSERT INTO os_info (scan_id, ip, os_name, device_type, os_details, scan_time)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, host, os_name, device_type, os_details, scan_time),
                )
                os_saved = True

                # ---------------- MERGE DETAILED SERVICES ----------------
                for proto in detail_scanner[host].all_protocols():
                    for port in detail_scanner[host][proto].keys():
                        port_data = detail_scanner[host][proto][port]
                        if port_data.get("state") == "open" or port in open_ports_dict:
                            if port not in open_ports_dict:
                                open_ports_dict[port] = {"proto": proto, "state": "open"}
                            
                            svc_name = port_data.get("name")
                            if svc_name and svc_name != "unknown":
                                open_ports_dict[port]["service"] = svc_name
                            elif not open_ports_dict[port].get("service") or open_ports_dict[port]["service"] == "unknown":
                                open_ports_dict[port]["service"] = COMMON_PORTS.get(port, "unknown")
                            
                            if port_data.get("product"):
                                open_ports_dict[port]["product"] = port_data["product"]
                            if port_data.get("version"):
                                open_ports_dict[port]["version"] = port_data["version"]
                            if port_data.get("extrainfo"):
                                open_ports_dict[port]["extra_info"] = port_data["extrainfo"]
        except Exception as e:
            report(f"Detailed inspection note: {e}")

        if not os_saved:
            cursor.execute(
                """
                INSERT INTO os_info (scan_id, ip, os_name, device_type, os_details, scan_time)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, "Unknown", "General Purpose / Server", "Heuristic network profile", scan_time),
            )

        # =====================================================
        # SAVE ALL DISCOVERED PORTS TO DATABASE
        # =====================================================
        total_ports = 0
        for port, p_info in open_ports_dict.items():
            proto = p_info.get("proto", "tcp")
            service = p_info.get("service") or COMMON_PORTS.get(port, "unknown")
            product = p_info.get("product", "")
            version = p_info.get("version", "")
            extra_info = p_info.get("extra_info", "")
            state = "open"

            banner = grab_banner(target, port)

            report(
                f"Port {port}/{proto} OPEN | service={service} "
                f"product={product} version={version}"
            )

            cursor.execute(
                """
                INSERT INTO ports (scan_id, ip, port, state, service, banner, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, port, state, service, banner, scan_time),
            )

            cursor.execute(
                """
                INSERT INTO service_versions
                (scan_id, ip, port, service, product, version, extra_info, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, port, service, product, version, extra_info, scan_time),
            )
            total_ports += 1

        conn.commit()
        conn.close()

        report(f"Scan completed successfully: {total_ports} open port(s) profiled.")

        return {
            "scan_id": scan_id,
            "target_ip": target,
            "host_status": "Scanned",
            "scan_time": scan_time,
            "ports_count": total_ports,
        }

    except Exception as e:
        conn.close()
        report(f"Port scan error: {e}")
        return {
            "scan_id": scan_id,
            "target_ip": target,
            "host_status": "Error",
            "scan_time": scan_time,
            "ports_count": 0,
        }


if __name__ == "__main__":
    target = input("Enter Target IP: ").strip()
    result = scan_target(target)
    print("\nScan Result:", result)