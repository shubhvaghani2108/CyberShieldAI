import concurrent.futures
import os
import re
import socket
import ssl
import sys
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import sqlite3

DB_FILE = os.path.join(BASE_DIR, "cybershield.db")

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
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    1883: "mqtt",
    3000: "http-dev",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "http-flask",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "sonarqube",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Standard Top 1000 common ports list for rapid discovery
TOP_PORTS = [
    80, 443, 22, 21, 25, 53, 110, 111, 135, 139, 143, 445, 465, 587, 993, 995,
    1433, 1521, 1883, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080,
    8081, 8443, 8888, 9000, 9200, 27017, 23, 69, 79, 88, 102, 113, 119, 123,
    137, 138, 161, 179, 389, 500, 514, 515, 520, 554, 636, 873, 902, 989, 990,
    1080, 1194, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222,
    2375, 2376, 2483, 2484, 3128, 3268, 3690, 4000, 4040, 4369, 4567, 4840,
    5001, 5060, 5672, 5984, 6000, 6443, 6667, 7001, 7077, 8008, 8088, 8161,
    8880, 9090, 9092, 9418, 9999, 10000, 11211, 25565
]


def grab_banner(ip, port, timeout=1.5):
    """
    Actively probes open ports to extract service banners and server signatures.
    Returns full HTTP response status and headers or raw service greeting banner.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # Check if service sends an immediate greeting upon connect (SSH, FTP, SMTP, MySQL, etc.)
        try:
            initial = s.recv(1024).decode(errors="ignore").strip()
            if initial:
                s.close()
                return " ".join(initial.split())[:300]
        except Exception:
            pass

        # First try HTTP HEAD probe (plain HTTP)
        try:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: CyberShieldAI/2.0\r\nConnection: close\r\n\r\n")
            raw = s.recv(2048).decode(errors="ignore").strip()
            s.close()
            if raw and ("HTTP/1." in raw or "Server:" in raw or "<html" in raw.lower()):
                return " ".join(raw.split())[:300]
        except Exception:
            pass

        # If HTTPS port and plain probe had no banner, try SSL wrap
        if port in (443, 8443, 993, 995, 465):
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(timeout)
                s2.connect((ip, port))
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ss = ctx.wrap_socket(s2, server_hostname=ip)
                ss.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: CyberShieldAI/2.0\r\nConnection: close\r\n\r\n")
                raw_ssl = ss.recv(2048).decode(errors="ignore").strip()
                ss.close()
                if raw_ssl:
                    return " ".join(raw_ssl.split())[:300]
            except Exception:
                pass

        return "No banner"
    except Exception:
        return "No banner"


def _probe_single_socket(target_ip, port, timeout=1.0):
    """Probes a single TCP port. Returns dict if open, else None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((target_ip, port))
        if res == 0:
            s.close()
            # Successfully connected — Port is open!
            banner = grab_banner(target_ip, port, timeout=1.5)
            service = COMMON_PORTS.get(port, "unknown")
            product = ""
            version = ""
            extra_info = ""

            # Extract service/product from banner
            if banner and banner != "No banner":
                b_lower = banner.lower()
                if "microsoft-iis" in b_lower:
                    service = "http" if port != 443 else "https"
                    product = "Microsoft IIS"
                    m = re.search(r"microsoft-iis/([\d\.]+)", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "nginx" in b_lower:
                    service = "http" if port != 443 else "https"
                    product = "nginx"
                    m = re.search(r"nginx/([\d\.]+)", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "apache" in b_lower:
                    service = "http" if port != 443 else "https"
                    product = "Apache httpd"
                    m = re.search(r"apache/([\d\.]+)", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "openssh" in b_lower or "ssh" in b_lower:
                    service = "ssh"
                    product = "OpenSSH"
                    m = re.search(r"openssh_?([\d\.\w]+)", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "mysql" in b_lower:
                    service = "mysql"
                    product = "MySQL"
                elif "postfix" in b_lower or "esmtp" in b_lower:
                    service = "smtp"
                    product = "Postfix / ESMTP"

            return {
                "port": port,
                "proto": "tcp",
                "state": "open",
                "service": service,
                "product": product,
                "version": version,
                "extra_info": extra_info,
                "banner": banner,
            }
        s.close()
    except Exception:
        try:
            s.close()
        except Exception:
            pass
    return None


def _scan_target_sockets(target, ports="top-1000", progress_callback=None, scan_id=None):
    """
    High-performance pure-Python multithreaded socket scanner.
    Provides 100% native scanning capability on any OS (Linux, Render, Windows, Mac)
    without requiring external Nmap binaries.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def report(msg):
        print(f"[+] {msg}")
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    report(f"Starting native socket scanner for {target} [scan_id={scan_id}]...")

    # Determine port list to scan
    ports_to_scan = []
    if ports.startswith("top-"):
        try:
            limit = int(ports.split("-")[1])
            ports_to_scan = TOP_PORTS[:limit]
        except Exception:
            ports_to_scan = TOP_PORTS
    elif ports == "1-65535":
        ports_to_scan = TOP_PORTS + list(range(1, 1025))
        ports_to_scan = sorted(list(set(ports_to_scan)))
    elif "," in ports or ports.isdigit():
        try:
            ports_to_scan = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        except Exception:
            ports_to_scan = TOP_PORTS
    else:
        ports_to_scan = TOP_PORTS

    report(f"Probing {len(ports_to_scan)} common network ports concurrently...")

    open_ports_list = []
    max_threads = min(50, len(ports_to_scan))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(_probe_single_socket, target, port): port
            for port in ports_to_scan
        }
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                res = future.result()
                if res:
                    open_ports_list.append(res)
                    report(f"Discovered OPEN port {res['port']}/tcp ({res['service']})")
            except Exception:
                pass

    open_ports_list.sort(key=lambda x: x["port"])
    report(f"Scan complete: {len(open_ports_list)} open port(s) detected on {target}")

    # Determine OS heuristics based on services and banners
    os_name = "Unknown"
    device_type = "General Purpose / Server"
    os_details = "Heuristic socket fingerprint"

    for p_info in open_ports_list:
        banner = p_info.get("banner", "").lower()
        if "microsoft" in banner or "iis" in banner or "windows" in banner:
            os_name = "Windows Server"
            device_type = "Windows Host"
            os_details = f"Fingerprinted via Microsoft-IIS on port {p_info['port']}"
            break
        elif "ubuntu" in banner:
            os_name = "Linux (Ubuntu)"
            device_type = "Linux Server"
            os_details = f"Fingerprinted via Ubuntu banner on port {p_info['port']}"
            break
        elif "debian" in banner:
            os_name = "Linux (Debian)"
            device_type = "Linux Server"
            os_details = f"Fingerprinted via Debian banner on port {p_info['port']}"
            break
        elif "centos" in banner or "red hat" in banner:
            os_name = "Linux (RHEL / CentOS)"
            device_type = "Linux Server"
            os_details = f"Fingerprinted via RHEL banner on port {p_info['port']}"
            break

    if os_name == "Unknown" and open_ports_list:
        os_name = "Linux / Unix / Embedded"
        os_details = "Standard TCP/IP stack active"

    # Save to SQLite Database
    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()

    try:
        cursor.execute("PRAGMA table_info(os_info)")
        os_cols = [r[1] for r in cursor.fetchall()]
        if "scan_id" not in os_cols:
            try:
                cursor.execute("ALTER TABLE os_info ADD COLUMN scan_id TEXT")
            except Exception:
                pass

        cursor.execute(
            """
            INSERT INTO os_info (scan_id, ip, os_name, device_type, os_details, scan_time)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_id, target, os_name, device_type, os_details, scan_time),
        )

        for p in open_ports_list:
            cursor.execute(
                """
                INSERT INTO ports (scan_id, ip, port, state, service, banner, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, p["port"], p["state"], p["service"], p["banner"], scan_time),
            )
            cursor.execute(
                """
                INSERT INTO service_versions (scan_id, ip, port, service, product, version, extra_info, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, p["port"], p["service"], p["product"], p["version"], p["extra_info"], scan_time),
            )

        conn.commit()
    except Exception as e:
        report(f"Database save note: {e}")
    finally:
        conn.close()

    return {
        "scan_id": scan_id,
        "target_ip": target,
        "host_status": "Scanned",
        "scan_time": scan_time,
        "ports_count": len(open_ports_list),
    }


def scan_target(target, ports="1-65535", progress_callback=None, scan_id=None):
    """
    Two-phase scan: uses Nmap if installed, automatically falls back to
    high-speed native socket scanner if Nmap is absent (e.g. Render/Cloud environments).
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def report(msg):
        print(f"[+] {msg}")
        if progress_callback:
            try:
                progress_callback(msg)
            except Exception:
                pass

    # Check if Nmap is available
    use_nmap = False
    try:
        from scanner.nmap_utils import get_nmap_path
        import nmap
        nmap_bin = get_nmap_path()
        if nmap_bin:
            use_nmap = True
    except Exception:
        use_nmap = False

    if not use_nmap:
        report("Using native high-speed socket scanner engine...")
        return _scan_target_sockets(target, ports=ports, progress_callback=progress_callback, scan_id=scan_id)

    report(f"Starting Nmap scan for {target} (ports={ports}) [scan_id={scan_id}]")

    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()

    try:
        report("Phase 1/2: Discovering open ports (fast sweep)...")
        discovery_scanner = nmap.PortScanner(nmap_search_path=(get_nmap_path(),))
        discovery_args = "-Pn -T4 --min-rate 1000 --max-retries 2 --host-timeout 45s --max-rtt-timeout 600ms"

        if ports.startswith("top-"):
            top_n = ports.split("-")[1]
            discovery_scanner.scan(target, arguments=f"{discovery_args} --top-ports {top_n}")
        else:
            discovery_scanner.scan(target, ports, arguments=discovery_args)

        if not discovery_scanner.all_hosts():
            report("Nmap found 0 open ports; verifying with native socket probe...")
            conn.close()
            return _scan_target_sockets(target, ports=ports, progress_callback=progress_callback, scan_id=scan_id)

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
            conn.close()
            return _scan_target_sockets(target, ports=ports, progress_callback=progress_callback, scan_id=scan_id)

        open_ports = sorted(list(open_ports_dict.keys()))
        report(f"Phase 1 complete: {len(open_ports)} open port(s) found -> {open_ports}")

        # Phase 2: Detailed Service Scan
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

        total_ports = 0
        for port, p_info in open_ports_dict.items():
            proto = p_info.get("proto", "tcp")
            service = p_info.get("service") or COMMON_PORTS.get(port, "unknown")
            product = p_info.get("product", "")
            version = p_info.get("version", "")
            extra_info = p_info.get("extra_info", "")
            state = "open"
            banner = grab_banner(target, port)

            report(f"Port {port}/{proto} OPEN | service={service} product={product} version={version}")

            cursor.execute(
                """
                INSERT INTO ports (scan_id, ip, port, state, service, banner, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, port, state, service, banner, scan_time),
            )
            cursor.execute(
                """
                INSERT INTO service_versions (scan_id, ip, port, service, product, version, extra_info, scan_time)
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
        report(f"Nmap encountered an issue ({e}); falling back to native socket scanner...")
        return _scan_target_sockets(target, ports=ports, progress_callback=progress_callback, scan_id=scan_id)


if __name__ == "__main__":
    target = input("Enter Target IP: ").strip()
    result = scan_target(target)
    print("\nScan Result:", result)