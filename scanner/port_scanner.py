import concurrent.futures
import os
import re
import socket
import ssl
import sys
import uuid
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_engine import get_db_connection

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

# Standard Top common service ports list for rapid discovery
TOP_PORTS = [
    80, 443, 22, 21, 25, 53, 110, 111, 135, 139, 143, 445, 465, 587, 993, 995,
    1433, 1521, 1883, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080,
    8081, 8443, 8888, 9000, 9200, 27017, 23, 69, 79, 88, 102, 113, 119, 123,
    137, 138, 161, 179, 389, 500, 514, 515, 520, 554, 636, 873, 902, 989, 990,
    1080, 1194, 1723, 2049, 2181, 2222, 2375, 2376, 2483, 2484, 3128, 3268,
    3690, 4000, 4040, 4369, 4567, 4840, 5001, 5060, 5672, 5984, 6000, 6443,
    6667, 7001, 7077, 8008, 8088, 8161, 9090, 9092, 9418, 9999, 10000, 11211,
    25565
]


def _is_ip_string(s):
    if not s:
        return False
    try:
        parts = s.strip().split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def grab_banner(ip, port, timeout=1.5, hostname=None):
    """
    Actively probes open ports to extract service banners and server signatures.
    Supports virtual host headers (domain name) when scanning a domain, or direct IP
    when scanning an IP target.
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

        # Build candidate Host headers: domain if explicitly provided (URL scan), else IP (pure IP scan)
        host_candidates = []
        if hostname and hostname.strip() and not _is_ip_string(hostname.strip()):
            host_candidates.append(hostname.strip())

        if ip not in host_candidates:
            host_candidates.append(ip)

        for host_hdr in host_candidates:
            # 1. First try HTTP HEAD probe (plain HTTP)
            try:
                s_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s_probe.settimeout(timeout)
                s_probe.connect((ip, port))
                s_probe.send(b"HEAD / HTTP/1.1\r\nHost: " + host_hdr.encode() + b"\r\nUser-Agent: CyberShieldAI/2.0\r\nConnection: close\r\n\r\n")
                raw = s_probe.recv(2048).decode(errors="ignore").strip()
                s_probe.close()
                if raw and ("HTTP/1." in raw or "Server:" in raw or "<html" in raw.lower()):
                    if not raw.startswith("HTTP/1.1 404") or host_hdr == host_candidates[-1]:
                        return " ".join(raw.split())[:300]
            except Exception:
                pass

            # 2. If HTTPS port and plain probe had no banner, try SSL wrap
            if port in (443, 8443, 993, 995, 465):
                try:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(timeout)
                    s2.connect((ip, port))
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ss = ctx.wrap_socket(s2, server_hostname=host_hdr)
                    ss.send(b"HEAD / HTTP/1.1\r\nHost: " + host_hdr.encode() + b"\r\nUser-Agent: CyberShieldAI/2.0\r\nConnection: close\r\n\r\n")
                    raw_ssl = ss.recv(2048).decode(errors="ignore").strip()
                    ss.close()
                    if raw_ssl:
                        return " ".join(raw_ssl.split())[:300]
                except Exception:
                    pass

        return "No banner"
    except Exception:
        return "No banner"


def _probe_single_socket(target_ip, port, timeout=1.0, hostname=None):
    """Probes a single TCP port. Returns dict if open, else None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((target_ip, port))
        if res == 0:
            s.close()
            # Successfully connected — Port is open!
            banner = grab_banner(target_ip, port, timeout=1.5, hostname=hostname)
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
                elif "vsftpd" in b_lower:
                    service = "ftp"
                    product = "vsftpd"
                    m = re.search(r"vsftpd\s*\(?([\d\.]+)\)?", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "pure-ftpd" in b_lower:
                    service = "ftp"
                    product = "Pure-FTPd"
                elif "proftpd" in b_lower:
                    service = "ftp"
                    product = "ProFTPD"
                    m = re.search(r"proftpd\s*([\d\.]+)", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "dovecot" in b_lower:
                    product = "Dovecot"
                    m = re.search(r"dovecot\s*([\d\.]+)", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "postfix" in b_lower or "esmtp" in b_lower:
                    service = "smtp"
                    product = "Postfix / ESMTP"
                elif "exim" in b_lower:
                    service = "smtp"
                    product = "Exim"
                    m = re.search(r"exim\s*([\d\.]+)", banner, re.I)
                    if m:
                        version = m.group(1)
                elif "mysql" in b_lower:
                    service = "mysql"
                    product = "MySQL"
                    m = re.search(r"([\d\.]+(?:-[\w\.\-]+)?)", banner)
                    if m:
                        version = m.group(1)
                elif "postgresql" in b_lower:
                    service = "postgresql"
                    product = "PostgreSQL"
                elif "bind" in b_lower or "named" in b_lower:
                    service = "dns"
                    product = "BIND DNS"

            if not product and service and service != "unknown":
                product = service.upper()

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


def deduce_os_from_services_and_system(open_ports_info, target_ip, hostname=None):
    """
    Intelligently identifies Operating System, Device Type, and Platform Details
    using local system inspection (for self-scans), Windows/Linux/Mac port signatures,
    active network banners, and cloud CDN edge profiles.
    """
    import platform

    ports_list = []
    if isinstance(open_ports_info, dict):
        for p, d in open_ports_info.items():
            item = dict(d)
            item["port"] = int(p)
            ports_list.append(item)
    elif isinstance(open_ports_info, list):
        ports_list = list(open_ports_info)

    open_port_numbers = {p.get("port") for p in ports_list}

    # 1. Localhost / Self-Scan Check
    is_self = False
    clean_ip = str(target_ip).strip()
    if clean_ip in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        is_self = True
    else:
        try:
            local_host_ips = set(socket.gethostbyname_ex(socket.gethostname())[2])
            local_host_ips.add(socket.gethostbyname(socket.gethostname()))
            if clean_ip in local_host_ips:
                is_self = True
        except Exception:
            pass

    if is_self:
        sys_name = platform.system()
        rel = platform.release()
        ver = platform.version()
        if sys_name == "Windows":
            win_ver = "Windows 11" if "11" in rel or (rel == "10" and int(ver.split(".")[2]) >= 22000 if ver.count(".") >= 2 and ver.split(".")[2].isdigit() else False) else f"Windows {rel}"
            return {
                "os_name": f"Microsoft Windows ({win_ver})",
                "device_type": "Personal Computer / Workstation",
                "os_details": f"Local Host Verified: {win_ver} (Build {ver})",
            }
        elif sys_name == "Linux":
            return {
                "os_name": f"Linux ({platform.platform()})",
                "device_type": "Linux Workstation / Server",
                "os_details": f"Local Host Verified: Linux Kernel {rel}",
            }
        elif sys_name == "Darwin":
            return {
                "os_name": f"Apple macOS ({rel})",
                "device_type": "Mac Workstation",
                "os_details": f"Local Host Verified: macOS {rel}",
            }

    # 2. Analyze banners and service products
    all_banners_text = " ".join(
        f"{p.get('service', '')} {p.get('product', '')} {p.get('banner', '')} {p.get('extra_info', '')}"
        for p in ports_list
    ).lower()

    # Windows Signature Check
    windows_ports = {135, 139, 445, 3389, 5357, 5985, 5986}
    matched_win_ports = open_port_numbers.intersection(windows_ports)

    has_win_banner = any(
        w in all_banners_text
        for w in [
            "microsoft", "windows", "microsoft-ds", "microsoft-httpapi", "netbios", "msrpc", "iis", "win32", "win64"
        ]
    )

    if matched_win_ports or has_win_banner:
        port_hints = []
        if 445 in matched_win_ports:
            port_hints.append("SMB (445)")
        if 135 in matched_win_ports:
            port_hints.append("MSRPC (135)")
        if 139 in matched_win_ports:
            port_hints.append("NetBIOS (139)")
        if 3389 in matched_win_ports:
            port_hints.append("RDP (3389)")

        details = f"Fingerprinted via Windows services: {', '.join(port_hints)}" if port_hints else "Fingerprinted via Microsoft service banner"

        if "iis" in all_banners_text:
            return {
                "os_name": "Microsoft Windows Server",
                "device_type": "Windows Server Host",
                "os_details": details + " (IIS active)",
            }
        return {
            "os_name": "Microsoft Windows (Windows 10 / 11 / Server)",
            "device_type": "Windows Workstation / Host",
            "os_details": details,
        }

    # Specific Linux Distros
    if "ubuntu" in all_banners_text:
        return {
            "os_name": "Ubuntu Linux",
            "device_type": "Linux Server",
            "os_details": "Fingerprinted via Ubuntu OpenSSH/web service banner",
        }
    if "debian" in all_banners_text:
        return {
            "os_name": "Debian Linux",
            "device_type": "Linux Server",
            "os_details": "Fingerprinted via Debian package signatures",
        }
    if any(k in all_banners_text for k in ["centos", "rhel", "red hat", "redhat", "fedora"]):
        return {
            "os_name": "Red Hat Enterprise Linux / CentOS",
            "device_type": "Linux Enterprise Server",
            "os_details": "Fingerprinted via Red Hat / CentOS enterprise banners",
        }
    if "alpine" in all_banners_text:
        return {
            "os_name": "Alpine Linux",
            "device_type": "Container / Micro-OS",
            "os_details": "Fingerprinted via Alpine Linux lightweight daemon",
        }
    if "freebsd" in all_banners_text or "openbsd" in all_banners_text:
        return {
            "os_name": "BSD Unix",
            "device_type": "Unix Server",
            "os_details": "Fingerprinted via BSD kernel banner",
        }

    # Cloud CDN Edge nodes (Akamai, Cloudflare, AWS CloudFront)
    if "akamai" in all_banners_text or (hostname and "edgekey.net" in str(hostname)):
        return {
            "os_name": "Linux (Akamai Edge OS / GHost)",
            "device_type": "Cloud CDN Edge Node",
            "os_details": "Enterprise Anycast CDN Node running hardened Linux kernel",
        }
    if "cloudflare" in all_banners_text:
        return {
            "os_name": "Linux (Cloudflare Edge OS)",
            "device_type": "Cloud CDN Edge Node",
            "os_details": "Cloudflare Global Edge Proxy on Linux",
        }
    if "cloudfront" in all_banners_text:
        return {
            "os_name": "Linux (Amazon CloudFront Edge)",
            "device_type": "Cloud CDN Edge Node",
            "os_details": "AWS CloudFront Edge Server on Linux",
        }

    # General Linux / Unix (OpenSSH, Nginx, Apache, Node, Express, Python)
    if 22 in open_port_numbers or any(k in all_banners_text for k in ["openssh", "nginx", "apache", "express", "k8s"]):
        evidence = "OpenSSH (Port 22)" if 22 in open_port_numbers else "web application stack"
        return {
            "os_name": "Linux / Unix Server",
            "device_type": "Cloud Server / Web Host",
            "os_details": f"Fingerprinted via standard {evidence}",
        }

    # Network Appliances / Routers (ports 53, 80, 8080 with lighttpd, rom-pager, mikrotik)
    if any(k in all_banners_text for k in ["mikrotik", "cisco", "dd-wrt", "openwrt", "zyxel", "rompager"]):
        return {
            "os_name": "Embedded Linux / Network OS",
            "device_type": "Router / Network Gateway",
            "os_details": "Embedded Network Appliance firmware",
        }

    # Fallback if ports are open
    if ports_list:
        return {
            "os_name": "TCP/IP Network Host",
            "device_type": "Network Device",
            "os_details": f"Active network host with {len(ports_list)} responsive port(s)",
        }

    return {
        "os_name": "Unknown",
        "device_type": "Unknown",
        "os_details": "OS could not be determined",
    }


def _scan_target_sockets(target, ports="top-1000", progress_callback=None, scan_id=None, hostname=None):
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
            executor.submit(_probe_single_socket, target, port, hostname=hostname): port
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

    # Determine OS heuristics using multi-layer signature detector
    deduced = deduce_os_from_services_and_system(open_ports_list, target, hostname=hostname)
    os_name = deduced["os_name"]
    device_type = deduced["device_type"]
    os_details = deduced["os_details"]

    # Save to Database
    conn = get_db_connection()
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
            c_banner = (p.get("banner") or "").replace("\x00", "")
            c_service = (p.get("service") or "").replace("\x00", "")
            c_product = (p.get("product") or "").replace("\x00", "")
            c_version = (p.get("version") or "").replace("\x00", "")
            c_extra = (p.get("extra_info") or "").replace("\x00", "")
            cursor.execute(
                """
                INSERT INTO ports (scan_id, ip, port, state, service, banner, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, p["port"], p["state"], c_service, c_banner, scan_time),
            )
            cursor.execute(
                """
                INSERT INTO service_versions (scan_id, ip, port, service, product, version, extra_info, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, p["port"], c_service, c_product, c_version, c_extra, scan_time),
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


def scan_target(target, ports="top-1000", progress_callback=None, scan_id=None, hostname=None):
    """
    Scans a target (IP or domain name) using Nmap when available,
    falling back seamlessly to native high-concurrency socket scanning.
    """
    if not scan_id:
        scan_id = uuid.uuid4().hex

    if not hostname and not _is_ip_string(target):
        hostname = target

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
        return _scan_target_sockets(target, ports=ports, progress_callback=progress_callback, scan_id=scan_id, hostname=hostname)

    report(f"Starting Nmap scan for {target} (ports={ports}) [scan_id={scan_id}]")

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
            return _scan_target_sockets(target, ports=ports, progress_callback=progress_callback, scan_id=scan_id, hostname=hostname)

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
            return _scan_target_sockets(target, ports=ports, progress_callback=progress_callback, scan_id=scan_id, hostname=hostname)

        open_ports = sorted(list(open_ports_dict.keys()))
        report(f"Phase 1 complete: {len(open_ports)} open port(s) found -> {open_ports}")

        # Phase 2: Detailed Service Scan
        report("Phase 2/2: Running service/version + OS detection on open ports...")
        os_info_list = []
        try:
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

                os_info_list.append((scan_id, host, os_name, device_type, os_details, scan_time))

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

        # Grab banners in memory before touching DB
        banners_dict = {}
        for port, p_info in open_ports_dict.items():
            proto = p_info.get("proto", "tcp")
            service = p_info.get("service") or COMMON_PORTS.get(port, "unknown")
            product = p_info.get("product", "")
            version = p_info.get("version", "")
            b_val = grab_banner(target, port, hostname=hostname)
            banners_dict[port] = b_val
            p_info["banner"] = b_val
            report(f"Port {port}/{proto} OPEN | service={service} product={product} version={version}")

        # If Nmap OS detection yielded Unknown or empty, apply intelligent heuristic deduction
        if not os_info_list or all(rec[2] in ("Unknown", None, "", "None") for rec in os_info_list):
            os_info_list = []
            deduced = deduce_os_from_services_and_system(open_ports_dict, target, hostname=hostname)
            os_info_list.append((scan_id, target, deduced["os_name"], deduced["device_type"], deduced["os_details"], scan_time))

        # Quick DB commit phase — hold connection for milliseconds only
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(os_info)")
            os_cols = [r["name"] if hasattr(r, "keys") else r[1] for r in cursor.fetchall()]
            if "scan_id" not in os_cols:
                try:
                    cursor.execute("ALTER TABLE os_info ADD COLUMN scan_id TEXT")
                except Exception:
                    pass

            for os_rec in os_info_list:
                cursor.execute(
                    """
                    INSERT INTO os_info (scan_id, ip, os_name, device_type, os_details, scan_time)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    os_rec,
                )

            total_ports = 0
            for port, p_info in open_ports_dict.items():
                service = (p_info.get("service") or COMMON_PORTS.get(port, "unknown") or "").replace("\x00", "")
                product = (p_info.get("product") or "").replace("\x00", "")
                version = (p_info.get("version") or "").replace("\x00", "")
                extra_info = (p_info.get("extra_info") or "").replace("\x00", "")
                state = "open"
                banner = (banners_dict.get(port) or "").replace("\x00", "")

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
        finally:
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