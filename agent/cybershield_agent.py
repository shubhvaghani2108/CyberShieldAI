#!/usr/bin/env python3
"""
CyberShieldAI Local Scan Agent
------------------------------
Runs on an internal/private LAN (e.g. your local computer or raspberry pi).
Polls your deployed CyberShieldAI cloud server for scan jobs targeting RFC 1918
private addresses (192.168.x.x, 10.x.x.x, etc.), executes a TCP port scan
locally with banner grabbing, and reports findings back to the server.

Usage:
    python cybershield_agent.py --token <YOUR_AGENT_TOKEN> --api https://cybershieldai.onrender.com
"""

import argparse
import concurrent.futures
import json
import socket
import sys
import time
import urllib.error
import urllib.request

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 1883, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8080, 8081, 8443, 8888, 9000, 9200, 27017
]

PORT_SERVICE_MAP = {
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
    3000: "http",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "http",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http",
    8080: "http-proxy",
    8081: "http",
    8443: "https-alt",
    8888: "http",
    9000: "http",
    9200: "elasticsearch",
    27017: "mongodb",
}


def scan_port(target, port, timeout=1.5):
    """Probes a single TCP port and attempts light banner grab."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((target, port))
        if res == 0:
            banner = ""
            try:
                s.settimeout(1.0)
                if port in (80, 8080, 8000, 5000, 3000, 8081, 8888, 9000):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port in (21, 22, 25, 110, 143):
                    pass  # Service automatically announces banner upon connect
                else:
                    s.sendall(b"\r\n")
                raw = s.recv(1024)
                banner = raw.decode("utf-8", errors="ignore").strip()
                # Clean up multiline banners
                if banner:
                    banner = banner.split("\n")[0].strip()
            except Exception:
                banner = ""

            return {
                "port": port,
                "state": "open",
                "service": PORT_SERVICE_MAP.get(port, "unknown"),
                "banner": banner,
                "product": "",
                "version": "",
                "extra_info": "Local Scan Agent (LAN)",
            }
        return None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def execute_scan(target):
    """Scans all designated common ports concurrently using a ThreadPoolExecutor."""
    print(f"\n[*] Starting local port scan for {target}...")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port): port for port in COMMON_PORTS
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"    [+] Port {result['port']}/tcp OPEN ({result['service']}) {result['banner'][:40]}")

    open_ports.sort(key=lambda x: x["port"])
    print(f"[*] Local scan complete for {target}. Found {len(open_ports)} open port(s).")
    return open_ports


def api_request(url, headers=None, data=None):
    """Performs an HTTP request using standard library urllib."""
    headers = headers or {}
    encoded_data = None
    if data is not None:
        encoded_data = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=encoded_data, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as response:
        resp_body = response.read().decode("utf-8")
        return json.loads(resp_body)


def main():
    parser = argparse.ArgumentParser(
        description="CyberShieldAI Local Scan Agent for RFC 1918 Private LANs"
    )
    parser.add_argument("--token", required=True, help="Agent authentication token from CyberShieldAI")
    parser.add_argument(
        "--api",
        default="https://cybershieldai.onrender.com",
        help="CyberShieldAI server API URL (e.g. https://cybershieldai.onrender.com or http://localhost:5000)",
    )
    args = parser.parse_args()

    api_url = args.api.rstrip("/")
    token = args.token.strip()

    print("==================================================")
    print("  CyberShieldAI — Local Scan Agent")
    print("==================================================")
    print(f"[*] Target Cloud Server: {api_url}")
    print(f"[*] Token: {token[:8]}...{token[-4:]}")
    print("[*] Polling for pending private LAN scan jobs every 5 seconds...")
    print("[*] Press Ctrl+C to stop.\n")

    while True:
        try:
            jobs_endpoint = f"{api_url}/api/agent/jobs"
            headers = {
                "X-Agent-Token": token,
                "User-Agent": "CyberShieldAI-LocalAgent/1.0",
            }
            res = api_request(jobs_endpoint, headers=headers)

            if res.get("status") == "success":
                jobs = res.get("jobs", [])
                for job in jobs:
                    job_id = job.get("job_id")
                    target = job.get("target")
                    scan_id = job.get("scan_id")

                    print(f"\n[!] New job assigned: job_id={job_id} target={target}")
                    open_ports = execute_scan(target)

                    # Post results back to server
                    results_endpoint = f"{api_url}/api/agent/results"
                    payload = {
                        "job_id": job_id,
                        "open_ports": open_ports,
                    }
                    print(f"[*] Reporting results for job {job_id} back to cloud server...")
                    post_res = api_request(results_endpoint, headers=headers, data=payload)
                    if post_res.get("status") == "success":
                        print(f"[+] Successfully reported job {job_id}. Cloud scan pipeline resumed!")
                    else:
                        print(f"[-] Warning: Server returned: {post_res}")

        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"[!] Authentication error (401): Invalid agent token. Please check your token.")
                time.sleep(10)
            else:
                print(f"[-] HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            print(f"[-] Connection error: {e.reason}. Retrying in 5 seconds...")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")

        time.sleep(5)


if __name__ == "__main__":
    main()
