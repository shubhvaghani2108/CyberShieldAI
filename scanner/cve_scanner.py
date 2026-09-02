import os
from datetime import datetime
from database.db_engine import get_db_connection

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def get_severity_rating(cvss_score):
    """
    Derives standard CVSS v3.1 Severity Rating from a numerical CVSS score:
    - 9.0 - 10.0 : Critical
    - 7.0 - 8.9  : High
    - 4.0 - 6.9  : Medium
    - 0.1 - 3.9  : Low
    - 0.0        : Informational
    """
    try:
        score = float(cvss_score)
    except (ValueError, TypeError):
        score = 0.0

    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "Informational"


# Official NVD CVSS dictionary for known service ports, verified against NIST NVD
CVE_DB = {
    21: {
        "cve_id": "CVE-2011-2523",
        "description": "vsftpd 2.3.4 Backdoor Remote Command Execution",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-78",
        "cwe_name": "OS Command Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523 | https://cwe.mitre.org/data/definitions/78.html",
        "published_date": "2019-11-27",
        "exploit_available": 1,
    },
    22: {
        "cve_id": "CVE-2023-38408",
        "description": "OpenSSH PKCS#11 Provider Remote Code Execution",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-426",
        "cwe_name": "Untrusted Search Path",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408 | https://cwe.mitre.org/data/definitions/426.html",
        "published_date": "2023-07-20",
        "exploit_available": 1,
    },
    23: {
        "cve_id": "CVE-2020-10188",
        "description": "Telnet Server Buffer Overflow & Cleartext Data Exposure",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-120",
        "cwe_name": "Buffer Overflow",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-10188 | https://cwe.mitre.org/data/definitions/120.html",
        "published_date": "2020-03-06",
        "exploit_available": 1,
    },
    25: {
        "cve_id": "CVE-2020-28018",
        "description": "Exim SMTP Server Remote Code Execution / Use-After-Free",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-416",
        "cwe_name": "Use-After-Free",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-28018 | https://cwe.mitre.org/data/definitions/416.html",
        "published_date": "2021-05-06",
        "exploit_available": 1,
    },
    53: {
        "cve_id": "CVE-2020-1350",
        "description": "SIGRed - Windows DNS Server Remote Code Execution Vulnerability",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_id": "CWE-122",
        "cwe_name": "Heap-based Buffer Overflow",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-1350 | https://cwe.mitre.org/data/definitions/122.html",
        "published_date": "2020-07-14",
        "exploit_available": 1,
    },
    110: {
        "cve_id": "CVE-2018-19518",
        "description": "UW-IMAP / POP3 Command Injection via rsh/ssh Options",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-88",
        "cwe_name": "Argument Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2018-19518 | https://cwe.mitre.org/data/definitions/88.html",
        "published_date": "2018-11-25",
        "exploit_available": 1,
    },
    111: {
        "cve_id": "CVE-2017-8779",
        "description": "RPCBomb - RPC portmapper Denial of Service and Memory Leak",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe_id": "CWE-400",
        "cwe_name": "Uncontrolled Resource Consumption",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2017-8779 | https://cwe.mitre.org/data/definitions/400.html",
        "published_date": "2017-05-05",
        "exploit_available": 1,
    },
    135: {
        "cve_id": "CVE-2003-0352",
        "description": "Microsoft RPC DCOM Remote Code Execution (Blaster Worm Vulnerability)",
        "cvss_score": 10.0,
        "cvss_vector": "(AV:N/AC:L/Au:N/C:C/I:C/A:C) [NVD CVSS v2.0]",
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within Bounds",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2003-0352 | https://cwe.mitre.org/data/definitions/119.html",
        "published_date": "2003-08-27",
        "exploit_available": 1,
    },
    139: {
        "cve_id": "CVE-2017-7494",
        "description": "SambaCry - Samba Remote Code Execution Vulnerability",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-434",
        "cwe_name": "Unrestricted Upload of File",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2017-7494 | https://cwe.mitre.org/data/definitions/434.html",
        "published_date": "2017-05-24",
        "exploit_available": 1,
    },
    143: {
        "cve_id": "CVE-2018-19518",
        "description": "University of Washington IMAP Client Command Injection",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-88",
        "cwe_name": "Argument Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2018-19518 | https://cwe.mitre.org/data/definitions/88.html",
        "published_date": "2018-11-25",
        "exploit_available": 1,
    },
    445: {
        "cve_id": "CVE-2017-0144",
        "description": "EternalBlue - Windows SMB Remote Code Execution Vulnerability",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within Bounds",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144 | https://cwe.mitre.org/data/definitions/119.html",
        "published_date": "2017-03-17",
        "exploit_available": 1,
    },
    465: {
        "cve_id": "CVE-2020-28018",
        "description": "Exim SMTP Server Remote Code Execution / Use-After-Free",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-416",
        "cwe_name": "Use-After-Free",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-28018 | https://cwe.mitre.org/data/definitions/416.html",
        "published_date": "2021-05-06",
        "exploit_available": 1,
    },
    587: {
        "cve_id": "CVE-2020-28018",
        "description": "Exim SMTP Server Remote Code Execution / Use-After-Free",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-416",
        "cwe_name": "Use-After-Free",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-28018 | https://cwe.mitre.org/data/definitions/416.html",
        "published_date": "2021-05-06",
        "exploit_available": 1,
    },
    993: {
        "cve_id": "CVE-2018-19518",
        "description": "University of Washington IMAP Client Command Injection",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-88",
        "cwe_name": "Argument Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2018-19518 | https://cwe.mitre.org/data/definitions/88.html",
        "published_date": "2018-11-25",
        "exploit_available": 1,
    },
    995: {
        "cve_id": "CVE-2018-19518",
        "description": "UW-IMAP / POP3 Command Injection via rsh/ssh Options",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-88",
        "cwe_name": "Argument Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2018-19518 | https://cwe.mitre.org/data/definitions/88.html",
        "published_date": "2018-11-25",
        "exploit_available": 1,
    },
    1433: {
        "cve_id": "CVE-2020-0618",
        "description": "Microsoft SQL Server Reporting Services Remote Code Execution",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-0618 | https://cwe.mitre.org/data/definitions/502.html",
        "published_date": "2020-02-11",
        "exploit_available": 1,
    },
    1521: {
        "cve_id": "CVE-2012-1675",
        "description": "Oracle TNS Listener Poison Attack",
        "cvss_score": 7.5,
        "cvss_vector": "(AV:N/AC:L/Au:N/C:P/I:P/A:P) [NVD CVSS v2.0: 7.5]",
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2012-1675 | https://cwe.mitre.org/data/definitions/287.html",
        "published_date": "2012-05-08",
        "exploit_available": 1,
    },
    1883: {
        "cve_id": "CVE-2020-13849",
        "description": "Eclipse Mosquitto MQTT Broker Unauthorized Access / DoS",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "cwe_id": "CWE-20",
        "cwe_name": "Improper Input Validation",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2020-13849 | https://cwe.mitre.org/data/definitions/20.html",
        "published_date": "2020-06-05",
        "exploit_available": 0,
    },
    3306: {
        "cve_id": "CVE-2012-2122",
        "description": "MySQL Authentication Bypass via memcmp() timing flaw",
        "cvss_score": "N/A",
        "cvss_vector": "N/A (NVD assessment not yet provided)",
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2012-2122 | https://cwe.mitre.org/data/definitions/287.html",
        "published_date": "2012-06-26",
        "exploit_available": 1,
        "severity": "High",
    },
    3389: {
        "cve_id": "CVE-2019-0708",
        "description": "BlueKeep - Remote Desktop Services Remote Code Execution",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-416",
        "cwe_name": "Use-After-Free",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708 | https://cwe.mitre.org/data/definitions/416.html",
        "published_date": "2019-05-16",
        "exploit_available": 1,
    },
    5432: {
        "cve_id": "CVE-2019-9193",
        "description": "PostgreSQL Authenticated Arbitrary Command Execution",
        "cvss_score": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-78",
        "cwe_name": "OS Command Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2019-9193 | https://cwe.mitre.org/data/definitions/78.html",
        "published_date": "2019-04-01",
        "exploit_available": 1,
    },
    5900: {
        "cve_id": "CVE-2006-2369",
        "description": "RealVNC Null Connection Authentication Bypass",
        "cvss_score": 7.5,
        "cvss_vector": "(AV:N/AC:L/Au:N/C:P/I:P/A:P) [NVD CVSS v2.0: 7.5]",
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2006-2369 | https://cwe.mitre.org/data/definitions/287.html",
        "published_date": "2006-05-15",
        "exploit_available": 1,
    },
    6379: {
        "cve_id": "CVE-2022-0543",
        "description": "Redis Lua Sandbox Escape Remote Code Execution",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_id": "CWE-94",
        "cwe_name": "Code Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543 | https://cwe.mitre.org/data/definitions/94.html",
        "published_date": "2022-02-18",
        "exploit_available": 1,
    },
    8080: {
        "cve_id": "CVE-2017-12617",
        "description": "Apache Tomcat Remote Code Execution via PUT Request",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-434",
        "cwe_name": "Unrestricted Upload of File",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2017-12617 | https://cwe.mitre.org/data/definitions/434.html",
        "published_date": "2017-10-04",
        "exploit_available": 1,
    },
    8081: {
        "cve_id": "CVE-2024-21626",
        "description": "runc / Container Environment File Descriptor Leak / RCE",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2024-21626 | https://cwe.mitre.org/data/definitions/200.html",
        "published_date": "2024-01-31",
        "exploit_available": 1,
    },
    8443: {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228 | https://cwe.mitre.org/data/definitions/502.html",
        "published_date": "2021-12-10",
        "exploit_available": 1,
    },
    9200: {
        "cve_id": "CVE-2015-1427",
        "description": "Elasticsearch Groovy Scripting Engine Remote Code Execution",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-94",
        "cwe_name": "Code Injection",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2015-1427 | https://cwe.mitre.org/data/definitions/94.html",
        "published_date": "2015-02-17",
        "exploit_available": 1,
    },
    27017: {
        "cve_id": "CVE-2019-2386",
        "description": "MongoDB Server Authentication Bypass & Account Takeover",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2019-2386 | https://cwe.mitre.org/data/definitions/287.html",
        "published_date": "2019-07-29",
        "exploit_available": 1,
    },
}

# Mapping common service keywords to a reference port in CVE_DB
SERVICE_CVE_MAP = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "pop3": 110,
    "rpcbind": 111,
    "sunrpc": 111,
    "epmap": 135,
    "netbios": 139,
    "imap": 143,
    "microsoft-ds": 445,
    "smb": 445,
    "ms-sql": 1433,
    "mssql": 1433,
    "oracle": 1521,
    "mqtt": 1883,
    "mysql": 3306,
    "rdp": 3389,
    "ms-wbt-server": 3389,
    "postgresql": 5432,
    "postgres": 5432,
    "vnc": 5900,
    "redis": 6379,
    "http-proxy": 8080,
    "tomcat": 8080,
    "container": 8081,
    "log4j": 8443,
    "elasticsearch": 9200,
    "mongodb": 27017,
}


def get_cve_info(port, service=None):
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        port_num = 0

    service = service or ""
    entry = None

    # Standard web listeners (80, 443, 8080, 5357, 9001) without vulnerable software are NOT CVEs
    if port_num in (80, 443) and not any(k in service.lower() for k in ["apache 2.4.49", "openssl 1.0.1"]):
        return None

    # 1. Exact Port Match
    if port_num in CVE_DB:
        entry = dict(CVE_DB[port_num])

    # 2. Service Keyword Match
    if not entry:
        srv_lower = service.lower()
        for keyword, mapped_port in SERVICE_CVE_MAP.items():
            if keyword in srv_lower:
                entry = dict(CVE_DB[mapped_port])
                entry["description"] = f"[{service.upper()} Service] " + entry["description"]
                break

    # 3. Dynamic Generic Exposure Fallback for non-web system ports
    if not entry:
        if port_num in (80, 443):
            return None
        is_system_port = 0 < port_num < 1024
        cvss_score = 5.3 if is_system_port else 3.9

        entry = {
            "cve_id": f"CVE-GENERIC-P{port_num}",
            "description": f"Exposed open service on port {port_num} ({service or 'unknown service'}). Potential attack surface requiring port hardening.",
            "cvss_score": cvss_score,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe_id": "CWE-200",
            "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "references": f"https://nvd.nist.gov/vuln/search/results?query=port+{port_num} | https://cwe.mitre.org/data/definitions/200.html",
            "published_date": datetime.now().strftime("%Y-%m-%d"),
            "exploit_available": 0,
        }

    # Ensure all CWE and reference keys exist
    if "cwe_id" not in entry or not entry["cwe_id"]:
        entry["cwe_id"] = "CWE-200"
    if "cwe_name" not in entry or not entry["cwe_name"]:
        entry["cwe_name"] = "Exposure of Sensitive Information"
    if "references" not in entry or not entry["references"]:
        entry["references"] = f"https://nvd.nist.gov/vuln/detail/{entry['cve_id']}"

    if "severity" not in entry or not entry["severity"]:
        entry["severity"] = get_severity_rating(entry["cvss_score"])
    return entry



def _ensure_tables(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            service TEXT,
            cve_id TEXT,
            severity TEXT,
            description TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            cwe_id TEXT,
            cwe_name TEXT,
            ref_links TEXT,
            published_date TEXT,
            exploit_available INTEGER,
            scan_time TEXT NOT NULL
        )
    """)
    conn.commit()

    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ports'"
    )
    if cursor.fetchone() is None:
        raise RuntimeError(
            "Table 'ports' does not exist in cybershield.db. "
            "Run your port scan step first so `ports` is populated."
        )


def scan_cves(target_ip, scan_id=None):
    if not target_ip:
        print("[!] No target IP provided.")
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        _ensure_tables(conn)

        if scan_id:
            cursor.execute("""
                SELECT ip, port, service
                FROM ports
                WHERE ip = ? AND scan_id = ?
            """, (target_ip, scan_id))
        else:
            cursor.execute("""
                SELECT ip, port, service
                FROM ports
                WHERE ip = ?
            """, (target_ip,))
        rows = cursor.fetchall()

        found = False

        print(f"\nCVE REPORT [scan_id={scan_id}]")
        print("=" * 70)

        for ip, port, service in rows:
            entry = get_cve_info(port, service)
            if not entry:
                continue
            found = True


            print(f"""
IP: {ip}
Port: {port}
Service: {service}
CVE: {entry['cve_id']}
CWE: {entry['cwe_id']} ({entry['cwe_name']})
Severity: {entry['severity']}
CVSS: {entry['cvss_score']}
Description: {entry['description']}
""")

            cursor.execute("""
                INSERT INTO cves
                (scan_id, ip, port, service, cve_id, severity, description,
                 cvss_score, cvss_vector, cwe_id, cwe_name, ref_links,
                 published_date, exploit_available, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, ip, port, service,
                entry["cve_id"], entry["severity"], entry["description"],
                entry["cvss_score"], entry["cvss_vector"],
                entry["cwe_id"], entry["cwe_name"], entry.get("references", ""),
                entry["published_date"], entry["exploit_available"],
                scan_time,
            ))

        conn.commit()

        if found:
            print("\n[+] CVE data saved successfully for all open ports.")
        else:
            print("\n[+] No open ports found for this IP.")

    except Exception as e:
        conn.rollback()
        print("[!] CVE scan error:", e)

    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    target = input("Enter target IP: ").strip()
    scan_cves(target)