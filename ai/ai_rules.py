PORT_RULES = {

    21: {
        "risk": "High",
        "reason": "FTP transmits credentials and files in plaintext.",
        "recommendation": "Migrate to SFTP (Port 22) or FTPS.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "High (Credential & Data Sniffing)"
    },

    22: {
        "risk": "Low",
        "reason": "SSH service detected. Secure when configured with key auth.",
        "recommendation": "Disable root password login and enforce SSH key authentication.",
        "cvss_score": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "attack_complexity": "High (AC:H)",
        "privileges_required": "None (PR:N)",
        "impact": "Low (Requires Brute Force / Exploitable Key)"
    },

    23: {
        "risk": "Critical",
        "reason": "Telnet protocol transmits all session data in cleartext.",
        "recommendation": "Disable Telnet immediately and replace with SSH.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Critical (Full Session Interception & System Takeover)"
    },

    25: {
        "risk": "Medium",
        "reason": "SMTP mail service exposed on public interface.",
        "recommendation": "Enforce SMTP AUTH and STARTTLS encryption.",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Medium (Email Spoofing & Open Relay Risk)"
    },

    53: {
        "risk": "Medium",
        "reason": "DNS name service exposed; vulnerable to amplification attacks.",
        "recommendation": "Disable open recursion and enable DNSSEC.",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Medium (DNS Cache Poisoning & Reflection Risk)"
    },

    80: {
        "risk": "Medium",
        "reason": "Unencrypted HTTP server listening on Port 80.",
        "recommendation": "Configure 301 Permanent Redirect to HTTPS.",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Medium (Plaintext HTTP Traffic Interception)"
    },

    110: {
        "risk": "High",
        "reason": "Unencrypted POP3 mail service exposed.",
        "recommendation": "Enforce POP3S over TLS (Port 995).",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "High (Mail Credential Interception)"
    },

    135: {
        "risk": "Medium",
        "reason": "Microsoft RPC Endpoint Mapper publicly accessible.",
        "recommendation": "Restrict Port 135 via network firewall.",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Medium (Internal Service Enumeration & RPC Vulnerability)"
    },

    139: {
        "risk": "High",
        "reason": "NetBIOS Session Service exposed to external networks.",
        "recommendation": "Disable NetBIOS over TCP/IP on external interface.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "High (Network Name Resolution Spoofing)"
    },

    143: {
        "risk": "Medium",
        "reason": "IMAP service listening without mandatory TLS.",
        "recommendation": "Enforce IMAPS (Port 993).",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Medium (IMAP Session Eavesdropping)"
    },

    443: {
        "risk": "Low",
        "reason": "HTTPS secure web server active.",
        "recommendation": "Enforce TLS 1.3 and modern cipher suites.",
        "cvss_score": 0.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "None (Secure Encrypted Communication)"
    },

    445: {
        "risk": "Critical",
        "reason": "Microsoft SMB service exposed; high risk of ransomware exploits.",
        "recommendation": "Block Port 445 at edge firewall and disable SMBv1.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Critical (Remote Code Execution & Ransomware Propagation)"
    },

    3306: {
        "risk": "High",
        "reason": "MySQL Database listener publicly exposed.",
        "recommendation": "Bind MySQL to 127.0.0.1 or restrict via firewall.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "High (Direct Database Data Exfiltration & Authentication Bypass)"
    },

    3389: {
        "risk": "Critical",
        "reason": "Remote Desktop Protocol (RDP) exposed on public IP.",
        "recommendation": "Restrict RDP access via VPN and require MFA.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Critical (Unauthenticated Remote Desktop Compromise & Takeover)"
    },

    5432: {
        "risk": "High",
        "reason": "PostgreSQL Database listener publicly accessible.",
        "recommendation": "Restrict PostgreSQL listening interfaces to private network.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "High (Unauthorized Database Query Execution & Data Leakage)"
    },

    8080: {
        "risk": "Medium",
        "reason": "HTTP Alternate / Proxy service listener active.",
        "recommendation": "Restrict external access and enforce HTTPS TLS proxy.",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "attack_complexity": "Low (AC:L)",
        "privileges_required": "None (PR:N)",
        "impact": "Medium (Unrestricted Proxy Access & Perimeter Bypassing)"
    }

}

def enrich_vulnerability_with_cvss(v):
    """
    Enriches a vulnerability row/dict with all 5 core CVSS v3.1 fields:
    - cvss_score
    - cvss_vector
    - attack_complexity
    - privileges_required
    - impact
    """
    if hasattr(v, "keys"):
        v_dict = dict(v)
    elif isinstance(v, dict):
        v_dict = dict(v)
    else:
        v_dict = {"port": v}

    port = v_dict.get("port")
    risk = str(v_dict.get("risk", "Medium")).capitalize()

    rule = PORT_RULES.get(port, {})

    score = v_dict.get("cvss_score") if v_dict.get("cvss_score") is not None else rule.get("cvss_score")
    if score is None:
        score = 9.8 if risk == "Critical" else (7.5 if risk == "High" else (5.3 if risk == "Medium" else 3.7))

    vector = v_dict.get("cvss_vector") or rule.get("cvss_vector")
    if not vector:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if risk == "Critical" else (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if risk == "High" else (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" if risk == "Medium" else
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
            )
        )

    ac = v_dict.get("attack_complexity") or rule.get("attack_complexity") or ("Low (AC:L)" if "AC:L" in vector else "High (AC:H)")
    pr = v_dict.get("privileges_required") or rule.get("privileges_required") or ("None (PR:N)" if "PR:N" in vector else "Low (PR:L)")
    imp = v_dict.get("impact") or rule.get("impact") or (
        "Critical (Full System Compromise & RCE)" if risk == "Critical" else (
            "High (Credential & Data Exposure)" if risk == "High" else (
                "Medium (Traffic Interception & Policy Violation)" if risk == "Medium" else
                "Low (Service Information Disclosure)"
            )
        )
    )

    v_dict["cvss_score"] = float(score)
    v_dict["cvss_vector"] = vector
    v_dict["attack_complexity"] = ac
    v_dict["privileges_required"] = pr
    v_dict["impact"] = imp

    return v_dict