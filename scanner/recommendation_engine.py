"""
CyberShieldAI
Recommendation Engine
"""

# =========================================================
# GENERATE SECURITY RECOMMENDATIONS
# =========================================================

def generate_recommendations(ports, services, os_info, vulnerabilities):

    recommendations = []

    # =====================================================
    # PORT BASED RECOMMENDATIONS
    # =====================================================

    for port in ports:

        port_number = port["port"]

        if port_number == 21:
            recommendations.append(
                "FTP (Port 21): Disable FTP if not required. Use SFTP instead."
            )

        elif port_number == 22:
            recommendations.append(
                "SSH (Port 22): Disable password authentication and use SSH Keys."
            )

        elif port_number == 23:
            recommendations.append(
                "Telnet (Port 23): Disable Telnet immediately and replace it with SSH."
            )

        elif port_number == 25:
            recommendations.append(
                "SMTP (Port 25): Configure SMTP authentication and spam protection."
            )

        elif port_number == 53:
            recommendations.append(
                "DNS (Port 53): Disable recursive DNS queries from public networks."
            )

        elif port_number == 80:
            recommendations.append(
                "HTTP (Port 80): Redirect all traffic to HTTPS."
            )

        elif port_number == 110:
            recommendations.append(
                "POP3 (Port 110): Use POP3S instead of POP3."
            )

        elif port_number == 143:
            recommendations.append(
                "IMAP (Port 143): Use IMAPS for secure communication."
            )

        elif port_number == 443:
            recommendations.append(
                "HTTPS (Port 443): Verify TLS configuration and SSL certificate."
            )

        elif port_number == 445:
            recommendations.append(
                "SMB (Port 445): Disable SMBv1 and restrict SMB access."
            )

        elif port_number == 3306:
            recommendations.append(
                "MySQL (Port 3306): Restrict remote database access."
            )

        elif port_number == 3389:
            recommendations.append(
                "RDP (Port 3389): Enable MFA and restrict Remote Desktop access."
            )

    # =====================================================
    # SERVICE BASED RECOMMENDATIONS
    # =====================================================

    for service in services:

        service_name = str(service["service"]).lower()

        product = str(service["product"]).lower() if "product" in service.keys() else ""

        if "apache" in product:
            recommendations.append(
                "Apache: Update Apache Server to the latest stable version."
            )

        if "mysql" in product:
            recommendations.append(
                "MySQL: Disable remote root login and use strong passwords."
            )

        if "oracle" in product:
            recommendations.append(
                "Oracle Database: Apply the latest Oracle security patches."
            )

        if "ftp" in service_name:
            recommendations.append(
                "FTP Service: Disable anonymous login."
            )

        if "ssh" in service_name:
            recommendations.append(
                "SSH Service: Disable root login."
            )

    # =====================================================
    # OPERATING SYSTEM RECOMMENDATIONS
    # =====================================================

    if os_info:

        os_name = str(os_info["os_name"]).lower()

        if "windows" in os_name:

            recommendations.append(
                "Windows: Enable Windows Firewall."
            )

            recommendations.append(
                "Windows: Install all latest security updates."
            )

            recommendations.append(
                "Windows: Enable Microsoft Defender."
            )

        elif "linux" in os_name:

            recommendations.append(
                "Linux: Keep packages updated using apt/yum."
            )

            recommendations.append(
                "Linux: Enable UFW or Firewalld."
            )

            recommendations.append(
                "Linux: Disable SSH root login."
            )

    # =====================================================
    # VULNERABILITY BASED RECOMMENDATIONS
    # =====================================================

    for vulnerability in vulnerabilities:

        service = vulnerability["service"]

        recommendations.append(
            f"Resolve vulnerabilities related to {service}."
        )

    # =====================================================
    # REMOVE DUPLICATES
    # =====================================================

    recommendations = list(dict.fromkeys(recommendations))

    # =====================================================
    # DEFAULT MESSAGE
    # =====================================================

    if not recommendations:

        recommendations.append(
            "No critical recommendations available."
        )

    return recommendations