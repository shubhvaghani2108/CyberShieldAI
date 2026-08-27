from ai.ai_rules import PORT_RULES

def generate_ai_recommendations(ports):
    recommendations = []
    if not ports:
        return recommendations

    port_nums = set()
    for p in ports:
        pn = p.get("port") if isinstance(p, dict) else p
        try:
            port_nums.add(int(pn))
        except (ValueError, TypeError):
            pass

    has_https = 443 in port_nums or 8443 in port_nums

    for p in ports:
        port = p.get("port") if isinstance(p, dict) else p
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            continue

        if port_num == 443:
            # Port 443 (HTTPS) is standard secure web listener
            continue

        if port_num == 80 and has_https:
            # Port 80 with HTTPS active is standard redirect listener
            continue

        if port_num in PORT_RULES:
            rec = dict(PORT_RULES[port_num])
            rec["port"] = port_num
            recommendations.append(rec)
        else:
            recommendations.append({
                "port": port_num,
                "risk": "Low",
                "reason": f"Open port {port_num} detected.",
                "recommendation": f"Verify if port {port_num} service is required and enforce network firewall rules.",
                "cvss_score": 3.7,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "attack_complexity": "Low (AC:L)",
                "privileges_required": "None (PR:N)",
                "impact": "Low (Exposed Network Listener)"
            })

    return recommendations