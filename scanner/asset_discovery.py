from scapy.all import ARP, Ether, srp


def discover_assets(target_ip):
    """
    ARP-scans a network range and returns a list of
    {"ip": ..., "mac": ...} dicts for every host that responds.
    """
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    return [
        {"ip": received.psrc, "mac": received.hwsrc}
        for sent, received in result
    ]


if __name__ == "__main__":
    target_ip = input("Enter Network Range (example 192.168.1.0/24): ")

    print("\nScanning Network...\n")
    hosts = discover_assets(target_ip)

    print("IP Address\t\tMAC Address")
    print("-" * 50)
    for host in hosts:
        print(f"{host['ip']}\t\t{host['mac']}")