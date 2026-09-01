import socket


def grab_banner(ip, port):
    """
    Try to grab banner / response from an open service.
    Returns full raw HTTP response status + headers or service greeting banner.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))

        # 1. Try to receive initial banner (SSH, FTP, SMTP, MySQL, etc.)
        try:
            initial = sock.recv(1024).decode(errors="ignore").strip()
            if initial:
                sock.close()
                return " ".join(initial.split())[:300]
        except Exception:
            pass

        # 2. If no banner comes automatically, try sending HTTP HEAD request
        if port in (80, 443, 8080, 8000, 8888, 8443):
            if port in (443, 8443):
                try:
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ssock = ctx.wrap_socket(sock, server_hostname=ip)
                    request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: CyberShieldAI/2.0\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())
                    response = ssock.recv(2048).decode(errors="ignore").strip()
                    ssock.close()
                    if response:
                        return " ".join(response.split())[:300]
                except Exception:
                    pass
            else:
                try:
                    request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: CyberShieldAI/2.0\r\nConnection: close\r\n\r\n"
                    sock.send(request.encode())
                    response = sock.recv(2048).decode(errors="ignore").strip()
                    sock.close()
                    if response:
                        return " ".join(response.split())[:300]
                except Exception:
                    pass

        try:
            sock.close()
        except Exception:
            pass
        return "No banner"

    except Exception:
        return "No banner"


if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    port = int(input("Enter Port: ").strip())

    banner = grab_banner(ip, port)

    print("\n=== BANNER RESULT ===")
    print("IP:", ip)
    print("Port:", port)
    print("Banner:", banner)