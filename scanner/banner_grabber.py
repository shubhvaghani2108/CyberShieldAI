import socket


def grab_banner(ip, port):
    """
    Try to grab banner / response from an open service.
    Returns banner text if available, otherwise 'No banner'.
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)

        sock.connect((ip, port))

        # Try to receive initial banner
        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            if banner:
                sock.close()
                return banner
        except:
            pass

        # If no banner comes automatically, try sending protocol-specific requests
        if port in [80, 8080, 8000, 8888, 443]:
            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()

            if response:
                first_line = response.split("\n")[0].strip()
                return first_line

        elif port == 21:
            # FTP often sends welcome banner automatically
            sock.close()
            return "FTP service detected"

        elif port == 22:
            # SSH often sends banner automatically
            sock.close()
            return "SSH service detected"

        elif port == 25:
            # SMTP may send greeting banner
            sock.close()
            return "SMTP service detected"

        elif port == 110:
            sock.close()
            return "POP3 service detected"

        elif port == 143:
            sock.close()
            return "IMAP service detected"

        sock.close()
        return "No banner"

    except Exception as e:
        return "No banner"


if __name__ == "__main__":
    ip = input("Enter IP: ").strip()
    port = int(input("Enter Port: ").strip())

    banner = grab_banner(ip, port)

    print("\n=== BANNER RESULT ===")
    print("IP:", ip)
    print("Port:", port)
    print("Banner:", banner)