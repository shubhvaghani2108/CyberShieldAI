import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scanner.recommendation_engine import generate_recommendations

ports = [
    {"port": 80},
    {"port": 445},
    {"port": 3389}
]

services = [
    {
        "service": "http",
        "product": "Apache"
    },
    {
        "service": "microsoft-ds",
        "product": "Windows SMB"
    }
]

os_info = {
    "os_name": "Windows 11"
}

vulnerabilities = [
    {
        "service": "Apache"
    }
]

recommendations = generate_recommendations(
    ports,
    services,
    os_info,
    vulnerabilities
)

print("\n===== SECURITY RECOMMENDATIONS =====\n")

for i, recommendation in enumerate(recommendations, start=1):
    print(f"{i}. {recommendation}")