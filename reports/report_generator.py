import os

from reports.report_data import get_report_data
from reports.pdf_builder import create_pdf


def generate_report(ip):
    report = get_report_data(ip)

    os.makedirs("reports/output", exist_ok=True)

    filename = ip.replace(".", "_") + ".pdf"

    output = os.path.join(
        "reports",
        "output",
        filename,
    )

    create_pdf(report, output)

    print(f"[OK] Report saved to: {output}")

    return output


if __name__ == "__main__":
    generate_report("142.251.153.119")