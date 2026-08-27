import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def get_report_data(ip):

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    report = {}

    tables = {
        "url_scan": "url_scan_results",
        "ports": "ports",
        "services": "service_versions",
        "os_info": "os_info",
        "technology": "technology_detection",
        "risk": "risk_summary",
        "vulnerabilities": "vulnerabilities",
        "cves": "cves",
        "ssl": "ssl_results",
        "url_intelligence": "url_intelligence"
    }

    for key, table in tables.items():

        if key in ["ports", "services", "vulnerabilities", "cves"]:
            cur.execute(
                f"""
                SELECT *
                FROM {table}
                WHERE ip=?
                """,
                (ip,),
            )
            report[key] = cur.fetchall()

        elif key == "ssl":
            cur.execute(
                f"""
                SELECT *
                FROM {table}
                WHERE host=?
                ORDER BY id DESC
                LIMIT 1
                """,
                (ip,),
            )
            report[key] = cur.fetchone()

        else:
            cur.execute(
                f"""
                SELECT *
                FROM {table}
                WHERE ip=?
                ORDER BY id DESC
                LIMIT 1
                """,
                (ip,),
            )
            report[key] = cur.fetchone()

    conn.close()

    return report


if __name__ == "__main__":

    from pprint import pprint

    pprint(get_report_data("142.251.153.119"))