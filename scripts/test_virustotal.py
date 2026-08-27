import os
import sys
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scanner.virustotal_scanner import (
    init_virustotal_table,
    query_virustotal,
    save_virustotal_result,
    get_latest_virustotal,
    calculate_vt_risk_badge,
)
from dashboard.app import app

def run_virustotal_tests():
    print("--- 1. Testing virustotal_results Database Table Initialization ---")
    init_virustotal_table()
    conn = sqlite3.connect("cybershield.db")
    conn.row_factory = sqlite3.Row
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(virustotal_results)").fetchall()]
    print("virustotal_results columns:", cols)
    for expected in ["malicious", "suspicious", "harmless", "undetected", "total_engines", "risk_badge", "scan_id", "url"]:
        assert expected in cols
    conn.close()
    print("Table virustotal_results verified with all required columns.")

    print("\n--- 2. Testing Risk Badge Calculation Logic ---")
    assert calculate_vt_risk_badge(malicious=3, suspicious=1) == "Malicious"
    assert calculate_vt_risk_badge(malicious=1, suspicious=0) == "Malicious"
    assert calculate_vt_risk_badge(malicious=0, suspicious=2) == "Suspicious"
    assert calculate_vt_risk_badge(malicious=0, suspicious=0) == "Safe"
    print("Risk badge logic verified: Safe, Suspicious, Malicious.")

    print("\n--- 3. Testing Graceful Handling of Missing API Key ---")
    # Query without API key in environment
    res_no_key = query_virustotal("https://example-test-safe.com", api_key="")
    print("Result without API key:", res_no_key)
    assert res_no_key["status"] == "missing_api_key"
    assert res_no_key["configured"] == False
    assert res_no_key["malicious"] == 0
    assert res_no_key["suspicious"] == 0
    assert res_no_key["harmless"] == 0
    assert res_no_key["undetected"] == 0
    assert res_no_key["risk_badge"] == "Safe"
    assert "not configured" in res_no_key["message"]
    print("Missing API key handled gracefully without crashing.")

    print("\n--- 4. Testing Manual / Simulated Result Storage ---")
    test_data = {
        "url": "https://suspicious-test-site.org/login",
        "domain": "suspicious-test-site.org",
        "malicious": 2,
        "suspicious": 3,
        "harmless": 65,
        "undetected": 5,
        "total_engines": 75,
        "risk_badge": "Malicious",
        "reputation": -10,
        "categories": {"Forcepoint ThreatSeeker": "suspicious"},
        "status": "success",
        "message": "Scanned by 75 engines (2 malicious, 3 suspicious).",
        "scan_time": "2026-08-17 17:55:00",
    }
    row_id = save_virustotal_result(test_data, scan_id="test_scan_vt_001")
    print(f"Saved simulated VirusTotal result id: {row_id}")
    assert row_id > 0

    latest_vt = get_latest_virustotal(url="https://suspicious-test-site.org/login")
    print("Retrieved VirusTotal record:", latest_vt)
    assert latest_vt["malicious"] == 2
    assert latest_vt["suspicious"] == 3
    assert latest_vt["harmless"] == 65
    assert latest_vt["undetected"] == 5
    assert latest_vt["risk_badge"] == "Malicious"

    print("\n--- 5. Testing URL Scan Result Web Page Integration ---")
    client = app.test_client()
    res = client.get("/url-scan-result")
    html = res.data.decode("utf-8")
    assert "VirusTotal Reputation Intelligence" in html
    assert "Malicious" in html
    assert "Suspicious" in html
    assert "Harmless" in html
    assert "Undetected" in html
    assert "Global Threat Verdict" in html
    print("VirusTotal Card, 4 metrics, and risk badge rendered properly in URL scan page HTML!")

    # Cleanup test record
    conn = sqlite3.connect("cybershield.db")
    conn.execute("DELETE FROM virustotal_results WHERE scan_id = 'test_scan_vt_001'")
    conn.commit()
    conn.close()

    print("\n[SUCCESS] All VirusTotal API integration requirements verified successfully!")

if __name__ == "__main__":
    run_virustotal_tests()
