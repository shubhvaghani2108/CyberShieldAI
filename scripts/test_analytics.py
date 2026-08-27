import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from analytics.trend_analytics import (
    get_security_score_trend,
    get_alert_trend,
    get_vulnerability_trend,
    get_risk_distribution,
    get_all_trend_analytics,
)
from dashboard.app import app

def run_analytics_tests():
    print("--- 1. Testing Chart 1: Security Score Over Time ---")
    score_data = get_security_score_trend(limit=10)
    print("Security score trend:", score_data)
    assert "labels" in score_data
    assert "scores" in score_data
    assert "average_score" in score_data
    assert len(score_data["scores"]) > 0
    assert all(0 <= s <= 100 for s in score_data["scores"])
    print("Security Score Over Time verified.")

    print("\n--- 2. Testing Chart 2: Alert Trend ---")
    alert_data = get_alert_trend(limit=10)
    print("Alert trend:", alert_data)
    assert "labels" in alert_data
    assert "critical" in alert_data
    assert "high" in alert_data
    assert "medium" in alert_data
    assert "low" in alert_data
    assert "total_alerts" in alert_data
    assert alert_data["total_alerts"] >= 0
    print("Alert Trend verified.")

    print("\n--- 3. Testing Chart 3: Vulnerability Trend ---")
    vuln_data = get_vulnerability_trend(limit=10)
    print("Vulnerability trend:", vuln_data)
    assert "labels" in vuln_data
    assert "critical" in vuln_data
    assert "high" in vuln_data
    assert "medium" in vuln_data
    assert "low" in vuln_data
    assert "total_vulns" in vuln_data
    print("Vulnerability Trend verified.")

    print("\n--- 4. Testing Chart 4: Risk Distribution ---")
    risk_data = get_risk_distribution()
    print("Risk distribution:", risk_data)
    assert "labels" in risk_data
    assert "counts" in risk_data
    assert "percentages" in risk_data
    assert "total_scanned_assets" in risk_data
    assert len(risk_data["labels"]) == 5
    assert set(risk_data["labels"]) == {"Critical", "High", "Medium", "Low", "Safe"}
    print("Risk Distribution verified.")

    print("\n--- 5. Testing Consolidated Analytics Payload ---")
    all_data = get_all_trend_analytics(limit=15)
    assert "security_score_trend" in all_data
    assert "alert_trend" in all_data
    assert "vulnerability_trend" in all_data
    assert "risk_distribution" in all_data
    print("Consolidated analytics payload verified.")

    print("\n--- 6. Testing Web Route (/analytics) & JSON API (/api/analytics/trends) ---")
    client = app.test_client()

    # GET /analytics
    res_page = client.get("/analytics")
    assert res_page.status_code == 200
    html = res_page.data.decode("utf-8")
    assert "Security Trend Analytics" in html
    assert "securityScoreTrendChart" in html
    assert "alertTrendChart" in html
    assert "vulnTrendChart" in html
    assert "riskDistributionChart" in html
    print("GET /analytics rendered HTML page with all 4 Chart.js canvas elements successfully.")

    # GET /api/analytics/trends
    res_api = client.get("/api/analytics/trends?limit=10")
    assert res_api.status_code == 200
    json_resp = res_api.get_json()
    assert "security_score_trend" in json_resp
    assert "alert_trend" in json_resp
    assert "vulnerability_trend" in json_resp
    assert "risk_distribution" in json_resp
    print("GET /api/analytics/trends returned JSON payload successfully.")

    print("\n[SUCCESS] All Security Trend Analytics requirements verified successfully!")

if __name__ == "__main__":
    run_analytics_tests()
