
"""
tests/test_url_scan_pipeline.py

Comprehensive regression tests for the generic URL scan_id pipeline:
1. Unique scan_id generation & persistence
2. URL result routing by scan_id (?scan_id=... and /<scan_id>)
3. Correct URL, domain, IP, protocol and risk rendering
4. Graceful handling of missing optional telemetry (SSL, Tech, DNS)
5. Proper 404 when scan_id is not found
6. Multi-scan isolation (different URLs & same URL scanned multiple times)
7. Preservation of IP Scan Result functionality
"""

import pytest
import uuid
from dashboard.app import app
from database.db_helpers import get_db_connection


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "ADMIN"
            sess["email"] = "admin@cybershield.ai"
        yield c


def _insert_test_url_scan(scan_id, url, domain, ip="93.184.216.34", protocol="HTTPS", score=0, risk="Low"):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO url_scan_results
        (scan_id, url, domain, ip, protocol, score, risk, remarks, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (scan_id, url, domain, ip, protocol, score, risk, "Test scan entry"),
    )
    conn.commit()
    conn.close()


def test_01_url_scan_result_by_scan_id_query_param(client):
    scan_id = uuid.uuid4().hex
    _insert_test_url_scan(scan_id, "https://test-alpha.example.com/app", "test-alpha.example.com")

    resp = client.get(f"/url-scan-result?scan_id={scan_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "https://test-alpha.example.com/app" in html
    assert "test-alpha.example.com" in html


def test_02_url_scan_result_by_scan_id_path(client):
    scan_id = uuid.uuid4().hex
    _insert_test_url_scan(scan_id, "https://test-beta.example.org:8443", "test-beta.example.org")

    resp = client.get(f"/url-scan-result/{scan_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "https://test-beta.example.org:8443" in html
    assert "test-beta.example.org" in html


def test_03_invalid_scan_id_returns_404(client):
    non_existent_scan_id = "non-existent-scan-" + uuid.uuid4().hex
    resp = client.get(f"/url-scan-result?scan_id={non_existent_scan_id}")
    assert resp.status_code == 404
    html = resp.data.decode("utf-8")
    assert "not found" in html.lower()


def test_04_two_different_urls_remain_distinct(client):
    scan_a = uuid.uuid4().hex
    scan_b = uuid.uuid4().hex
    _insert_test_url_scan(scan_a, "https://target-one.net", "target-one.net", score=10, risk="Medium")
    _insert_test_url_scan(scan_b, "https://target-two.io/secure", "target-two.io", score=0, risk="Low")

    resp_a = client.get(f"/url-scan-result?scan_id={scan_a}")
    assert resp_a.status_code == 200
    html_a = resp_a.data.decode("utf-8")
    assert "https://target-one.net" in html_a
    assert "<tr><th>Target URL</th><td>https://target-one.net</td></tr>" in html_a
    assert "<tr><th>Target URL</th><td>https://target-two.io/secure</td></tr>" not in html_a

    resp_b = client.get(f"/url-scan-result?scan_id={scan_b}")
    assert resp_b.status_code == 200
    html_b = resp_b.data.decode("utf-8")
    assert "https://target-two.io/secure" in html_b
    assert "<tr><th>Target URL</th><td>https://target-two.io/secure</td></tr>" in html_b
    assert "<tr><th>Target URL</th><td>https://target-one.net</td></tr>" not in html_b


def test_05_same_url_scanned_twice_produces_separate_results(client):
    scan_1 = uuid.uuid4().hex
    scan_2 = uuid.uuid4().hex
    _insert_test_url_scan(scan_1, "https://re-scan-target.com", "re-scan-target.com", score=15, risk="Medium")
    _insert_test_url_scan(scan_2, "https://re-scan-target.com", "re-scan-target.com", score=0, risk="Low")

    resp_1 = client.get(f"/url-scan-result?scan_id={scan_1}")
    assert resp_1.status_code == 200
    html_1 = resp_1.data.decode("utf-8")
    assert "15 / 100" in html_1 or "Medium" in html_1

    resp_2 = client.get(f"/url-scan-result?scan_id={scan_2}")
    assert resp_2.status_code == 200
    html_2 = resp_2.data.decode("utf-8")
    assert "0 / 100" in html_2 or "Low" in html_2


def test_06_url_scan_with_unknown_ip_renders_cleanly(client):
    scan_id = uuid.uuid4().hex
    _insert_test_url_scan(scan_id, "https://unresolvable-domain.test", "unresolvable-domain.test", ip="Unknown")

    resp = client.get(f"/url-scan-result?scan_id={scan_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "unresolvable-domain.test" in html
    assert "Unknown" in html or "Target Overview" in html


def test_07_url_scan_without_optional_ssl_or_tech_renders_gracefully(client):
    scan_id = uuid.uuid4().hex
    _insert_test_url_scan(scan_id, "http://plain-http-target.org", "plain-http-target.org", protocol="HTTP")

    resp = client.get(f"/url-scan-result?scan_id={scan_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "plain-http-target.org" in html
    assert "Target Overview" in html


def test_08_ip_scan_result_page_still_functions(client):
    resp = client.get("/ip-scan-result")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "IP Scan Result" in html or "Target Overview" in html


def test_09_exact_user_scan_id_route(client, capsys):
    scan_id = "b746d6e8b88b46c1ae81a10782f574b3"
    _insert_test_url_scan(scan_id, "https://github.com", "github.com", ip="140.82.121.4")

    resp = client.get(f"/url-scan-result/{scan_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "https://github.com" in html
    assert "github.com" in html

    captured = capsys.readouterr()
    assert "unexpected keyword argument 'scan_id'" not in captured.out
    assert "unexpected keyword argument 'scan_id'" not in captured.err
