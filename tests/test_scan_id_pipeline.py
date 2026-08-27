import uuid
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

from database.db_helpers import (
    init_db,
    get_db_connection,
    get_ports,
    get_vulnerabilities,
    get_cves,
    get_latest_risk,
    migrate_db_add_scan_id,
)
from scanner.port_scanner import scan_target
from scanner.service_detector import detect_services
from scanner.os_detector import detect_os
from scanner.vulnerability_scanner import scan_vulnerabilities
from scanner.cve_scanner import scan_cves
from scanner.risk_calculator import calculate_risk
from scanner.host_discovery import check_host_alive


@pytest.fixture(autouse=True)
def ensure_db_migrated():
    init_db()
    migrate_db_add_scan_id()
    yield
    # Teardown: purge mock scan data generated during tests
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = OFF")
    for t in [
        "ports", "vulnerabilities", "cves", "risk_summary", "host_status",
        "url_scan_results", "os_detection", "os_info", "service_versions",
        "services", "technology_detection", "security_headers", "ssl_info",
        "ssl_results", "url_intelligence", "nvd_cache", "alerts",
        "scan_history", "security_posture", "monitored_targets",
        "monitoring_logs", "virustotal_results"
    ]:
        try:
            cur.execute(f"DELETE FROM {t}")
            cur.execute("DELETE FROM sqlite_sequence WHERE name=?", (t,))
        except Exception:
            pass
    conn.commit()
    conn.close()


def test_ip_scan_generates_and_propagates_scan_id():
    """Test that _run_ip_scan_job generates a scan_id and propagates it to all submodules."""
    from dashboard.scan_jobs import _run_ip_scan_job

    target_ip = "192.168.1.99"
    captured_scan_ids = []

    with patch("dashboard.scan_jobs.check_host_alive") as mock_host, \
         patch("dashboard.scan_jobs.scan_target") as mock_port, \
         patch("dashboard.scan_jobs.scan_vulnerabilities") as mock_vuln, \
         patch("dashboard.scan_jobs.scan_cves") as mock_cve, \
         patch("dashboard.scan_jobs.calculate_risk") as mock_risk, \
         patch("dashboard.scan_jobs.generate_alerts") as mock_alerts, \
         patch("dashboard.scan_jobs._job_done") as mock_done, \
         patch("dashboard.scan_jobs._job_log"):

        mock_host.return_value = {"alive": True, "status": "Alive", "scan_time": "2026-08-24 12:00:00"}
        mock_port.return_value = {"target_ip": target_ip, "ports_count": 2}

        _run_ip_scan_job("test_job_1", target_ip)

        # 1. Verify host discovery got a scan_id
        assert mock_host.call_count == 1
        _, host_kwargs = mock_host.call_args
        scan_id = host_kwargs.get("scan_id")
        assert scan_id is not None
        assert len(scan_id) == 32  # uuid4 hex

        # 2. Verify port scan got the exact same scan_id
        assert mock_port.call_count == 1
        _, port_kwargs = mock_port.call_args
        assert port_kwargs.get("scan_id") == scan_id

        # 3. Verify vulnerability scan got the exact same scan_id
        assert mock_vuln.call_count == 1
        _, vuln_kwargs = mock_vuln.call_args
        assert vuln_kwargs.get("scan_id") == scan_id

        # 4. Verify CVE scan got the exact same scan_id
        assert mock_cve.call_count == 1
        _, cve_kwargs = mock_cve.call_args
        assert cve_kwargs.get("scan_id") == scan_id

        # 5. Verify risk calculator got the exact same scan_id
        assert mock_risk.call_count == 1
        _, risk_kwargs = mock_risk.call_args
        assert risk_kwargs.get("scan_id") == scan_id


class MockHostDict:
    def __init__(self, ports_data, osmatch=None):
        self.ports_data = ports_data
        self.osmatch = osmatch or []

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, proto):
        if proto == "tcp":
            return self.ports_data
        return {}

    def get(self, key, default=None):
        if key == "osmatch":
            return self.osmatch
        return default


def test_ports_and_services_store_scan_id(monkeypatch):
    """Test that ports and service_versions store scan_id upon scan_target completion."""
    target_ip = "192.168.1.101"
    scan_id = uuid.uuid4().hex

    syn_host = MockHostDict({80: {"state": "open"}, 443: {"state": "open"}})
    fake_syn_scanner = MagicMock()
    fake_syn_scanner.all_hosts.return_value = [target_ip]
    fake_syn_scanner.__getitem__.return_value = syn_host

    detail_host = MockHostDict(
        {
            80: {"state": "open", "name": "http", "product": "Apache", "version": "2.4.49", "extrainfo": ""},
            443: {"state": "open", "name": "https", "product": "OpenSSL", "version": "1.1.1", "extrainfo": ""},
        },
        osmatch=[{"name": "Linux 5.4", "accuracy": "95", "osclass": [{"type": "general"}]}]
    )
    fake_detail_scanner = MagicMock()
    fake_detail_scanner.all_hosts.return_value = [target_ip]
    fake_detail_scanner.__getitem__.return_value = detail_host

    with patch("nmap.PortScanner", side_effect=[fake_syn_scanner, fake_detail_scanner]), \
         patch("scanner.port_scanner.grab_banner", return_value="Server: Apache"):

        res = scan_target(target_ip, ports="80,443", scan_id=scan_id)
        assert res["scan_id"] == scan_id

    # Verify in DB
    conn = get_db_connection()
    ports_rows = conn.execute("SELECT * FROM ports WHERE ip = ? AND scan_id = ?", (target_ip, scan_id)).fetchall()
    assert len(ports_rows) == 2
    for r in ports_rows:
        assert r["scan_id"] == scan_id
        assert r["port"] in [80, 443]

    svc_rows = conn.execute("SELECT * FROM service_versions WHERE ip = ? AND scan_id = ?", (target_ip, scan_id)).fetchall()
    assert len(svc_rows) == 2
    for r in svc_rows:
        assert r["scan_id"] == scan_id

    os_rows = conn.execute("SELECT * FROM os_info WHERE ip = ? AND scan_id = ?", (target_ip, scan_id)).fetchall()
    assert len(os_rows) >= 1
    assert os_rows[0]["scan_id"] == scan_id

    conn.close()


def test_vulnerabilities_and_cves_store_scan_id():
    """Test that vulnerabilities and CVEs are tagged with scan_id and retrievable by scan_id."""
    target_ip = "192.168.1.102"
    scan_id = uuid.uuid4().hex

    conn = get_db_connection()
    # Insert open ports with scan_id
    conn.execute(
        "INSERT INTO ports (scan_id, ip, port, state, service, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, target_ip, 21, "open", "ftp", "2026-08-24 12:00:00")
    )
    conn.execute(
        "INSERT INTO service_versions (scan_id, ip, port, service, product, version, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (scan_id, target_ip, 21, "ftp", "vsftpd", "2.3.4", "2026-08-24 12:00:00")
    )
    conn.commit()
    conn.close()

    # Run vulnerability scanner
    vulns = scan_vulnerabilities(target_ip, scan_id=scan_id)
    assert len(vulns) >= 1
    for v in vulns:
        assert v.get("scan_id") == scan_id

    # Run CVE scanner
    scan_cves(target_ip, scan_id=scan_id)

    # Verify DB records
    conn = get_db_connection()
    vuln_db = conn.execute("SELECT * FROM vulnerabilities WHERE ip = ? AND scan_id = ?", (target_ip, scan_id)).fetchall()
    assert len(vuln_db) >= 1
    assert all(r["scan_id"] == scan_id for r in vuln_db)

    cve_db = conn.execute("SELECT * FROM cves WHERE ip = ? AND scan_id = ?", (target_ip, scan_id)).fetchall()
    assert len(cve_db) >= 1
    assert all(r["scan_id"] == scan_id for r in cve_db)

    conn.close()


def test_risk_calculator_stores_scan_id():
    """Test that risk calculation saves risk_summary with scan_id."""
    target_ip = "192.168.1.103"
    scan_id = uuid.uuid4().hex

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO vulnerabilities (scan_id, ip, port, service, risk, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, target_ip, 80, "http", "High", "2026-08-24 12:00:00")
    )
    conn.commit()
    conn.close()

    res = calculate_risk(target_ip, scan_id=scan_id)
    assert res is not None
    assert res["scan_id"] == scan_id
    assert res["high_count"] == 1
    assert res["total_score"] == 7

    conn = get_db_connection()
    risk_db = conn.execute("SELECT * FROM risk_summary WHERE ip = ? AND scan_id = ?", (target_ip, scan_id)).fetchall()
    assert len(risk_db) == 1
    assert risk_db[0]["scan_id"] == scan_id
    assert risk_db[0]["total_score"] == 7
    conn.close()


def test_multiple_scans_preserve_history_without_deletion():
    """Verify that running a second scan on the same IP does NOT delete previous scan records."""
    unique_suffix = uuid.uuid4().hex[:6]
    target_ip = f"10.200.{unique_suffix}"
    scan_id_1 = f"SCAN_AAA_{unique_suffix}"
    scan_id_2 = f"SCAN_BBB_{unique_suffix}"

    conn = get_db_connection()

    # Scan 1 inserts
    conn.execute("INSERT INTO ports (scan_id, ip, port, state, service, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
                 (scan_id_1, target_ip, 80, "open", "http", "2026-08-24 10:00:00"))
    conn.execute("INSERT INTO service_versions (scan_id, ip, port, service, product, version, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (scan_id_1, target_ip, 80, "http", "Apache", "2.2", "2026-08-24 10:00:00"))
    conn.execute("INSERT INTO os_info (scan_id, ip, os_name, device_type, os_details, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
                 (scan_id_1, target_ip, "Linux 4.x", "Server", "Linux", "2026-08-24 10:00:00"))
    conn.execute("INSERT INTO vulnerabilities (scan_id, ip, port, service, risk, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
                 (scan_id_1, target_ip, 80, "http", "Medium", "2026-08-24 10:00:00"))
    conn.commit()
    conn.close()

    # Run calculate_risk for Scan 1
    calculate_risk(target_ip, scan_id=scan_id_1)

    # Scan 2 inserts for same IP
    conn = get_db_connection()
    conn.execute("INSERT INTO ports (scan_id, ip, port, state, service, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
                 (scan_id_2, target_ip, 443, "open", "https", "2026-08-24 11:00:00"))
    conn.execute("INSERT INTO service_versions (scan_id, ip, port, service, product, version, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (scan_id_2, target_ip, 443, "https", "Nginx", "1.18", "2026-08-24 11:00:00"))
    conn.execute("INSERT INTO os_info (scan_id, ip, os_name, device_type, os_details, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
                 (scan_id_2, target_ip, "Linux 5.x", "Server", "Linux", "2026-08-24 11:00:00"))
    conn.execute("INSERT INTO vulnerabilities (scan_id, ip, port, service, risk, scan_time) VALUES (?, ?, ?, ?, ?, ?)",
                 (scan_id_2, target_ip, 443, "https", "High", "2026-08-24 11:00:00"))
    conn.commit()
    conn.close()

    # Run calculate_risk for Scan 2
    calculate_risk(target_ip, scan_id=scan_id_2)

    # Verify both scans' records exist
    conn = get_db_connection()

    ports_1 = conn.execute("SELECT * FROM ports WHERE ip = ? AND scan_id = ?", (target_ip, scan_id_1)).fetchall()
    ports_2 = conn.execute("SELECT * FROM ports WHERE ip = ? AND scan_id = ?", (target_ip, scan_id_2)).fetchall()
    assert len(ports_1) == 1 and ports_1[0]["port"] == 80
    assert len(ports_2) == 1 and ports_2[0]["port"] == 443

    os_1 = conn.execute("SELECT * FROM os_info WHERE ip = ? AND scan_id = ?", (target_ip, scan_id_1)).fetchall()
    os_2 = conn.execute("SELECT * FROM os_info WHERE ip = ? AND scan_id = ?", (target_ip, scan_id_2)).fetchall()
    assert len(os_1) >= 1 and os_1[0]["os_name"] == "Linux 4.x"
    assert len(os_2) >= 1 and os_2[0]["os_name"] == "Linux 5.x"

    risk_1 = conn.execute("SELECT * FROM risk_summary WHERE ip = ? AND scan_id = ?", (target_ip, scan_id_1)).fetchall()
    risk_2 = conn.execute("SELECT * FROM risk_summary WHERE ip = ? AND scan_id = ?", (target_ip, scan_id_2)).fetchall()
    assert len(risk_1) == 1 and risk_1[0]["medium_count"] == 1
    assert len(risk_2) == 1 and risk_2[0]["high_count"] == 1

    conn.close()
