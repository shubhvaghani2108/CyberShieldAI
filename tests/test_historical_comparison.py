"""
tests/test_historical_comparison.py

Comprehensive test suite for CyberShieldAI Historical Scan Comparison logic.
Verifies all 13 test scenarios including repeat scans, first scans, port changes,
header changes, TLS changes, CVE changes, and missing data handling.
"""

import unittest
from scanner.scan_comparator import compare_url_scans


class TestHistoricalScanComparator(unittest.TestCase):

    def test_01_first_scan_behavior(self):
        """Scenario 1: First scan for a target (no previous posture data)."""
        current = {
            "score": 99,
            "grade": "A+",
            "threat_score": 5,
            "open_ports": [80, 443],
            "tls_version": "TLSv1.3",
            "headers": {"Strict-Transport-Security": True},
            "scan_time": "2026-08-13 12:00:00"
        }
        res = compare_url_scans(current, None)
        self.assertFalse(res["has_previous"])
        self.assertEqual(res["score_diff"], 0)
        self.assertIn("Initial Security Assessment", res["summary_text"])
        self.assertEqual(len(res["changes"]), 0)

    def test_02_same_scan_twice(self):
        """Scenario 2: Repeat scan with identical data (score 99 -> 99)."""
        current = {
            "score": 99,
            "grade": "A+",
            "open_ports": [80, 443],
            "tls_version": "TLSv1.3",
            "headers": {"Strict-Transport-Security": True},
            "headers_available": True,
            "waf": {"detected": False},
            "waf_available": True,
            "technologies": ["Nginx"],
            "technologies_available": True,
            "cves": [],
            "scan_time": "2026-08-13 12:10:00"
        }
        previous = {
            "has_previous": True,
            "score": 99,
            "grade": "A+",
            "open_ports": [80, 443],
            "tls_version": "TLSv1.3",
            "headers": {"Strict-Transport-Security": True},
            "headers_available": True,
            "waf": {"detected": False},
            "waf_available": True,
            "technologies": ["Nginx"],
            "technologies_available": True,
            "cves": [],
            "scan_time": "2026-08-13 12:00:00"
        }
        res = compare_url_scans(current, previous)
        self.assertTrue(res["has_previous"])
        self.assertEqual(res["score_diff"], 0)
        self.assertEqual(res["score_direction"], "same")
        # Ensure no false changes (no false port or header changes)
        change_texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("unchanged" in t for t in change_texts))
        self.assertFalse(any("New port" in t for t in change_texts))
        self.assertFalse(any("removed" in t for t in change_texts))

    def test_03_score_improvement(self):
        """Scenario 3: Security score improved."""
        current = {"score": 95, "open_ports": [443]}
        previous = {"has_previous": True, "score": 85, "open_ports": [443]}
        res = compare_url_scans(current, previous)
        self.assertEqual(res["score_diff"], 10)
        self.assertEqual(res["score_direction"], "up")

    def test_04_score_deterioration(self):
        """Scenario 4: Security score deteriorated."""
        current = {"score": 75, "open_ports": [443]}
        previous = {"has_previous": True, "score": 90, "open_ports": [443]}
        res = compare_url_scans(current, previous)
        self.assertEqual(res["score_diff"], -15)
        self.assertEqual(res["score_direction"], "down")

    def test_05_new_port_detected(self):
        """Scenario 5: New open port detected (Port 8080 added)."""
        current = {"score": 85, "open_ports": [80, 443, 8080]}
        previous = {"has_previous": True, "score": 90, "open_ports": [80, 443]}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("New port detected open: Port 8080" in t for t in texts))

    def test_06_port_closed(self):
        """Scenario 6: Open port closed/secured (Port 8080 closed)."""
        current = {"score": 90, "open_ports": [80, 443]}
        previous = {"has_previous": True, "score": 85, "open_ports": [80, 443, 8080]}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("Port closed/secured: Port 8080" in t for t in texts))

    def test_07_header_added(self):
        """Scenario 7: Security header enabled."""
        current = {"score": 95, "headers": {"Content-Security-Policy": True}, "headers_available": True}
        previous = {"has_previous": True, "score": 90, "headers": {"Content-Security-Policy": False}, "headers_available": True}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("Security header enabled: Content-Security-Policy" in t for t in texts))

    def test_08_header_removed(self):
        """Scenario 8: Security header removed."""
        current = {"score": 85, "headers": {"Strict-Transport-Security": False}, "headers_available": True}
        previous = {"has_previous": True, "score": 95, "headers": {"Strict-Transport-Security": True}, "headers_available": True}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("Security header removed: Strict-Transport-Security" in t for t in texts))

    def test_09_tls_upgrade(self):
        """Scenario 9: TLS upgraded to 1.3."""
        current = {"score": 95, "tls_version": "TLSv1.3"}
        previous = {"has_previous": True, "score": 85, "tls_version": "TLSv1.2"}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("TLS configuration improved" in t for t in texts))

    def test_10_tls_downgrade(self):
        """Scenario 10: TLS downgraded."""
        current = {"score": 80, "tls_version": "TLSv1.2"}
        previous = {"has_previous": True, "score": 95, "tls_version": "TLSv1.3"}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("Warning: TLS configuration downgraded" in t for t in texts))

    def test_11_new_cve(self):
        """Scenario 11: New CVE vulnerability detected."""
        current = {"score": 70, "cves": ["CVE-2025-1234"]}
        previous = {"has_previous": True, "score": 90, "cves": []}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("New CVE vulnerability: CVE-2025-1234" in t for t in texts))

    def test_12_fixed_cve(self):
        """Scenario 12: CVE vulnerability resolved."""
        current = {"score": 90, "cves": []}
        previous = {"has_previous": True, "score": 70, "cves": ["CVE-2024-5678"]}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("CVE vulnerability resolved: CVE-2024-5678" in t for t in texts))

    def test_13_missing_historical_data(self):
        """Scenario 13: Historical header/WAF data unavailable."""
        current = {"score": 90, "headers": {"Content-Security-Policy": True}}
        previous = {"has_previous": True, "score": 90, "headers": None, "headers_available": False, "waf": None, "waf_available": False}
        res = compare_url_scans(current, previous)
        texts = [c["text"] for c in res["changes"]]
        self.assertTrue(any("Previous security-header data unavailable" in t for t in texts))
        self.assertTrue(any("Historical WAF data unavailable" in t for t in texts))


if __name__ == "__main__":
    unittest.main()
