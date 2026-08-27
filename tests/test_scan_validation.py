"""
tests/test_scan_validation.py

Comprehensive test suite for CyberShieldAI Scan Validation logic and AI Engine Inconclusive Handling.
Verifies all required scan validation scenarios.
"""

import unittest
from scanner.scan_validation import validate_url_scan
from ai.ai_engine import run_ai_engine
from scanner.scan_comparator import compare_url_scans


class TestScanValidationSuite(unittest.TestCase):

    def test_01_valid_url_successful_https_scan(self):
        """Scenario 1: Valid URL with successful HTTPS scan -> status = ASSESSED, score is numeric."""
        result = {
            "url": "https://example.com",
            "domain": "example.com",
            "ip": "93.184.216.34",
            "protocol": "https",
            "score": 0,
            "risk": "Low",
            "remarks": ["Website is using HTTPS"]
        }
        ports = [{"port": 443, "service": "https", "state": "open"}]
        ssl_info = {"has_ssl": True, "tls_version": "TLSv1.3", "valid_days": 180}
        url_info = {"security_headers": {"scanned": True, "Strict-Transport-Security": True}, "dns": {"A": ["93.184.216.34"]}}
        technology = {"server": "Nginx", "technologies": ["Nginx"]}

        val = validate_url_scan(
            result=result,
            ports=ports,
            ssl_info=ssl_info,
            url_info=url_info,
            technology=technology,
            ports_scanned=True,
            ssl_scanned=True,
            dns_scanned=True,
            technology_scanned=True
        )
        self.assertTrue(val["valid"])
        self.assertEqual(val["status"], "ASSESSED")

        ai_res = run_ai_engine(
            ports=ports,
            ssl_info=ssl_info,
            url_info=url_info,
            technology=technology,
            result=result,
            ports_scanned=True,
            ssl_scanned=True,
            dns_scanned=True,
            technology_scanned=True
        )
        self.assertIsNotNone(ai_res["score"])
        self.assertIsInstance(ai_res["score"], int)
        self.assertNotEqual(ai_res["grade"], "N/A")

    def test_02_valid_url_with_vulnerabilities(self):
        """Scenario 2: Valid URL with vulnerabilities -> status = ASSESSED, score lower according to real findings."""
        result = {
            "url": "https://vulnerable.local",
            "domain": "vulnerable.local",
            "ip": "192.168.1.50",
            "protocol": "https",
            "score": 15,
            "risk": "Medium",
            "remarks": ["Website is using HTTPS"]
        }
        vulnerabilities = [{"port": 80, "risk": "Critical", "description": "RCE Vuln"}]
        ports = [{"port": 80, "service": "http", "state": "open"}]

        val = validate_url_scan(
            result=result,
            ports=ports,
            vulnerabilities=vulnerabilities,
            ports_scanned=True,
            vulnerability_scanned=True
        )
        self.assertTrue(val["valid"])
        self.assertEqual(val["status"], "ASSESSED")

        ai_res = run_ai_engine(
            ports=ports,
            vulnerabilities=vulnerabilities,
            result=result,
            ports_scanned=True,
            vulnerability_scanned=True
        )
        self.assertIsNotNone(ai_res["score"])
        self.assertLess(ai_res["score"], 100)

    def test_03_invalid_unresolvable_url(self):
        """Scenario 3: Invalid/unresolvable URL -> status = INCONCLUSIVE, score = None, grade = N/A."""
        result = {
            "url": "https://2600:140f:7200:3c::17d4:c8",
            "domain": "2600:140f:7200:3c::17d4:c8",
            "ip": "Unknown",
            "protocol": "unknown",
            "score": 35,
            "risk": "High",
            "remarks": ["Protocol could not be verified", "Domain could not be resolved"]
        }

        val = validate_url_scan(result=result)
        self.assertFalse(val["valid"])
        self.assertEqual(val["status"], "INCONCLUSIVE")
        self.assertTrue(len(val["reasons"]) > 0)

        ai_res = run_ai_engine(result=result)
        self.assertIsNone(ai_res["score"])
        self.assertEqual(ai_res["grade"], "N/A")
        self.assertEqual(ai_res["status"], "INCONCLUSIVE")

    def test_04_url_with_no_http_response(self):
        """Scenario 4: URL with no HTTP response -> status = INCONCLUSIVE."""
        result = {
            "url": "https://unreachable-host-999.local",
            "domain": "unreachable-host-999.local",
            "ip": "Unknown",
            "protocol": "unknown",
            "score": 20,
            "risk": "Medium",
            "remarks": ["Protocol could not be verified"]
        }
        val = validate_url_scan(result=result)
        self.assertFalse(val["valid"])
        self.assertEqual(val["status"], "INCONCLUSIVE")

    def test_05_vulnerability_scanner_never_ran(self):
        """Scenario 5: Scan where vulnerability scanner never ran -> evidence flag vulnerability_scanned is False."""
        result = {
            "url": "https://example.com",
            "domain": "example.com",
            "ip": "93.184.216.34",
            "protocol": "https",
            "score": 0,
            "risk": "Low"
        }
        ai_res = run_ai_engine(result=result, vulnerability_scanned=False)
        self.assertNotIn("✔ No Critical Vulnerabilities", ai_res["positives"])
        self.assertNotIn("✔ No Known CVEs / Vulnerabilities", ai_res["positives"])

    def test_06_same_target_scanned_twice_valid(self):
        """Scenario 6: Same target scanned successfully twice -> normal historical comparison."""
        curr = {"score": 95, "grade": "A+", "status": "ASSESSED", "has_previous": True}
        prev = {"score": 90, "grade": "A", "status": "ASSESSED", "has_previous": True}
        res = compare_url_scans(curr, prev)
        self.assertEqual(res["score_diff"], 5)
        self.assertEqual(res["score_direction"], "up")

    def test_07_first_scan_inconclusive_second_scan_valid(self):
        """Scenario 7: First scan inconclusive, second scan valid -> 'No previous valid security posture available'."""
        curr = {"score": 90, "grade": "A", "status": "ASSESSED", "has_previous": True}
        prev = {"score": None, "grade": "N/A", "status": "INCONCLUSIVE", "has_previous": True}
        res = compare_url_scans(curr, prev)
        self.assertIsNone(res["score_diff"])
        self.assertEqual(res["score_direction"], "inconclusive")
        self.assertIn("No previous valid security posture available", res["summary_text"])

    def test_08_previous_scan_valid_current_scan_inconclusive(self):
        """Scenario 8: Previous scan valid, current scan inconclusive -> 'No valid current security score available'."""
        curr = {"score": None, "grade": "N/A", "status": "INCONCLUSIVE", "has_previous": True}
        prev = {"score": 96, "grade": "A+", "status": "ASSESSED", "has_previous": True}
        res = compare_url_scans(curr, prev)
        self.assertIsNone(res["score_diff"])
        self.assertEqual(res["score_direction"], "inconclusive")
        self.assertIn("No valid current security score available", res["summary_text"])


if __name__ == "__main__":
    unittest.main()
