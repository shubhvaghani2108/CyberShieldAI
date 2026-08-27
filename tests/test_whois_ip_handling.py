"""
tests/test_whois_ip_handling.py

Unit test suite verifying WHOIS handling for IPv4 and IPv6 targets.
Ensures domain WHOIS lookups are skipped entirely for IP targets and
that 'N/A' values are returned for registrar, creation_date, expiration_date, and updated_date.
"""

import unittest
from scanner.whois_lookup import get_whois
from scanner.url_intelligence import analyze_url_intelligence, get_domain


class TestWhoisIPHandling(unittest.TestCase):

    def test_ipv6_target_whois_returns_na(self):
        """Verify raw IPv6 target returns N/A for WHOIS domain fields."""
        ipv6 = "2600:140f:7200:3c::17d4:c8"
        res = get_whois(ipv6)
        self.assertEqual(res["registrar"], "N/A")
        self.assertEqual(res["creation_date"], "N/A")
        self.assertEqual(res["expiration_date"], "N/A")
        self.assertEqual(res["updated_date"], "N/A")
        self.assertTrue(res["is_ip"])
        self.assertIn("Target is an IP address", res["reason"])

    def test_ipv6_bracketed_target_whois_returns_na(self):
        """Verify bracketed IPv6 target [2600::1] returns N/A."""
        ipv6_bracketed = "[2600:140f:7200:3c::17d4:c8]"
        res = get_whois(ipv6_bracketed)
        self.assertEqual(res["registrar"], "N/A")
        self.assertEqual(res["creation_date"], "N/A")
        self.assertEqual(res["expiration_date"], "N/A")
        self.assertTrue(res["is_ip"])

    def test_ipv4_target_whois_returns_na(self):
        """Verify raw IPv4 target returns N/A for WHOIS domain fields."""
        ipv4 = "192.168.1.1"
        res = get_whois(ipv4)
        self.assertEqual(res["registrar"], "N/A")
        self.assertEqual(res["creation_date"], "N/A")
        self.assertEqual(res["expiration_date"], "N/A")
        self.assertEqual(res["updated_date"], "N/A")
        self.assertTrue(res["is_ip"])
        self.assertIn("Target is an IP address", res["reason"])

    def test_url_intelligence_ipv6_target(self):
        """Verify analyze_url_intelligence on IPv6 URL returns N/A for WHOIS."""
        url = "https://2600:140f:7200:3c::17d4:c8"
        intel = analyze_url_intelligence(url)
        whois = intel["whois"]
        self.assertEqual(whois["registrar"], "N/A")
        self.assertEqual(whois["creation_date"], "N/A")
        self.assertEqual(whois["expiration_date"], "N/A")
        self.assertTrue(whois["is_ip"])

    def test_domain_extractor_ipv6(self):
        """Verify get_domain extracts clean IPv6 address without port/brackets."""
        dom1 = get_domain("https://[2600:140f:7200:3c::17d4:c8]:443")
        self.assertEqual(dom1, "2600:140f:7200:3c::17d4:c8")

        dom2 = get_domain("https://2600:140f:7200:3c::17d4:c8")
        self.assertEqual(dom2, "2600:140f:7200:3c::17d4:c8")


if __name__ == "__main__":
    unittest.main()
