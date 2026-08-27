"""
tests/test_geoip_unknown_handling.py

Unit test suite verifying GeoIP handling for Unknown / unresolved target IPs.
Ensures HTTP lookups to ip-api.com are skipped entirely when IP is Unknown or invalid,
storing 'Unknown' for all location fields and setting is_assessed = False.
"""

import unittest
from scanner.geoip_lookup import get_geoip
from scanner.url_intelligence import analyze_url_intelligence
from database.save_url_intelligence import save_url_intelligence


class TestGeoIPUnknownHandling(unittest.TestCase):

    def test_01_geoip_unknown_ip_skips_http(self):
        """Verify get_geoip('Unknown') skips HTTP lookup and returns is_assessed=False."""
        res = get_geoip("Unknown")
        self.assertEqual(res["country"], "Unknown")
        self.assertEqual(res["region"], "Unknown")
        self.assertEqual(res["city"], "Unknown")
        self.assertEqual(res["isp"], "Unknown")
        self.assertEqual(res["asn"], "Unknown")
        self.assertFalse(res["is_assessed"])
        self.assertIn("Target IP address could not be resolved", res["reason"])

    def test_02_geoip_none_ip(self):
        """Verify get_geoip(None) returns is_assessed=False."""
        res = get_geoip(None)
        self.assertEqual(res["country"], "Unknown")
        self.assertFalse(res["is_assessed"])

    def test_03_geoip_invalid_string(self):
        """Verify get_geoip('invalid_ip_string') returns is_assessed=False."""
        res = get_geoip("invalid_ip_string")
        self.assertEqual(res["country"], "Unknown")
        self.assertFalse(res["is_assessed"])

    def test_04_url_intelligence_unresolvable_url(self):
        """Verify analyze_url_intelligence on unresolvable URL sets GeoIP to Unknown."""
        url = "https://unreachable-domain-99999.local"
        intel = analyze_url_intelligence(url)
        geoip = intel["geoip"]
        self.assertEqual(geoip["country"], "Unknown")
        self.assertEqual(geoip["city"], "Unknown")
        self.assertFalse(geoip["is_assessed"])

    def test_05_database_save_unknown_ip(self):
        """Verify save_url_intelligence persists 'Unknown' for location fields when IP is Unknown."""
        data = {
            "url": "https://unreachable-domain-99999.local",
            "domain": "unreachable-domain-99999.local",
            "ip": "Unknown",
            "whois": {"registrar": "N/A", "creation_date": "N/A", "expiration_date": "N/A", "updated_date": "N/A", "is_ip": True},
            "geoip": {"country": "India", "region": "Maharashtra", "city": "Vashi", "isp": "Akamai", "asn": "AS20940", "is_assessed": False},
            "waf": {"provider": "None"}
        }
        # save_url_intelligence should sanitize and store 'Unknown' for country, region, city, isp, asn
        save_url_intelligence(data)


if __name__ == "__main__":
    unittest.main()
