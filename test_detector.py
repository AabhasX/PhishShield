import unittest
from unittest.mock import patch
import socket
import json

from detector import check_domain_exists, extract_hostname, analyze_url
from app import app, get_db, init_db


class TestDNSResolution(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        init_db()

    def test_extract_hostname(self):
        self.assertEqual(extract_hostname("https://google.com/path"), "google.com")
        self.assertEqual(extract_hostname("http://sub.example.org:8080/"), "sub.example.org")
        self.assertEqual(extract_hostname("paypal-login.com"), "paypal-login.com")
        self.assertEqual(extract_hostname(""), "")

    def test_check_domain_exists_valid_ip(self):
        # Local loopback / IP always resolves
        self.assertTrue(check_domain_exists("127.0.0.1"))
        self.assertTrue(check_domain_exists("8.8.8.8"))

    def test_check_domain_exists_empty(self):
        self.assertFalse(check_domain_exists(""))
        self.assertFalse(check_domain_exists("   "))
        self.assertFalse(check_domain_exists("0.0.0.0"))

    def test_check_domain_exists_nonexistent(self):
        # Non-existent domain
        self.assertFalse(check_domain_exists("this-domain-does-not-exist-12345xyz6789.org"))

    @patch("detector.socket.gethostbyname")
    def test_check_domain_exists_mocked_success(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "93.184.216.34"
        self.assertTrue(check_domain_exists("example.com"))

    @patch("detector.socket.gethostbyname")
    def test_check_domain_exists_mocked_gaierror(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.gaierror("getaddrinfo failed")
        self.assertFalse(check_domain_exists("invalid-domain.test"))

    @patch("detector.socket.gethostbyname")
    def test_check_domain_exists_mocked_timeout(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.timeout("timed out")
        self.assertFalse(check_domain_exists("slow-domain.test"))

    def test_analyze_url_nonexistent_domain(self):
        result = analyze_url("http://this-domain-does-not-exist-12345xyz6789.org")
        self.assertEqual(result["exists"], False)
        self.assertEqual(result["error"], "URL Not Found")
        self.assertEqual(
            result["message"],
            "The specified domain could not be resolved. Please verify the URL or ensure the host is registered."
        )
        self.assertNotIn("score", result)
        self.assertNotIn("reasons", result)

    @patch("detector.check_domain_exists", return_value=True)
    def test_analyze_url_resolvable_domain(self, mock_check_domain):
        result = analyze_url("https://google.com")
        self.assertEqual(result["exists"], True)
        self.assertEqual(result["host"], "google.com")
        self.assertIn("score", result)
        self.assertIn("status", result)
        self.assertIn("reasons", result)

    def test_analyze_url_check_dns_false(self):
        # Offline heuristic analysis when check_dns=False
        result = analyze_url("http://arbitrary-fake-domain-test.com/login", check_dns=False)
        self.assertEqual(result["exists"], True)
        self.assertIn("score", result)
        self.assertIn("reasons", result)

    def test_analyze_route_nonexistent_domain(self):
        response = self.app.post(
            "/analyze",
            json={"url": "http://this-domain-does-not-exist-12345xyz6789.org"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["exists"], False)
        self.assertEqual(data["error"], "URL Not Found")

    def test_api_scan_simulation_mode_bypass_dns(self):
        # Simulation mode: check_dns=False allows analyzing synthetic domains like netfiix-verify.com
        response = self.app.post(
            "/api/scan",
            json={
                "url": "http://netfiix-verify.com/login",
                "check_dns": False
            }
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["exists"], True)
        self.assertEqual(data["host"], "netfiix-verify.com")
        self.assertEqual(data["status"], "HIGH RISK")
        self.assertGreater(data["score"], 60)
        self.assertTrue(any("netflix" in r.lower() for r in data["reasons"]))

    def test_api_scan_missing_url(self):
        response = self.app.post("/api/scan", json={})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_api_scan_nonexistent_domain(self):
        conn = get_db()
        initial_count = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        conn.close()

        response = self.app.post(
            "/api/scan",
            json={"url": "http://this-domain-does-not-exist-12345xyz6789.org"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["exists"], False)
        self.assertEqual(data["error"], "URL Not Found")
        self.assertEqual(
            data["message"],
            "The specified domain could not be resolved. Please verify the URL or ensure the host is registered."
        )

        # Confirm scan was NOT saved to the database
        conn = get_db()
        final_count = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        conn.close()
        self.assertEqual(initial_count, final_count)

    @patch("app.analyze_url")
    def test_api_scan_resolvable_domain(self, mock_analyze):
        mock_analyze.return_value = {
            "exists": True,
            "url": "https://resolved-domain-test.com",
            "host": "resolved-domain-test.com",
            "score": 0,
            "status": "SAFE",
            "reasons": ["No major risk indicators were detected by the current rules"]
        }

        conn = get_db()
        initial_count = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        conn.close()

        response = self.app.post(
            "/api/scan",
            json={"url": "https://resolved-domain-test.com"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["exists"], True)
        self.assertEqual(data["score"], 0)
        self.assertEqual(data["status"], "SAFE")

        # Confirm scan was saved to the database
        conn = get_db()
        final_count = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        conn.close()
        self.assertEqual(final_count, initial_count + 1)


if __name__ == "__main__":
    unittest.main()
