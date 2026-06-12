import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from checks.ip_check import check_ip_url

class TestIPCheck(unittest.TestCase):

    def test_private_ip_flagged(self):
        r = check_ip_url("http://192.168.1.1/login")
        self.assertTrue(r["flagged"])
        self.assertEqual(r["severity"], "DANGEROUS")

    def test_public_ip_flagged(self):
        r = check_ip_url("http://8.8.8.8/page")
        self.assertTrue(r["flagged"])
        self.assertEqual(r["severity"], "DANGEROUS")

    def test_normal_domain_ok(self):
        r = check_ip_url("https://google.com")
        self.assertFalse(r["flagged"])
        self.assertEqual(r["severity"], "OK")

    def test_subdomain_ok(self):
        r = check_ip_url("https://mail.google.com/inbox")
        self.assertFalse(r["flagged"])
        self.assertEqual(r["severity"], "OK")

    def test_https_ip_flagged(self):
        r = check_ip_url("https://10.0.0.1/secure")
        self.assertTrue(r["flagged"])
        self.assertEqual(r["severity"], "DANGEROUS")

if __name__ == "__main__":
    unittest.main()
