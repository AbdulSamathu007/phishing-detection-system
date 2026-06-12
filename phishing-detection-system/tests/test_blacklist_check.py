import os, tempfile, unittest, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from checks.blacklist_check import check_blacklist, load_blacklist

class TestBlacklistCheck(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        self.tmp.write("known-phishing-site.com\n")
        self.tmp.write("paypal-secure-login.com\n")
        self.tmp.write("# comment line\n")
        self.tmp.write("amazon-security-alert.com\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_load_returns_set(self):
        self.assertIsInstance(load_blacklist(self.tmp.name), set)

    def test_load_ignores_comments(self):
        bl = load_blacklist(self.tmp.name)
        for entry in bl:
            self.assertFalse(entry.startswith("#"))

    def test_missing_file_returns_empty(self):
        self.assertEqual(load_blacklist("/nonexistent/path.txt"), set())

    def test_blacklisted_domain_dangerous(self):
        r = check_blacklist("https://known-phishing-site.com/login", self.tmp.name)
        self.assertTrue(r["flagged"])
        self.assertEqual(r["severity"], "DANGEROUS")

    def test_www_prefix_stripped(self):
        r = check_blacklist("https://www.paypal-secure-login.com", self.tmp.name)
        self.assertTrue(r["flagged"])

    def test_clean_domain_ok(self):
        r = check_blacklist("https://google.com", self.tmp.name)
        self.assertFalse(r["flagged"])
        self.assertEqual(r["severity"], "OK")

if __name__ == "__main__":
    unittest.main()
