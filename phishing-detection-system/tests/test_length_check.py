import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from checks.length_check import check_url_length

class TestLengthCheck(unittest.TestCase):

    def test_short_url_ok(self):
        r = check_url_length("https://google.com")
        self.assertFalse(r["flagged"])
        self.assertEqual(r["severity"], "OK")

    def test_exactly_75_ok(self):
        url = "https://" + "a" * 63 + ".com"   # 75 chars
        r = check_url_length(url)
        self.assertFalse(r["flagged"])

    def test_76_chars_suspicious(self):
        url = "https://" + "a" * 64 + ".com"   # 76 chars
        r = check_url_length(url)
        self.assertTrue(r["flagged"])
        self.assertEqual(r["severity"], "SUSPICIOUS")

    def test_very_long_suspicious(self):
        url = "https://example.com/" + "a" * 200
        r = check_url_length(url)
        self.assertTrue(r["flagged"])
        self.assertEqual(r["severity"], "SUSPICIOUS")

if __name__ == "__main__":
    unittest.main()
