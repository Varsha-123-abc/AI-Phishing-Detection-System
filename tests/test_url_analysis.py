import unittest

from core.url_analysis.url_analyzer import analyze_url


class URLAnalysisTests(unittest.TestCase):
    def test_ordinary_https_url(self):
        result = analyze_url("https://example.com/about")
        self.assertTrue(result["valid_syntax"])
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["risk_score"], 0)

    def test_userinfo_indicator(self):
        result = analyze_url("https://trusted.example@evil.example/login")
        codes = [item["code"] for item in result["indicators"]]
        self.assertIn("URL_CONTAINS_USERINFO", codes)
        self.assertEqual(result["hostname"], "evil.example")

    def test_ip_address_host(self):
        result = analyze_url("http://192.0.2.10/login")
        codes = [item["code"] for item in result["indicators"]]
        self.assertIn("URL_USES_IP_ADDRESS", codes)

    def test_punycode_host(self):
        result = analyze_url("https://xn--e1afmkfd.example/")
        codes = [item["code"] for item in result["indicators"]]
        self.assertIn("URL_HAS_PUNYCODE_HOST", codes)

    def test_malformed_url_is_handled(self):
        result = analyze_url("http://[invalid-ipv6/")
        self.assertFalse(result["valid_syntax"])
        self.assertEqual(result["risk_level"], "unknown")

    def test_unsupported_scheme_is_rejected(self):
        result = analyze_url("javascript:alert(1)")
        self.assertFalse(result["valid_syntax"])

    def test_non_string_input_is_rejected(self):
        with self.assertRaises(TypeError):
            analyze_url(None)

    def test_score_is_bounded(self):
        result = analyze_url(
            "http://user:pass@192.0.2.10/"
            + "login/verify/account/" + ("a" * 150)
        )
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_oversized_url_is_not_parsed(self):
        result = analyze_url("https://example.com/" + ("a" * 2100))
        self.assertFalse(result["valid_syntax"])
        self.assertIn(
            "URL_EXCESSIVE_LENGTH",
            [item["code"] for item in result["indicators"]],
        )


if __name__ == "__main__":
    unittest.main()
