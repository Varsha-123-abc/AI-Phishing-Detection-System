import unittest

from core.email_analysis.email_parser import parse_email
from core.email_analysis.indicator_extractor import extract_indicators
from core.threat_scoring.risk_scorer import score_email


class EmailIntegrationTests(unittest.TestCase):
    def make_email(self, body, extra_headers=""):
        return parse_email(
            "From: sender@example.com\n"
            "To: analyst@example.org\n"
            f"{extra_headers}"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            f"{body}\n"
        )

    def test_url_findings_are_included_in_email_indicators(self):
        parsed = self.make_email(
            "Review this link: https://trusted.example@evil.example/login"
        )
        indicators = extract_indicators(parsed)
        codes = [item["code"] for item in indicators]

        self.assertIn("URL_CONTAINS_USERINFO", codes)
        self.assertIn("URL_SUSPICIOUS_PATH_WORD", codes)

        url_finding = next(
            item for item in indicators
            if item["code"] == "URL_CONTAINS_USERINFO"
        )
        self.assertEqual(
            url_finding["url"],
            "https://trusted.example@evil.example/login",
        )
        self.assertEqual(url_finding["source"], "url_analysis")

    def test_ordinary_email_has_low_zero_score(self):
        result = score_email(
            self.make_email("The meeting starts at 10.")
        )
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["indicator_count"], 0)

    def test_suspicious_email_receives_higher_score(self):
        result = score_email(
            self.make_email(
                "Urgent action required. Verify your account. "
                "https://trusted.example@evil.example/login"
            )
        )
        self.assertGreater(result["risk_score"], 0)
        self.assertIn(
            result["risk_level"],
            {"medium", "high", "critical"},
        )
        self.assertGreater(result["indicator_count"], 1)

    def test_score_is_bounded(self):
        result = score_email(
            self.make_email(
                " ".join(["Verify your account."] * 20)
                + " http://192.0.2.10/login"
            )
        )
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_risk_level_thresholds(self):
        from core.threat_scoring.risk_scorer import risk_level_from_score

        self.assertEqual(risk_level_from_score(0), "low")
        self.assertEqual(risk_level_from_score(25), "medium")
        self.assertEqual(risk_level_from_score(50), "high")
        self.assertEqual(risk_level_from_score(75), "critical")

    def test_invalid_score_is_rejected(self):
        from core.threat_scoring.risk_scorer import risk_level_from_score

        with self.assertRaises(ValueError):
            risk_level_from_score(101)


if __name__ == "__main__":
    unittest.main()
