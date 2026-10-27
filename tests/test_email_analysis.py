import unittest

from core.email_analysis.email_parser import parse_email
from core.email_analysis.indicator_extractor import extract_indicators


class EmailAnalysisTests(unittest.TestCase):
    def test_parse_basic_email(self):
        raw = (
            "From: sender@example.com\n"
            "To: analyst@example.org\n"
            "Subject: Meeting notes\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "The meeting starts at 10.\n"
        )
        result = parse_email(raw)
        self.assertEqual(result["headers"]["from"], "sender@example.com")
        self.assertEqual(result["headers"]["subject"], "Meeting notes")
        self.assertIn("meeting starts", result["body"].lower())
        self.assertEqual(result["urls"], [])

    def test_extracts_url_without_visiting_it(self):
        raw = (
            "From: sender@example.com\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Review this link: https://example.com/login.\n"
        )
        result = parse_email(raw)
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(result["urls"][0]["hostname"], "example.com")

    def test_urgency_indicator(self):
        raw = (
            "From: sender@example.com\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Urgent action required. Verify your account.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertIn("SUSPICIOUS_URGENCY_LANGUAGE", codes)

    def test_reply_to_domain_mismatch(self):
        raw = (
            "From: Support <help@example.com>\n"
            "Reply-To: account@different.example\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Please review the notice.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertIn("REPLY_TO_DOMAIN_MISMATCH", codes)

    def test_rejects_oversized_email(self):
        with self.assertRaises(ValueError):
            parse_email("A" * 1_000_001)

    def test_rejects_non_string_input(self):
        with self.assertRaises(TypeError):
            parse_email(None)


    def test_reported_authentication_failure(self):
        raw = (
            "From: sender@example.com\n"
            "Authentication-Results: mx.example; spf=fail\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Please review this message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        findings = [
            item for item in indicators
            if item["code"] == "AUTHENTICATION_FAILURE_REPORTED"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("spf=fail", findings[0]["evidence"].lower())

    def test_duplicate_authentication_failure_is_deduplicated(self):
        raw = (
            "From: sender@example.com\n"
            "Authentication-Results: mx.example; spf=fail; spf=fail\n"
            "Received-SPF: fail (example: SPF check failed)\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Please review this message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        findings = [
            item for item in indicators
            if item["code"] == "AUTHENTICATION_FAILURE_REPORTED"
        ]
        self.assertEqual(len(findings), 1)

    def test_received_spf_failure_is_detected(self):
        raw = (
            "From: sender@example.com\n"
            "Received-SPF: fail (example: SPF check failed)\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Please review this message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        findings = [
            item for item in indicators
            if item["code"] == "AUTHENTICATION_FAILURE_REPORTED"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("Received-SPF", findings[0]["evidence"])
        self.assertIn("unverified", findings[0]["evidence"].lower())

    def test_distinct_authentication_mechanisms_are_preserved(self):
        raw = (
            "From: sender@example.com\n"
            "Authentication-Results: mx.example; spf=fail; dkim=fail\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Please review this message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        findings = [
            item for item in indicators
            if item["code"] == "AUTHENTICATION_FAILURE_REPORTED"
        ]
        self.assertEqual(len(findings), 2)
        evidence = " ".join(item["evidence"].lower() for item in findings)
        self.assertIn("spf=fail", evidence)
        self.assertIn("dkim=fail", evidence)

    def test_non_failure_authentication_results_are_not_failures(self):
        raw = (
            "From: sender@example.com\n"
            "Authentication-Results: mx.example; spf=softfail; dkim=none; "
            "dmarc=neutral\n"
            "Received-SPF: softfail (example: SPF soft failure)\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Ordinary test message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertNotIn("AUTHENTICATION_FAILURE_REPORTED", codes)

    def test_missing_authentication_results_is_not_a_failure_indicator(self):
        raw = (
            "From: sender@example.com\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Hello, this is an ordinary message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertNotIn("AUTHENTICATION_FAILURE_REPORTED", codes)


    def test_from_return_path_domain_mismatch_is_low_severity(self):
        raw = (
            "From: sender@example.com\n"
            "Return-Path: bounce@mailer.example.net\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\nAn ordinary message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        findings = [
            item for item in indicators
            if item["code"] == "FROM_RETURN_PATH_DOMAIN_MISMATCH"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "low")
        self.assertIn("can be legitimate", findings[0]["evidence"])

    def test_matching_from_and_return_path_domains_are_not_flagged(self):
        raw = (
            "From: sender@example.com\n"
            "Return-Path: bounce@example.com\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\nAn ordinary message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertNotIn("FROM_RETURN_PATH_DOMAIN_MISMATCH", codes)

    def test_missing_return_path_is_not_flagged(self):
        raw = (
            "From: sender@example.com\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\nAn ordinary message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertNotIn("FROM_RETURN_PATH_DOMAIN_MISMATCH", codes)

    def test_malformed_present_from_header_is_reported(self):
        raw = (
            "From: not-an-email-address\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\nPlease review this message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertIn("MALFORMED_FROM_ADDRESS", codes)

    def test_missing_from_header_is_not_called_malformed(self):
        raw = (
            "Subject: Header test\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\nAn ordinary message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertNotIn("MALFORMED_FROM_ADDRESS", codes)

    def test_conflicting_spf_results_are_reported_for_review(self):
        raw = (
            "From: sender@example.com\n"
            "Authentication-Results: mx.example; spf=pass\n"
            "Received-SPF: fail (example: SPF check failed)\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\nPlease review this message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        findings = [
            item for item in indicators
            if item["code"] == "CONFLICTING_AUTHENTICATION_RESULTS"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "low")
        self.assertIn("spf", findings[0]["evidence"].lower())
        self.assertIn("unverified", findings[0]["evidence"].lower())

    def test_consistent_authentication_results_are_not_conflicting(self):
        raw = (
            "From: sender@example.com\n"
            "Authentication-Results: mx.example; spf=pass; dkim=pass\n"
            "Received-SPF: pass (example: SPF check passed)\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\nAn ordinary message.\n"
        )
        indicators = extract_indicators(parse_email(raw))
        codes = [item["code"] for item in indicators]
        self.assertNotIn("CONFLICTING_AUTHENTICATION_RESULTS", codes)

if __name__ == "__main__":
    unittest.main()
