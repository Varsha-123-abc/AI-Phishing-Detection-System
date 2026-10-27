import unittest

from app import create_app


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

    def test_dashboard_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PhishGuard", response.data)

    def test_empty_submission_shows_message(self):
        response = self.client.post("/", data={"raw_email": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please paste an email", response.data)

    def test_analysis_renders_heuristic_and_ml_results(self):
        raw_email = (
            "From: sender@example.com\n"
            "Subject: Meeting update\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "The team meeting starts at 10 AM tomorrow."
        )
        response = self.client.post("/", data={"raw_email": raw_email})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Heuristic score", response.data)
        self.assertIn(b"Experimental ML assessment", response.data)
        self.assertIn(b"Evidence and indicators", response.data)

    def test_severity_summary_renders_all_four_categories(self):
        raw_email = (
            "From: sender@example.com\n"
            "Subject: Urgent account verification required\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "URGENT: Verify your account immediately to avoid suspension."
        )
        response = self.client.post("/", data={"raw_email": raw_email})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Indicator severity breakdown", response.data)
        self.assertIn(b"Critical", response.data)
        self.assertIn(b"High", response.data)
        self.assertIn(b"Medium", response.data)
        self.assertIn(b"Low", response.data)

    def test_oversized_request_is_rejected(self):
        response = self.client.post(
            "/",
            data={"raw_email": "A" * 1_200_000},
        )
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
