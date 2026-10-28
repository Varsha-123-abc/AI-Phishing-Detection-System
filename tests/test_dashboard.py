
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from database.history_db import get_recent_analyses


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(self.temp_dir.name) / "test_history.sqlite3"

        self.app = create_app({
            "TESTING": True,
            "HISTORY_DB_PATH": str(db_path),
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def sample_email(self):
        return (
            "From: sender@example.com\n"
            "Subject: Meeting update\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "The team meeting starts at 10 AM tomorrow."
        )

    def test_dashboard_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PhishGuard", response.data)

    def test_empty_submission_shows_message(self):
        response = self.client.post("/", data={"raw_email": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please paste an email", response.data)

    def test_analysis_renders_heuristic_and_ml_results(self):
        response = self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Heuristic score", response.data)
        self.assertIn(b"Experimental ML assessment", response.data)
        self.assertIn(b"Evidence and indicators", response.data)

    def test_large_baseline_warning_and_limitations_render(self):
        response = self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Experimental baseline trained on a merged",
            response.data,
        )
        self.assertIn(b"source or campaign leakage", response.data)
        self.assertIn(b"investigation indicators", response.data)
        self.assertIn(b"not calibrated threat", response.data)

    @patch("core.threat_scoring.risk_scorer.predict_email_text")
    def test_demo_model_warning_renders_when_demo_selected(
        self, mock_predict
    ):
        mock_predict.return_value = {
            "predicted_label": "phishing",
            "class_probabilities": {
                "legitimate": 0.1,
                "phishing": 0.9,
            },
            "model_type": "TF-IDF + Logistic Regression",
            "is_demo_model": True,
            "limitations": (
                "Demo model trained on 12 hand-written examples; "
                "not reliable real-world phishing verdicts."
            ),
        }

        response = self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"12 hand-written examples", response.data)
        self.assertIn(b"not suitable", response.data)
        self.assertNotIn(
            b"Experimental baseline trained on a merged",
            response.data,
        )
        mock_predict.assert_called_once()

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

    def test_successful_analysis_is_saved_to_history(self):
        response = self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )
        self.assertEqual(response.status_code, 200)

        history_response = self.client.get("/history")
        self.assertEqual(history_response.status_code, 200)
        self.assertIn(b"sender@example.com", history_response.data)
        self.assertIn(b"Meeting update", history_response.data)

    def test_history_detail_shows_saved_analysis(self):
        self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )

        records = get_recent_analyses(
            db_path=self.app.config["HISTORY_DB_PATH"]
        )
        self.assertEqual(len(records), 1)

        detail_response = self.client.get(
            f"/history/{records[0]['id']}"
        )
        self.assertEqual(detail_response.status_code, 200)
        self.assertIn(b"Saved Analysis", detail_response.data)
        self.assertIn(b"ML assessment snapshot", detail_response.data)

    def test_missing_history_record_returns_404(self):
        response = self.client.get("/history/999999")
        self.assertEqual(response.status_code, 404)


    def test_investigation_note_is_saved_and_displayed(self):
        self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )

        records = get_recent_analyses(
            db_path=self.app.config["HISTORY_DB_PATH"]
        )
        analysis_id = records[0]["id"]

        response = self.client.post(
            f"/history/{analysis_id}/notes",
            data={"note": "Reviewed sender; further verification required."},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Investigation note saved.", response.data)
        self.assertIn(
            b"Reviewed sender; further verification required.",
            response.data,
        )
        self.assertIn(b"Saved notes (1)", response.data)

    def test_blank_investigation_note_is_rejected(self):
        self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )
        records = get_recent_analyses(
            db_path=self.app.config["HISTORY_DB_PATH"]
        )
        analysis_id = records[0]["id"]

        response = self.client.post(
            f"/history/{analysis_id}/notes",
            data={"note": "   "},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Investigation note cannot be empty.",
            response.data,
        )
        self.assertIn(b"Saved notes (0)", response.data)

    def test_oversized_investigation_note_is_rejected(self):
        self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )
        records = get_recent_analyses(
            db_path=self.app.config["HISTORY_DB_PATH"]
        )
        analysis_id = records[0]["id"]

        response = self.client.post(
            f"/history/{analysis_id}/notes",
            data={"note": "N" * 5001},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"cannot exceed 5000 characters",
            response.data,
        )
        self.assertIn(b"Saved notes (0)", response.data)

    def test_notes_route_returns_404_for_missing_analysis(self):
        response = self.client.post(
            "/history/999999/notes",
            data={"note": "Test note"},
        )

        self.assertEqual(response.status_code, 404)
    def test_csv_export_downloads_empty_history(self):
        response = self.client.get("/history/export.csv")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn(
            'filename="phishguard-analysis-history.csv"',
             response.headers["Content-Disposition"],
         )
        self.assertIn(b"Analysis ID", response.data)
        self.assertIn(b"Attachment Count", response.data)

    def test_csv_export_contains_saved_analysis(self):
        self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )

        response = self.client.get("/history/export.csv")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"sender@example.com", response.data)
        self.assertIn(b"Meeting update", response.data)
        self.assertIn(b"Risk Score", response.data)

    def test_csv_export_escapes_formula_like_sender(self):
        raw_email = (
            "From: =1+1@example.com\n"
            "Subject: Spreadsheet safety test\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "Test message."
        )
        self.client.post("/", data={"raw_email": raw_email})

        response = self.client.get("/history/export.csv")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"'=1+1@example.com", response.data)

    def test_history_page_contains_csv_export_link(self):
        response = self.client.get("/history")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"/history/export.csv", response.data)
        self.assertIn(b"Export history as CSV", response.data)
    def test_pdf_export_downloads_saved_analysis(self):
        self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )

        records = get_recent_analyses(
            db_path=self.app.config["HISTORY_DB_PATH"]
        )
        analysis_id = records[0]["id"]

        response = self.client.get(
            f"/history/{analysis_id}/export.pdf"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/pdf", response.content_type)
        self.assertIn(
            f'phishguard-analysis-{analysis_id}.pdf',
            response.headers["Content-Disposition"],
        )
        self.assertTrue(response.data.startswith(b"%PDF-"))
        self.assertEqual(
            response.headers.get("X-Content-Type-Options"),
            "nosniff",
        )

    def test_pdf_export_returns_404_for_missing_analysis(self):
        response = self.client.get(
            "/history/999999/export.pdf"
        )

        self.assertEqual(response.status_code, 404)

    def test_history_detail_contains_pdf_export_link(self):
        self.client.post(
            "/", data={"raw_email": self.sample_email()}
        )

        records = get_recent_analyses(
            db_path=self.app.config["HISTORY_DB_PATH"]
        )
        analysis_id = records[0]["id"]

        response = self.client.get(
            f"/history/{analysis_id}"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            f"/history/{analysis_id}/export.pdf".encode(),
            response.data,
        )
        self.assertIn(b"Download this analysis as PDF", response.data)


if __name__ == "__main__":
    unittest.main()
