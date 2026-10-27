import unittest
from unittest.mock import patch

from core.email_analysis.email_parser import parse_email
from core.threat_scoring.risk_scorer import score_email


class MLScoringIntegrationTests(unittest.TestCase):
    def make_email(self, subject="Meeting", body="The meeting starts at 10."):
        return parse_email(
            f"From: sender@example.com\n"
            f"Subject: {subject}\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            f"{body}\n"
        )

    def mock_prediction(self, text):
        return {
            "predicted_label": "phishing",
            "class_probabilities": {
                "legitimate": 0.4,
                "phishing": 0.6,
            },
            "model_type": "TF-IDF + Logistic Regression",
            "is_demo_model": True,
            "limitations": "Experimental demonstration model.",
        }

    @patch(
        "core.threat_scoring.risk_scorer.predict_email_text"
    )
    def test_ml_assessment_is_reported_separately(self, mock_predict):
        mock_predict.side_effect = self.mock_prediction

        result = score_email(self.make_email())

        self.assertEqual(result["ml_assessment"]["status"], "available")
        self.assertEqual(
            result["ml_assessment"]["predicted_label"], "phishing"
        )
        self.assertTrue(result["ml_assessment"]["is_demo_model"])
        mock_predict.assert_called_once()
        self.assertIn("Meeting", mock_predict.call_args.args[0])

    @patch(
        "core.threat_scoring.risk_scorer.predict_email_text"
    )
    def test_ml_prediction_does_not_change_heuristic_score(self, mock_predict):
        mock_predict.side_effect = self.mock_prediction
        email = self.make_email()

        with_ml = score_email(email, include_ml=True)
        without_ml = score_email(email, include_ml=False)

        self.assertEqual(with_ml["risk_score"], without_ml["risk_score"])
        self.assertEqual(with_ml["risk_level"], without_ml["risk_level"])
        self.assertEqual(with_ml["indicator_count"], without_ml["indicator_count"])
        self.assertEqual(with_ml["ml_assessment"]["status"], "available")
        self.assertEqual(without_ml["ml_assessment"]["status"], "disabled")

    @patch(
        "core.threat_scoring.risk_scorer.predict_email_text",
        side_effect=FileNotFoundError("Model file is missing."),
    )
    def test_missing_model_is_reported_as_unavailable(self, mock_predict):
        result = score_email(self.make_email())

        self.assertEqual(result["ml_assessment"]["status"], "unavailable")
        self.assertIn("missing", result["ml_assessment"]["note"].lower())
        self.assertEqual(result["risk_score"], 0)

    @patch(
        "core.threat_scoring.risk_scorer.predict_email_text"
    )
    def test_empty_email_text_does_not_call_model(self, mock_predict):
        email = self.make_email(subject="", body="")
        result = score_email(email)

        self.assertEqual(result["ml_assessment"]["status"], "unavailable")
        mock_predict.assert_not_called()


if __name__ == "__main__":
    unittest.main()
