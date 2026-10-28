import tempfile
import unittest
from pathlib import Path

from core.ml.predictor import (
    DEMO_MODEL_PATH,
    MODEL_PATH,
    MAX_TEXT_LENGTH,
    clear_model_cache,
    predict_email_text,
)


class MLPredictorTests(unittest.TestCase):
    def setUp(self):
        clear_model_cache()

    def tearDown(self):
        clear_model_cache()

    def test_predicts_supported_label(self):
        result = predict_email_text(
            "URGENT: Verify your password immediately to avoid account suspension."
        )
        self.assertIn(result["predicted_label"], {"legitimate", "phishing"})

    def test_returns_both_class_estimates(self):
        result = predict_email_text("Please review the meeting agenda.")
        probabilities = result["class_probabilities"]

        self.assertEqual(set(probabilities), {"legitimate", "phishing"})
        self.assertTrue(all(0.0 <= p <= 1.0 for p in probabilities.values()))
        self.assertAlmostEqual(sum(probabilities.values()), 1.0, places=4)

    def test_uses_large_baseline_by_default(self):
        self.assertEqual(MODEL_PATH.name, "balanced_phishing_model.joblib")

        result = predict_email_text(
            "Your order has shipped. Thank you for your purchase."
        )

        self.assertFalse(result["is_demo_model"])
        self.assertIn("random holdout split", result["limitations"])
        self.assertIn("investigation indicators", result["limitations"])

    def test_demo_model_can_be_selected_explicitly(self):
        self.assertTrue(DEMO_MODEL_PATH.is_file())

        result = predict_email_text(
            "Your order has shipped.",
            model_path=DEMO_MODEL_PATH,
        )

        self.assertTrue(result["is_demo_model"])
        self.assertIn("12 hand-written examples", result["limitations"])
        self.assertIn("not reliable real-world", result["limitations"])

    def test_rejects_non_string_input(self):
        for value in (None, 123, ["email text"]):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    predict_email_text(value)

    def test_rejects_empty_input(self):
        for value in ("", "   ", "\n\t"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    predict_email_text(value)

    def test_rejects_oversized_input(self):
        with self.assertRaises(ValueError):
            predict_email_text("x" * (MAX_TEXT_LENGTH + 1))

    def test_missing_model_has_clear_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "missing_model.joblib"

            with self.assertRaisesRegex(
                FileNotFoundError, "Train it first"
            ):
                predict_email_text(
                    "Test email",
                    model_path=missing_path,
                )


if __name__ == "__main__":
    unittest.main()
