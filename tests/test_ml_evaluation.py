
import json
import unittest
from unittest.mock import patch

from core.ml import train_model


class MLEvaluationTests(unittest.TestCase):
    @patch("core.ml.train_model.joblib.dump")
    @patch("core.ml.train_model.REPORT_PATH")
    @patch("core.ml.train_model.MODEL_PATH")
    @patch("core.ml.train_model.load_dataset")
    def test_report_preserves_evaluation_integrity(
        self,
        mock_load_dataset,
        mock_model_path,
        mock_report_path,
        mock_joblib_dump,
    ):
        texts = [
            "Routine meeting scheduled",
            "Normal project update",
            "Quarterly report available",
            "Team lunch tomorrow",
            "Project notes for review",
            "Your regular invoice is ready",
            "Verify your password urgently",
            "Claim your prize immediately",
            "Account suspended, act now",
            "Urgent payment required",
            "Open the attachment to claim reward",
            "Confirm your account details now",
        ]
        labels = [
            "legitimate",
            "legitimate",
            "legitimate",
            "legitimate",
            "legitimate",
            "legitimate",
            "phishing",
            "phishing",
            "phishing",
            "phishing",
            "phishing",
            "phishing",
        ]

        mock_load_dataset.return_value = (
            texts,
            labels,
            {"legitimate": 6, "phishing": 6},
        )

        mock_model_path.parent.mkdir.return_value = None
        mock_report_path.parent.mkdir.return_value = None
        mock_model_path.relative_to.return_value = train_model.Path(
            "reports/ml/demo_phishing_model.joblib"
        )
        mock_report_path.relative_to.return_value = train_model.Path(
            "reports/ml/demo_evaluation.json"
        )

        captured = {}

        def capture_report(content, encoding):
            captured["report"] = json.loads(content)

        mock_report_path.write_text.side_effect = capture_report

        train_model.train_and_evaluate()

        report = captured["report"]
        matrix = report["confusion_matrix"]
        class_report = report["classification_report"]

        self.assertEqual(report["sample_count"], 12)
        self.assertEqual(report["class_counts"], {
            "legitimate": 6,
            "phishing": 6,
        })
        self.assertEqual(report["train_count"] + report["test_count"], 12)
        self.assertEqual(report["test_count"], 3)

        self.assertEqual(
            report["labels_in_confusion_matrix_order"],
            ["legitimate", "phishing"],
        )
        self.assertEqual(len(matrix), 2)
        self.assertTrue(all(len(row) == 2 for row in matrix))
        self.assertTrue(
            all(
                isinstance(value, int) and value >= 0
                for row in matrix
                for value in row
            )
        )
        self.assertEqual(
            sum(sum(row) for row in matrix),
            report["test_count"],
        )

        self.assertIn("legitimate", class_report)
        self.assertIn("phishing", class_report)
        self.assertIn("accuracy", class_report)

        self.assertTrue(report["limitations"])
        self.assertTrue(
            any(
                "not represent real-world performance" in item
                for item in report["limitations"]
            )
        )
        self.assertEqual(
            report["experiment"],
            "small_demonstration_dataset",
        )

        mock_joblib_dump.assert_called_once()


if __name__ == "__main__":
    unittest.main()
