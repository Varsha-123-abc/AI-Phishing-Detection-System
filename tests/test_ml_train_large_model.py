import csv
import hashlib
import tempfile
import unittest
from pathlib import Path

from core.ml.train_large_model import (
    LABELS,
    MAX_FEATURES,
    RANDOM_STATE,
    TEST_SIZE,
    load_dataset,
    sha256_file,
)


class LargeModelDatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.csv_path = Path(self.temp_dir.name) / "emails.csv"

    def write_csv(self, headers, rows):
        with self.csv_path.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(rows)

    def test_loads_valid_dataset_and_counts_classes(self):
        self.write_csv(
            ["text", "label"],
            [
                ["A normal meeting reminder", "legitimate"],
                ["A suspicious password request", "phishing"],
                ["A project status update", "legitimate"],
                ["An urgent account verification request", "phishing"],
            ],
        )

        texts, labels, counts = load_dataset(self.csv_path)

        self.assertEqual(len(texts), 4)
        self.assertEqual(len(labels), 4)
        self.assertEqual(
            counts, {"legitimate": 2, "phishing": 2}
        )
        self.assertEqual(set(labels), set(LABELS))

    def test_missing_file_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            load_dataset(Path(self.temp_dir.name) / "missing.csv")

    def test_missing_header_raises_error(self):
        self.csv_path.write_text("", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "header is missing"):
            load_dataset(self.csv_path)

    def test_missing_required_column_raises_error(self):
        self.write_csv(
            ["text", "category"],
            [["Normal email", "legitimate"]],
        )

        with self.assertRaisesRegex(
            ValueError, "must contain 'text' and 'label'"
        ):
            load_dataset(self.csv_path)

    def test_duplicate_column_names_raise_error(self):
        self.write_csv(
            ["text", "label", "label"],
            [["Normal email", "legitimate", "legitimate"]],
        )

        with self.assertRaisesRegex(ValueError, "duplicate columns"):
            load_dataset(self.csv_path)

    def test_blank_email_raises_error(self):
        self.write_csv(
            ["text", "label"],
            [["   ", "legitimate"]],
        )

        with self.assertRaisesRegex(ValueError, "Empty text"):
            load_dataset(self.csv_path)

    def test_unsupported_label_raises_error(self):
        self.write_csv(
            ["text", "label"],
            [["Email text", "unknown"]],
        )

        with self.assertRaisesRegex(
            ValueError, "Unsupported label"
        ):
            load_dataset(self.csv_path)

    def test_duplicate_email_text_raises_error(self):
        self.write_csv(
            ["text", "label"],
            [
                ["Repeated email body", "legitimate"],
                ["Repeated email body", "phishing"],
            ],
        )

        with self.assertRaisesRegex(ValueError, "Duplicate email text"):
            load_dataset(self.csv_path)

    def test_missing_class_raises_error(self):
        self.write_csv(
            ["text", "label"],
            [
                ["First normal email", "legitimate"],
                ["Second normal email", "legitimate"],
            ],
        )

        with self.assertRaisesRegex(ValueError, "both required classes"):
            load_dataset(self.csv_path)

    def test_class_with_too_few_examples_raises_error(self):
        self.write_csv(
            ["text", "label"],
            [
                ["Normal email one", "legitimate"],
                ["Normal email two", "legitimate"],
                ["One suspicious email", "phishing"],
            ],
        )

        with self.assertRaisesRegex(
            ValueError, "At least two examples per class"
        ):
            load_dataset(self.csv_path)

    def test_sha256_matches_standard_digest(self):
        self.csv_path.write_bytes(b"test dataset bytes")

        expected = hashlib.sha256(b"test dataset bytes").hexdigest()

        self.assertEqual(sha256_file(self.csv_path), expected)

    def test_training_configuration_is_valid(self):
        self.assertEqual(LABELS, ["legitimate", "phishing"])
        self.assertGreater(MAX_FEATURES, 0)
        self.assertGreater(TEST_SIZE, 0)
        self.assertLess(TEST_SIZE, 1)
        self.assertIsInstance(RANDOM_STATE, int)


if __name__ == "__main__":
    unittest.main()
