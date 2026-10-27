
import csv
import tempfile
import unittest
from pathlib import Path

from core.ml.train_model import load_dataset


class MLDatasetTests(unittest.TestCase):
    def write_csv(self, directory, headers, rows):
        path = Path(directory) / "emails.csv"

        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(rows)

        return path

    def test_loads_valid_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_csv(
                directory,
                ["text", "label"],
                [
                    ["Normal meeting email", "legitimate"],
                    ["Another normal email", "legitimate"],
                    ["Verify your password urgently", "phishing"],
                    ["Claim your prize now", "phishing"],
                ],
            )

            texts, labels, counts = load_dataset(path)

        self.assertEqual(len(texts), 4)
        self.assertEqual(labels.count("legitimate"), 2)
        self.assertEqual(labels.count("phishing"), 2)
        self.assertEqual(
            counts, {"legitimate": 2, "phishing": 2}
        )

    def test_missing_file_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.csv"

            with self.assertRaises(FileNotFoundError):
                load_dataset(path)

    def test_empty_dataset_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_csv(directory, ["text", "label"], [])

            with self.assertRaisesRegex(ValueError, "empty"):
                load_dataset(path)

    def test_missing_required_column_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_csv(
                directory,
                ["text"],
                [["Email text"]],
            )

            with self.assertRaisesRegex(ValueError, "columns"):
                load_dataset(path)

    def test_blank_email_text_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_csv(
                directory,
                ["text", "label"],
                [
                    ["   ", "legitimate"],
                    ["Normal email", "legitimate"],
                    ["Phishing email", "phishing"],
                    ["Another phishing email", "phishing"],
                ],
            )

            with self.assertRaisesRegex(ValueError, "Empty text"):
                load_dataset(path)

    def test_unsupported_label_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_csv(
                directory,
                ["text", "label"],
                [
                    ["Normal email", "legitimate"],
                    ["Another normal email", "legitimate"],
                    ["Suspicious email", "spam"],
                    ["Phishing email", "phishing"],
                ],
            )

            with self.assertRaisesRegex(ValueError, "Unsupported label"):
                load_dataset(path)

    def test_missing_class_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_csv(
                directory,
                ["text", "label"],
                [
                    ["Normal email one", "legitimate"],
                    ["Normal email two", "legitimate"],
                ],
            )

            with self.assertRaisesRegex(ValueError, "both required classes"):
                load_dataset(path)

    def test_insufficient_class_examples_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_csv(
                directory,
                ["text", "label"],
                [
                    ["Normal email", "legitimate"],
                    ["Phishing email one", "phishing"],
                    ["Phishing email two", "phishing"],
                ],
            )

            with self.assertRaisesRegex(ValueError, "two examples per class"):
                load_dataset(path)


if __name__ == "__main__":
    unittest.main()

