import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.ml.prepare_dataset import (
    MAX_EMAIL_CHARS,
    prepare_dataset,
)


class PrepareDatasetTests(unittest.TestCase):
    def write_source(self, directory, rows, headers=None):
        path = Path(directory) / "source.csv"

        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(headers or ["body", "label"])
            writer.writerows(rows)

        return path

    def test_normalizes_labels_and_writes_expected_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_source(
                directory,
                [
                    ["Routine meeting update", "0.0"],
                    ["Urgent password verification", "1.0"],
                ],
            )
            output = Path(directory) / "processed" / "emails.csv"

            prepare_dataset(source, output)

            with output.open(newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                rows = list(reader)

        self.assertEqual(reader.fieldnames, ["text", "label"])
        self.assertEqual(
            rows,
            [
                {"text": "Routine meeting update", "label": "legitimate"},
                {"text": "Urgent password verification", "label": "phishing"},
            ],
        )

    def test_skips_blank_duplicate_and_oversized_bodies(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_source(
                directory,
                [
                    ["   ", "0"],
                    ["Repeated normal message", "0"],
                    ["Repeated normal message", "0"],
                    ["x" * (MAX_EMAIL_CHARS + 1), "1"],
                    ["Suspicious password message", "1"],
                ],
            )
            output = Path(directory) / "processed.csv"

            with patch("builtins.print"):
                prepare_dataset(source, output)

            with output.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["label"] for row in rows},
            {"legitimate", "phishing"},
        )
        self.assertNotIn(
            "Repeated normal message",
            [row["text"] for row in rows][1:],
        )
        self.assertFalse(any(len(row["text"]) > MAX_EMAIL_CHARS for row in rows))

    def test_invalid_label_raises_error_even_for_blank_body(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_source(
                directory,
                [
                    ["Normal message", "0"],
                    ["Phishing message", "1"],
                    ["", "unknown"],
                ],
            )
            output = Path(directory) / "processed.csv"

            with self.assertRaisesRegex(ValueError, "Unsupported label"):
                prepare_dataset(source, output)

            self.assertFalse(output.exists())

    def test_missing_required_column_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_source(
                directory,
                [["Some message"]],
                headers=["message"],
            )
            output = Path(directory) / "processed.csv"

            with self.assertRaisesRegex(ValueError, "columns"):
                prepare_dataset(source, output)

    def test_missing_class_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_source(
                directory,
                [
                    ["Normal message one", "0"],
                    ["Normal message two", "0"],
                ],
            )
            output = Path(directory) / "processed.csv"

            with self.assertRaisesRegex(ValueError, "both classes"):
                prepare_dataset(source, output)

            self.assertFalse(output.exists())

    def test_source_file_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_source(
                directory,
                [
                    ["Normal message", "0"],
                    ["Suspicious message", "1"],
                ],
            )
            original_bytes = source.read_bytes()
            output = Path(directory) / "processed.csv"

            prepare_dataset(source, output)

            self.assertEqual(source.read_bytes(), original_bytes)

    def test_missing_source_file_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "missing.csv"
            output = Path(directory) / "processed.csv"

            with self.assertRaises(FileNotFoundError):
                prepare_dataset(source, output)

    def test_unsupported_numeric_label_raises_error(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_source(
                directory,
                [
                    ["Normal message", "0"],
                    ["Suspicious message", "1"],
                    ["Unknown category", "2"],
                ],
            )
            output = Path(directory) / "processed.csv"

            with self.assertRaisesRegex(ValueError, "Unsupported label"):
                prepare_dataset(source, output)


if __name__ == "__main__":
    unittest.main()
