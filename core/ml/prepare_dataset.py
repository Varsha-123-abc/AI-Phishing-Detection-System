"""Prepare a large phishing-email dataset without changing the source file."""

import csv
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = Path.home() / "Downloads" / "Balanced_Dataset.csv"
OUTPUT_PATH = PROJECT_ROOT / "datasets" / "processed" / "balanced_emails.csv"

MAX_EMAIL_CHARS = 100_000

LABEL_MAP = {
    "0": "legitimate",
    "0.0": "legitimate",
    "1": "phishing",
    "1.0": "phishing",
}


def prepare_dataset(source_path=SOURCE_PATH, output_path=OUTPUT_PATH):
    """Validate, normalize, deduplicate, and stream cleaned email bodies."""
    source_path = Path(source_path)
    output_path = Path(output_path)

    if not source_path.is_file():
        raise FileNotFoundError(f"Source dataset not found: {source_path}")

    if source_path.resolve() == output_path.resolve():
        raise ValueError("Source and output paths must be different.")

    csv.field_size_limit(sys.maxsize)

    seen_bodies = set()
    class_counts = Counter()
    skipped = Counter()
    source_rows = 0
    prepared_rows = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None

    try:
        with source_path.open(
            "r", encoding="utf-8-sig", newline=""
        ) as source:
            reader = csv.DictReader(source)

            if (
                not reader.fieldnames
                or not {"body", "label"}.issubset(reader.fieldnames)
            ):
                raise ValueError(
                    "Source CSV must contain 'body' and 'label' columns."
                )

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="",
                dir=output_path.parent,
                prefix=f".{output_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                writer = csv.DictWriter(
                    temporary, fieldnames=["text", "label"]
                )
                writer.writeheader()

                for row_number, row in enumerate(reader, start=2):
                    source_rows += 1

                    body = (row.get("body") or "").strip()
                    raw_label = (row.get("label") or "").strip()

                    label = LABEL_MAP.get(raw_label)
                    if label is None:
                        raise ValueError(
                            f"Unsupported label {raw_label!r} "
                            f"at CSV row {row_number}."
                        )

                    if not body:
                        skipped["blank_body"] += 1
                        continue

                    if len(body) > MAX_EMAIL_CHARS:
                        skipped["over_length_limit"] += 1
                        continue

                    if body in seen_bodies:
                        skipped["duplicate_body"] += 1
                        continue

                    seen_bodies.add(body)
                    writer.writerow({"text": body, "label": label})
                    class_counts[label] += 1
                    prepared_rows += 1

        if prepared_rows == 0:
            raise ValueError("No usable email records remain after cleaning.")

        if set(class_counts) != {"legitimate", "phishing"}:
            raise ValueError("Cleaned dataset must contain both classes.")

        # Replace the final file only after successful validation.
        os.replace(temporary_path, output_path)
        temporary_path = None

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    print("Dataset preparation completed.")
    print("Source rows:", source_rows)
    print("Prepared rows:", prepared_rows)
    print("Class counts:", dict(class_counts))
    print("Skipped records:", dict(skipped))
    print("Maximum accepted email length:", MAX_EMAIL_CHARS)
    print("Processed dataset:", output_path)


if __name__ == "__main__":
    prepare_dataset()
