"""Train and evaluate the experimental phishing email classifier.

The bundled demonstration dataset is intentionally small and is not
suitable for estimating real-world phishing detection performance.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = PROJECT_ROOT / "datasets" / "demo_emails.csv"
MODEL_PATH = PROJECT_ROOT / "reports" / "ml" / "demo_phishing_model.joblib"
REPORT_PATH = PROJECT_ROOT / "reports" / "ml" / "demo_evaluation.json"

LABELS = ["legitimate", "phishing"]



def load_dataset(path):
    """Load and validate labeled email text from a CSV file."""
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}")

    with path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        # Validate the header before processing any data rows.
        headers = reader.fieldnames
        if not headers:
            raise ValueError("CSV header is missing.")

        if len(headers) != len(set(headers)):
            raise ValueError("CSV header contains duplicate column names.")

        required_columns = {"text", "label"}
        if not required_columns.issubset(headers):
            raise ValueError("CSV must contain 'text' and 'label' columns.")

        rows = list(reader)

    if not rows:
        raise ValueError("Dataset is empty.")

    texts = []
    labels = []
    seen_texts = set()

    for row_number, row in enumerate(rows, start=2):
        text = (row.get("text") or "").strip()
        label = (row.get("label") or "").strip().lower()

        if text in seen_texts:
            raise ValueError(
                f"Duplicate email text at CSV row {row_number}."
            )
        seen_texts.add(text)

        if not text:
            raise ValueError(f"Empty text at CSV row {row_number}.")
        if label not in LABELS:
            raise ValueError(
                f"Unsupported label at CSV row {row_number}: {label!r}"
            )

        texts.append(text)
        labels.append(label)

    if set(labels) != set(LABELS):
        raise ValueError("Dataset must contain both required classes.")

    counts = {label: labels.count(label) for label in LABELS}
    if min(counts.values()) < 2:
        raise ValueError("At least two examples per class are required.")

    return texts, labels, counts


def train_and_evaluate():
    texts, labels, counts = load_dataset(DATASET_PATH)

    # Keep a held-out split. With only 12 demo samples, results will be
    # unstable and must not be interpreted as real-world performance.
    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                max_features=5000,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ])

    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    report = classification_report(
        y_test,
        predictions,
        labels=LABELS,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predictions, labels=LABELS)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    results = {
        "experiment": "small_demonstration_dataset",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": str(DATASET_PATH.relative_to(PROJECT_ROOT)),
        "sample_count": len(texts),
        "class_counts": counts,
        "train_count": len(x_train),
        "test_count": len(x_test),
        "random_state": 42,
        "labels_in_confusion_matrix_order": LABELS,
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "limitations": [
            "Only 12 hand-written demonstration examples were used.",
            "The test set contains only 3 examples.",
            "Metrics are unstable and do not represent real-world performance.",
            "Use a larger, representative, independently labeled dataset "
            "before drawing operational conclusions."
        ],
        "model_file": str(MODEL_PATH.relative_to(PROJECT_ROOT)),
    }

    REPORT_PATH.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    print("Training completed.")
    print(f"Dataset samples: {len(texts)} ({counts})")
    print(f"Training samples: {len(x_train)}")
    print(f"Test samples: {len(x_test)}")
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print("Labels:", LABELS)
    print(matrix)
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, labels=LABELS, zero_division=0
    ))
    print("Model saved to:", MODEL_PATH)
    print("Evaluation saved to:", REPORT_PATH)
    print("\nWARNING: Demonstration results only; not real-world validation.")


if __name__ == "__main__":
    train_and_evaluate()
