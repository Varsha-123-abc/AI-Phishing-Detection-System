"""Train and evaluate a phishing classifier on the prepared public dataset.

Experimental baseline only. Existing demo artifacts remain separate.
"""
from contextlib import closing
import csv
import hashlib
import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = PROJECT_ROOT / "datasets" / "processed" / "balanced_emails.csv"
MODEL_PATH = PROJECT_ROOT / "reports" / "ml" / "balanced_phishing_model.joblib"
REPORT_PATH = PROJECT_ROOT / "reports" / "ml" / "balanced_evaluation.json"

LABELS = ["legitimate", "phishing"]
RANDOM_STATE = 42
TEST_SIZE = 0.20
MAX_FEATURES = 30_000


def load_dataset(path):
    """Validate the CSV, checking duplicate text through temporary SQLite."""
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}")

    texts = []
    labels = []
    counts = {label: 0 for label in LABELS}

    # SQLite keeps the duplicate index on disk instead of retaining a large
    # Python set of every email body. The temporary database is auto-deleted.
    with tempfile.TemporaryDirectory(prefix="phishing-dataset-check-") as temp:
        db_path = Path(temp) / "duplicates.sqlite3"

        with closing(sqlite3.connect(db_path)) as connection:
            with connection:
                connection.execute("PRAGMA temp_store = FILE")
            connection.execute("PRAGMA cache_size = -8192")
            connection.execute(
                "CREATE TABLE email_hashes (digest TEXT PRIMARY KEY)"
            )

            with path.open("r", newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)

                if not reader.fieldnames:
                    raise ValueError("CSV header is missing.")
                if len(reader.fieldnames) != len(set(reader.fieldnames)):
                    raise ValueError("CSV header contains duplicate columns.")
                if not {"text", "label"}.issubset(reader.fieldnames):
                    raise ValueError(
                        "CSV must contain 'text' and 'label' columns."
                    )

                for row_number, row in enumerate(reader, start=2):
                    text = (row.get("text") or "").strip()
                    label = (row.get("label") or "").strip().lower()

                    if not text:
                        raise ValueError(
                            f"Empty text at CSV row {row_number}."
                        )
                    if label not in LABELS:
                        raise ValueError(
                            f"Unsupported label at CSV row {row_number}: "
                            f"{label!r}"
                        )

                    digest = hashlib.sha256(
                        text.encode("utf-8")
                    ).hexdigest()

                    try:
                        connection.execute(
                            "INSERT INTO email_hashes (digest) VALUES (?)",
                            (digest,),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise ValueError(
                            f"Duplicate email text at CSV row {row_number}."
                        ) from exc

                    texts.append(text)
                    labels.append(label)
                    counts[label] += 1

    if not texts:
        raise ValueError("Dataset is empty.")
    if any(counts[label] == 0 for label in LABELS):
        raise ValueError("Dataset must contain both required classes.")
    if min(counts.values()) < 2:
        raise ValueError("At least two examples per class are required.")

    return texts, labels, counts


def sha256_file(path):
    """Calculate the dataset file's SHA-256 digest."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train_and_evaluate():
    texts, labels, counts = load_dataset(DATASET_PATH)

    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                max_features=MAX_FEATURES,
                min_df=2,
                sublinear_tf=True,
                dtype=np.float32,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                solver="liblinear",
                max_iter=300,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            ),
        ),
    ])

    print("Training on the prepared dataset.")
    print(f"Total samples: {len(texts):,}")
    print(f"Training samples: {len(x_train):,}")
    print(f"Test samples: {len(x_test):,}")
    print(f"Class counts: {counts}")
    print("Training may take several minutes.")

    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    matrix = confusion_matrix(y_test, predictions, labels=LABELS)
    class_report = classification_report(
        y_test,
        predictions,
        labels=LABELS,
        output_dict=True,
        zero_division=0,
    )

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Save atomically to the new model path only.
    model_temp = MODEL_PATH.with_suffix(".joblib.tmp")
    try:
        joblib.dump(model, model_temp, compress=3)
        model_temp.replace(MODEL_PATH)
    finally:
        if model_temp.exists():
            model_temp.unlink()

    results = {
        "experiment": "prepared_public_dataset_baseline",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": str(DATASET_PATH.relative_to(PROJECT_ROOT)),
        "dataset_sha256": sha256_file(DATASET_PATH),
        "sample_count": len(texts),
        "class_counts": counts,
        "train_count": len(x_train),
        "test_count": len(x_test),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "model": "TF-IDF + Logistic Regression",
        "feature_configuration": {
            "lowercase": True,
            "strip_accents": "unicode",
            "ngram_range": [1, 2],
            "max_features": MAX_FEATURES,
            "min_df": 2,
            "sublinear_tf": True,
            "dtype": "float32",
        },
        "classifier_configuration": {
            "solver": "liblinear",
            "max_iter": 300,
            "class_weight": "balanced",
        },
        "accuracy": float(accuracy_score(y_test, predictions)),
        "labels_in_confusion_matrix_order": LABELS,
        "confusion_matrix": matrix.tolist(),
        "classification_report": class_report,
        "limitations": [
            "Experimental baseline; not a production-ready detector.",
            "The random split may place related emails in both train and test.",
            "Near-duplicate or source/campaign leakage may inflate metrics.",
            "The merged public dataset may contain labeling errors and bias.",
            "Time-based and campaign/source-separated evaluation is needed.",
            "Predictions are investigation indicators, not definitive proof.",
        ],
        "model_file": str(MODEL_PATH.relative_to(PROJECT_ROOT)),
    }

    report_temp = REPORT_PATH.with_suffix(".json.tmp")
    try:
        report_temp.write_text(
            json.dumps(results, indent=2),
            encoding="utf-8",
        )
        report_temp.replace(REPORT_PATH)
    finally:
        if report_temp.exists():
            report_temp.unlink()

    print("\nTraining completed.")
    print(f"Accuracy: {results['accuracy']:.4f}")
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print("Labels:", LABELS)
    print(matrix)
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, labels=LABELS, zero_division=0
    ))
    print(f"Model saved: {MODEL_PATH}")
    print(f"Evaluation saved: {REPORT_PATH}")
    print("WARNING: Results do not establish real-world performance.")


if __name__ == "__main__":
    train_and_evaluate()
