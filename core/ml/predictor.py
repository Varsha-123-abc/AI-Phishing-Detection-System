"""Prediction helpers for the experimental phishing email classifiers."""

from functools import lru_cache
from pathlib import Path

import joblib


PROJECT_ROOT = Path(__file__).resolve().parents[2]

# The prepared public-dataset model is the default classifier.
MODEL_PATH = (
    PROJECT_ROOT
    / "reports"
    / "ml"
    / "balanced_phishing_model.joblib"
)

# Keep the original demonstration model available for explicit testing.
DEMO_MODEL_PATH = (
    PROJECT_ROOT
    / "reports"
    / "ml"
    / "demo_phishing_model.joblib"
)

MAX_TEXT_LENGTH = 100_000
ALLOWED_LABELS = {"legitimate", "phishing"}

BASELINE_LIMITATIONS = (
    "Experimental baseline trained on a merged public email dataset. "
    "Evaluation used a random holdout split, which may contain related "
    "emails or source/campaign leakage. Performance on unseen sources "
    "has not been established. Class probabilities are not calibrated "
    "threat probabilities. Treat predictions as investigation indicators, "
    "not definitive proof that an email is safe or malicious."
)

DEMO_LIMITATIONS = (
    "Demonstration model trained on 12 hand-written examples. "
    "Predictions and class estimates are not reliable real-world "
    "phishing verdicts or calibrated threat probabilities."
)


@lru_cache(maxsize=2)
def _load_model(model_path_string):
    """Load a trusted local model and cache it for repeated predictions."""
    model_path = Path(model_path_string)

    if not model_path.is_file():
        raise FileNotFoundError(
            "Phishing classifier model not found. Train it first with: "
            "python -m core.ml.train_large_model"
        )

    # Only load trusted model artifacts created by this project.
    return joblib.load(model_path)


def predict_email_text(text, model_path=None):
    """Classify email text and return labels, estimates, and limitations."""
    if not isinstance(text, str):
        raise TypeError("Email text must be a string.")

    text = text.strip()

    if not text:
        raise ValueError("Email text must not be empty.")

    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(
            f"Email text exceeds the {MAX_TEXT_LENGTH}-character limit."
        )

    selected_path = Path(model_path) if model_path else MODEL_PATH
    selected_path = selected_path.resolve()
    model = _load_model(str(selected_path))

    predicted_label = str(model.predict([text])[0])
    if predicted_label not in ALLOWED_LABELS:
        raise ValueError("The model returned an unsupported class label.")

    probabilities = model.predict_proba([text])[0]
    class_probabilities = {
        str(label): round(float(probability), 6)
        for label, probability in zip(model.classes_, probabilities)
    }

    if set(class_probabilities) != ALLOWED_LABELS:
        raise ValueError("The model does not contain the required classes.")

    if not all(
        0.0 <= probability <= 1.0
        for probability in class_probabilities.values()
    ):
        raise ValueError("The model returned invalid class estimates.")

    if abs(sum(class_probabilities.values()) - 1.0) > 1e-4:
        raise ValueError("The model returned estimates that do not sum to 1.")

    is_demo_model = selected_path == DEMO_MODEL_PATH.resolve()

    return {
        "predicted_label": predicted_label,
        "class_probabilities": class_probabilities,
        "model_type": "TF-IDF + Logistic Regression",
        "is_demo_model": is_demo_model,
        "limitations": (
            DEMO_LIMITATIONS if is_demo_model else BASELINE_LIMITATIONS
        ),
    }


def clear_model_cache():
    """Clear cached models, useful after retraining or during tests."""
    _load_model.cache_clear()
