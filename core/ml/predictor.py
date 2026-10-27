"""Prediction helpers for the experimental phishing email classifier."""

from functools import lru_cache
from pathlib import Path

import joblib


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "reports" / "ml" / "demo_phishing_model.joblib"
MAX_TEXT_LENGTH = 100_000
ALLOWED_LABELS = {"legitimate", "phishing"}


@lru_cache(maxsize=1)
def _load_model(model_path_string):
    """Load the locally trained model, caching it for repeated predictions."""
    model_path = Path(model_path_string)

    if not model_path.is_file():
        raise FileNotFoundError(
            "Phishing classifier model not found. "
            "Train it first with: python -m core.ml.train_model"
        )

    # Only load trusted model artifacts created by this project.
    return joblib.load(model_path)


def predict_email_text(text, model_path=None):
    """Classify email text and return class estimates and a limitation note."""
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
    model = _load_model(str(selected_path.resolve()))

    predicted_label = str(model.predict([text])[0])
    if predicted_label not in ALLOWED_LABELS:
        raise ValueError("The model returned an unsupported class label.")

    probabilities = model.predict_proba([text])[0]
    class_probabilities = {
        str(label): round(float(probability), 6)
        for label, probability in zip(model.classes_, probabilities)
    }

    return {
        "predicted_label": predicted_label,
        "class_probabilities": class_probabilities,
        "model_type": "TF-IDF + Logistic Regression",
        "is_demo_model": True,
        "limitations": (
            "Experimental model trained on 12 hand-written examples. "
            "Predictions and probabilities are not reliable real-world "
            "phishing verdicts or calibrated threat probabilities."
        ),
    }


def clear_model_cache():
    """Clear the cached model, useful after retraining or in tests."""
    _load_model.cache_clear()
