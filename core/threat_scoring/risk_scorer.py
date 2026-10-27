"""Transparent heuristic scoring with a separate experimental ML assessment."""

from core.email_analysis.indicator_extractor import extract_indicators
from core.ml.predictor import predict_email_text

SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 40,
}


def risk_level_from_score(score: int) -> str:
    """Map a score from 0 to 100 to a risk label."""
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")

    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def _get_ml_assessment(parsed_email: dict, enabled: bool) -> dict:
    """Return ML metadata separately from the evidence-based risk score."""
    if not enabled:
        return {
            "status": "disabled",
            "note": "Experimental ML assessment was not requested.",
        }

    headers = parsed_email.get("headers", {})
    subject = (headers.get("subject") or "").strip()
    body = (parsed_email.get("body") or "").strip()

    if not subject and not body:
        return {
            "status": "unavailable",
            "note": "No subject or body text was available for ML analysis.",
        }

    text = f"Subject: {subject}\n\n{body}".strip()

    try:
        prediction = predict_email_text(text)
    except (FileNotFoundError, ValueError) as exc:
        return {
            "status": "unavailable",
            "note": str(exc),
        }

    return {
        "status": "available",
        "predicted_label": prediction["predicted_label"],
        "class_probabilities": prediction["class_probabilities"],
        "model_type": prediction["model_type"],
        "is_demo_model": prediction["is_demo_model"],
        "limitations": prediction["limitations"],
        "note": (
            "Experimental ML output only. It does not change the heuristic "
            "risk score and is not proof that an email is malicious or safe."
        ),
    }


def score_email(parsed_email: dict, include_ml: bool = True) -> dict:
    """Calculate an explainable heuristic score and a separate ML assessment.

    The heuristic score is for triage, not a probability or proof of
    maliciousness. Experimental ML output never changes this score.
    """
    indicators = extract_indicators(parsed_email)

    raw_score = sum(
        item.get(
            "weight",
            SEVERITY_WEIGHTS.get(item.get("severity", "low"), 5),
        )
        for item in indicators
    )
    score = min(100, raw_score)

    return {
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "indicators": indicators,
        "indicator_count": len(indicators),
        "ml_assessment": _get_ml_assessment(parsed_email, include_ml),
        "note": (
            "Heuristic triage score, not a probability or definitive verdict. "
            "Experimental ML output is reported separately and does not "
            "change the score. Authentication headers are not independently "
            "verified, and URLs are analyzed without network requests."
        ),
    }
