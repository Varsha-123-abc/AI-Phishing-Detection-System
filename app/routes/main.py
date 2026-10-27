"""Routes for the local phishing analysis dashboard."""

from flask import Blueprint, render_template, request

from core.email_analysis.email_parser import parse_email
from core.threat_scoring.risk_scorer import score_email

main_bp = Blueprint("main", __name__)


@main_bp.route("/", methods=["GET", "POST"])
def dashboard():
    result = None
    error = None
    raw_email = ""

    if request.method == "POST":
        raw_email = request.form.get("raw_email", "")

        if not raw_email.strip():
            error = "Please paste an email message before analyzing."
        else:
            try:
                parsed_email = parse_email(raw_email)
                result = score_email(parsed_email)
                severity_order = ("critical", "high", "medium", "low")
                result["severity_counts"] = {
                    severity: sum(
                        1
                        for item in result["indicators"]
                        if item.get("severity") == severity
                    )
                    for severity in severity_order
                }
                result["email_summary"] = {
                    "subject": parsed_email["headers"].get("subject") or "(No subject)",
                    "sender": parsed_email["headers"].get("from") or "(Unknown sender)",
                    "url_count": len(parsed_email.get("urls", [])),
                    "attachment_count": parsed_email.get("attachment_count", 0),
                }
            except (TypeError, ValueError) as exc:
                error = str(exc)

    return render_template(
        "dashboard.html",
        result=result,
        error=error,
        raw_email=raw_email,
    )
