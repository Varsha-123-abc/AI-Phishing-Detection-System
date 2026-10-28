
"""Routes for the local phishing analysis dashboard."""
import json
from xml.sax.saxutils import escape

from flask import send_file
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Preformatted,
)
import csv
import io

from flask import Response
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from core.email_analysis.email_parser import parse_email
from core.threat_scoring.risk_scorer import score_email
from database.history_db import (
    get_analysis_by_id,
    get_investigation_notes,
    get_recent_analyses,
    save_analysis,
    save_investigation_note,
)

main_bp = Blueprint("main", __name__)


def history_db_path():
    """Return the configured database path, if one was supplied."""
    return current_app.config.get("HISTORY_DB_PATH")


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
                    "subject": (
                        parsed_email["headers"].get("subject")
                        or "(No subject)"
                    ),
                    "sender": (
                        parsed_email["headers"].get("from")
                        or "(Unknown sender)"
                    ),
                    "url_count": len(parsed_email.get("urls", [])),
                    "attachment_count": parsed_email.get(
                        "attachment_count", 0
                    ),
                }

                save_analysis(result, db_path=history_db_path())

            except (TypeError, ValueError) as exc:
                error = str(exc)

    return render_template(
        "dashboard.html",
        result=result,
        error=error,
        raw_email=raw_email,
    )


@main_bp.route("/history", methods=["GET"])
def analysis_history():
    analyses = get_recent_analyses(db_path=history_db_path())
    return render_template("history.html", analyses=analyses)

@main_bp.route("/history/export.csv", methods=["GET"])
def export_history_csv():
    """Download recent analysis summaries as a spreadsheet-safe CSV."""
    analyses = get_recent_analyses(db_path=history_db_path())

    output = io.StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow([
        "Analysis ID",
        "Analyzed At (UTC)",
        "Sender",
        "Subject",
        "Risk Score",
        "Risk Level",
        "Indicator Count",
        "URL Count",
        "Attachment Count",
    ])

    def safe_csv_value(value):
        """Reduce spreadsheet formula-injection risk for untrusted text."""
        text_value = str(value if value is not None else "")
        if text_value.lstrip(" \t\r\n").startswith(
            ("=", "+", "-", "@")
        ):
            return "'" + text_value
        return text_value

    for item in analyses:
        writer.writerow([
            item["id"],
            safe_csv_value(item["analyzed_at"]),
            safe_csv_value(item["sender"]),
            safe_csv_value(item["subject"]),
            item["risk_score"],
            safe_csv_value(item["risk_level"]),
            item["indicator_count"],
            item["url_count"],
            item["attachment_count"],
        ])

    response = Response(
        output.getvalue(),
        content_type="text/csv; charset=utf-8",
    )
    response.headers["Content-Disposition"] = (
        'attachment; filename="phishguard-analysis-history.csv"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
@main_bp.route(
    "/history/<int:analysis_id>/export.pdf",
    methods=["GET"],
)
def export_analysis_pdf(analysis_id):
    """Download a saved analysis and its investigation notes as PDF."""
    analysis = get_analysis_by_id(
        analysis_id,
        db_path=history_db_path(),
    )

    if analysis is None:
        abort(404)

    notes = get_investigation_notes(
        analysis_id,
        db_path=history_db_path(),
    )

    pdf_buffer = io.BytesIO()
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        spaceAfter=12,
    )
    section_style = styles["Heading2"]
    body_style = styles["BodyText"]
    small_style = ParagraphStyle(
        "SmallReportText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    )
    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Code"],
        fontSize=7,
        leading=9,
        leftIndent=4,
        rightIndent=4,
        wordWrap="CJK",
    )

    def safe_text(value):
        """Escape untrusted text before using ReportLab paragraph markup."""
        return escape(str(value if value is not None else ""))

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"PhishGuard Analysis {analysis_id}",
        author="PhishGuard",
    )

    story = [
        Paragraph("PhishGuard Analysis Report", title_style),
        Paragraph(
            f"Analysis ID: {analysis_id}",
            body_style,
        ),
        Paragraph(
            f"Analyzed at (UTC): {safe_text(analysis.get('analyzed_at'))}",
            body_style,
        ),
        Spacer(1, 8),
        Paragraph("Analysis Summary", section_style),
    ]

    summary_rows = [
        ["Field", "Recorded Value"],
        ["Sender", safe_text(analysis.get("sender"))],
        ["Subject", safe_text(analysis.get("subject"))],
        [
            "Heuristic Risk Score",
            f"{analysis.get('risk_score', 0)}/100",
        ],
        ["Risk Level", safe_text(analysis.get("risk_level"))],
        ["Indicator Count", str(analysis.get("indicator_count", 0))],
        ["URLs Found", str(analysis.get("url_count", 0))],
        [
            "Attachments Reported",
            str(analysis.get("attachment_count", 0)),
        ],
    ]

    summary_table = Table(
        summary_rows,
        colWidths=[48 * mm, 112 * mm],
        repeatRows=1,
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243447")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([summary_table, Spacer(1, 12)])

    story.append(Paragraph("ML Assessment Snapshot", section_style))
    ml_assessment = analysis.get("ml_assessment") or {}
    ml_json = json.dumps(
        ml_assessment,
        indent=2,
        ensure_ascii=True,
        default=str,
    )
    story.append(
        Preformatted(
            escape(ml_json),
            code_style,
            maxLineLength=95,
        )
    )
    story.append(Spacer(1, 10))

    story.append(Paragraph("Evidence and Indicators", section_style))
    indicators = analysis.get("indicators") or []

    if indicators:
        for index, indicator in enumerate(indicators, start=1):
            indicator_json = json.dumps(
                indicator,
                indent=2,
                ensure_ascii=True,
                default=str,
            )
            story.append(
                Paragraph(f"Indicator {index}", styles["Heading3"])
            )
            story.append(
                Preformatted(
                    escape(indicator_json),
                    code_style,
                    maxLineLength=95,
                )
            )
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph(
            "No indicators were recorded for this analysis.",
            body_style,
        ))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Investigation Notes", section_style))

    if notes:
        for note in notes:
            story.append(Paragraph(
                f"Note #{note.get('id')} — "
                f"{safe_text(note.get('created_at'))} (UTC)",
                styles["Heading3"],
            ))
            note_text = safe_text(note.get("note")).replace(
                "\n", "<br/>"
            )
            story.append(Paragraph(note_text, body_style))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph(
            "No investigation notes have been added.",
            body_style,
        ))

    story.extend([
        Spacer(1, 12),
        Paragraph("Important Disclaimer", section_style),
        Paragraph(
            "Findings, heuristic scores, and model predictions are "
            "investigation indicators, not definitive proof of phishing. "
            "Verify the supporting evidence before taking action. "
            "The original email body is not stored in analysis history "
            "and is not included in this report.",
            body_style,
        ),
    ])

    document.build(story)
    pdf_buffer.seek(0)

    response = send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"phishguard-analysis-{analysis_id}.pdf",
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@main_bp.route("/history/<int:analysis_id>", methods=["GET"])
def analysis_detail(analysis_id):
    analysis = get_analysis_by_id(
        analysis_id,
        db_path=history_db_path(),
    )

    if analysis is None:
        abort(404)

    notes = get_investigation_notes(
        analysis_id,
        db_path=history_db_path(),
    )

    return render_template(
        "history_detail.html",
        analysis=analysis,
        notes=notes,
    )


@main_bp.route(
    "/history/<int:analysis_id>/notes",
    methods=["POST"],
)
def add_investigation_note(analysis_id):
    analysis = get_analysis_by_id(
        analysis_id,
        db_path=history_db_path(),
    )

    if analysis is None:
        abort(404)

    note = request.form.get("note", "")

    try:
        save_investigation_note(
            analysis_id,
            note,
            db_path=history_db_path(),
        )
        flash("Investigation note saved.", "success")
    except ValueError as exc:
        flash(str(exc), "error")

    return redirect(
        url_for("main.analysis_detail", analysis_id=analysis_id)
    )
