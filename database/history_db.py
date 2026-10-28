
"""SQLite persistence for phishing analysis history and investigation notes."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parent / "phishing_history.sqlite3"
)
MAX_NOTE_LENGTH = 5000


def get_connection(db_path=None):
    """Open a SQLite connection with row access and foreign keys enabled."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(db_path=None):
    """Create history and investigation-note tables if necessary."""
    with closing(get_connection(db_path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analyzed_at TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    risk_score INTEGER NOT NULL CHECK (
                        risk_score BETWEEN 0 AND 100
                    ),
                    risk_level TEXT NOT NULL,
                    indicator_count INTEGER NOT NULL,
                    url_count INTEGER NOT NULL,
                    attachment_count INTEGER NOT NULL,
                    ml_assessment_json TEXT NOT NULL,
                    indicators_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    note TEXT NOT NULL CHECK (
                        length(note) BETWEEN 1 AND 5000
                    ),
                    FOREIGN KEY (analysis_id)
                        REFERENCES analysis_history(id)
                        ON DELETE CASCADE
                )
                """
            )


def save_analysis(result, db_path=None):
    """Save analysis metadata without storing the raw email body."""
    summary = result["email_summary"]

    record = (
        datetime.now(timezone.utc).isoformat(),
        summary.get("sender") or "(Unknown sender)",
        summary.get("subject") or "(No subject)",
        int(result["risk_score"]),
        result["risk_level"],
        int(result["indicator_count"]),
        int(summary.get("url_count", 0)),
        int(summary.get("attachment_count", 0)),
        json.dumps(result.get("ml_assessment", {})),
        json.dumps(result.get("indicators", [])),
    )

    initialize_database(db_path)

    with closing(get_connection(db_path)) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO analysis_history (
                    analyzed_at, sender, subject, risk_score, risk_level,
                    indicator_count, url_count, attachment_count,
                    ml_assessment_json, indicators_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                record,
            )
            return cursor.lastrowid


def get_recent_analyses(limit=100, db_path=None):
    """Return recent saved analysis summaries."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")

    initialize_database(db_path)

    with closing(get_connection(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT id, analyzed_at, sender, subject, risk_score, risk_level,
                   indicator_count, url_count, attachment_count
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_analysis_by_id(analysis_id, db_path=None):
    """Return one saved analysis and decode its JSON fields."""
    initialize_database(db_path)

    with closing(get_connection(db_path)) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM analysis_history
            WHERE id = ?
            """,
            (analysis_id,),
        ).fetchone()

    if row is None:
        return None

    analysis = dict(row)
    analysis["ml_assessment"] = json.loads(
        analysis.pop("ml_assessment_json")
    )
    analysis["indicators"] = json.loads(
        analysis.pop("indicators_json")
    )
    return analysis


def save_investigation_note(analysis_id, note, db_path=None):
    """Save a timestamped note associated with an existing analysis."""
    if not isinstance(analysis_id, int) or isinstance(analysis_id, bool):
        raise ValueError("analysis_id must be an integer")

    if not isinstance(note, str):
        raise ValueError("Note must be text.")

    note = note.strip()

    if not note:
        raise ValueError("Investigation note cannot be empty.")

    if len(note) > MAX_NOTE_LENGTH:
        raise ValueError(
            f"Investigation note cannot exceed {MAX_NOTE_LENGTH} characters."
        )

    initialize_database(db_path)

    with closing(get_connection(db_path)) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO investigation_notes (
                    analysis_id, created_at, note
                ) VALUES (?, ?, ?)
                """,
                (
                    analysis_id,
                    datetime.now(timezone.utc).isoformat(),
                    note,
                ),
            )
            return cursor.lastrowid


def get_investigation_notes(analysis_id, db_path=None):
    """Return notes for an analysis, oldest first."""
    initialize_database(db_path)

    with closing(get_connection(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT id, analysis_id, created_at, note
            FROM investigation_notes
            WHERE analysis_id = ?
            ORDER BY id ASC
            """,
            (analysis_id,),
        ).fetchall()

    return [dict(row) for row in rows]
