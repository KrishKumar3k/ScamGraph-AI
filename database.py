import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


import os

# On Vercel, the project directory is read-only; only /tmp is writable.
# Use /tmp for the database when running on Vercel, local path for dev.
if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV"):
    DB_PATH = Path("/tmp/scamgraph.db")
else:
    DB_PATH = Path(__file__).resolve().parent / "scamgraph.db"


def connect():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                raw_text TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()


def save_report(title, source, raw_text, result):
    init_db()
    created_at = datetime.now(timezone.utc).isoformat()

    with connect() as conn:
        cursor = conn.execute("""
            INSERT INTO reports (
                title, source, raw_text, risk_score, risk_level,
                indicators_json, reasons_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            title,
            source,
            raw_text,
            int(result.get("risk_score", 0)),
            str(result.get("risk_level", "low")),
            json.dumps(result.get("indicators", [])),
            json.dumps(result.get("reasons", [])),
            created_at,
        ))
        conn.commit()
        return cursor.lastrowid


def row_to_report(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "source": row["source"],
        "raw_text": row["raw_text"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "indicators": json.loads(row["indicators_json"] or "[]"),
        "reasons": json.loads(row["reasons_json"] or "[]"),
        "created_at": row["created_at"],
    }


def get_report(report_id):
    init_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM reports WHERE id = ?",
            (report_id,)
        ).fetchone()
        return row_to_report(row) if row else None


def list_reports(limit=50):
    init_db()
    limit = max(1, min(int(limit), 200))

    with connect() as conn:
        rows = conn.execute("""
            SELECT id, title, source, risk_score, risk_level,
                   indicators_json, created_at
            FROM reports
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    reports = []
    for row in rows:
        item = dict(row)
        item["indicators"] = json.loads(
            item.pop("indicators_json") or "[]"
        )
        item["indicator_count"] = len(item["indicators"])
        reports.append(item)
    return reports


def get_all_reports():
    init_db()
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY id ASC"
        ).fetchall()
        return [row_to_report(row) for row in rows]