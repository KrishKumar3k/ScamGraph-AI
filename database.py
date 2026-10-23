"""
database.py - Storage layer for ScamGraph AI
─────────────────────────────────────────────
Priority:
  1. Supabase REST SDK  ->  SUPABASE_URL + SUPABASE_KEY env vars
  2. SQLite             ->  local dev / Vercel /tmp fallback

How to get your Supabase credentials:
  Supabase dashboard -> Project Settings -> API
    Project URL  -> SUPABASE_URL
    anon/public  -> SUPABASE_KEY
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# ── Supabase credentials ────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "").strip()
USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)

# ── SQLite path (fallback) ──────────────────────────────
if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV"):
    SQLITE_PATH = Path("/tmp/scamgraph.db")
else:
    SQLITE_PATH = Path(__file__).resolve().parent / "scamgraph.db"

TABLE = "reports"


# =========================================================
# Supabase SDK helpers
# =========================================================

_supabase_client = None

def _sb():
    """Return a cached Supabase client."""
    global _supabase_client
    if _supabase_client is None:
        from supabase import create_client
        _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _supabase_client


def _sb_init():
    """
    Supabase manages its own schema via the dashboard or migrations.
    Create the table manually once in Supabase SQL Editor:

        CREATE TABLE IF NOT EXISTS reports (
            id              BIGSERIAL PRIMARY KEY,
            title           TEXT NOT NULL,
            source          TEXT NOT NULL,
            raw_text        TEXT NOT NULL,
            risk_score      INTEGER NOT NULL,
            risk_level      TEXT NOT NULL,
            indicators_json TEXT NOT NULL DEFAULT ''[]'',
            reasons_json    TEXT NOT NULL DEFAULT ''[]'',
            created_at      TEXT NOT NULL
        );

    No action needed here at runtime.
    """
    pass


def _sb_save(title, source, raw_text, result):
    created_at = datetime.now(timezone.utc).isoformat()
    row = {
        "title":           title,
        "source":          source,
        "raw_text":        raw_text,
        "risk_score":      int(result.get("risk_score", 0)),
        "risk_level":      str(result.get("risk_level", "low")),
        "indicators_json": json.dumps(result.get("indicators", [])),
        "reasons_json":    json.dumps(result.get("reasons",    [])),
        "created_at":      created_at,
    }
    response = _sb().table(TABLE).insert(row).execute()
    return response.data[0]["id"]


def _sb_get(report_id):
    response = (
        _sb().table(TABLE)
        .select("*")
        .eq("id", report_id)
        .single()
        .execute()
    )
    return _sb_row_to_report(response.data) if response.data else None


def _sb_list(limit):
    response = (
        _sb().table(TABLE)
        .select("id, title, source, risk_score, risk_level, indicators_json, created_at")
        .order("id", desc=True)
        .limit(limit)
        .execute()
    )
    out = []
    for item in (response.data or []):
        item = dict(item)
        item["indicators"] = json.loads(item.pop("indicators_json", "[]") or "[]")
        item["indicator_count"] = len(item["indicators"])
        out.append(item)
    return out


def _sb_all():
    response = (
        _sb().table(TABLE)
        .select("*")
        .order("id")
        .execute()
    )
    return [_sb_row_to_report(r) for r in (response.data or [])]


def _sb_delete(report_id):
    response = (
        _sb().table(TABLE)
        .delete()
        .eq("id", report_id)
        .execute()
    )
    return len(response.data or []) > 0


def _sb_row_to_report(row):
    return {
        "id":         row["id"],
        "title":      row["title"],
        "source":     row["source"],
        "raw_text":   row.get("raw_text", ""),
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "indicators": json.loads(row.get("indicators_json", "[]") or "[]"),
        "reasons":    json.loads(row.get("reasons_json",    "[]") or "[]"),
        "created_at": row.get("created_at", ""),
    }


# =========================================================
# SQLite helpers (local dev / Vercel /tmp)
# =========================================================

def _sqlite_connect():
    conn = sqlite3.connect(str(SQLITE_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _sqlite_init():
    with _sqlite_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT NOT NULL,
                source          TEXT NOT NULL,
                raw_text        TEXT NOT NULL,
                risk_score      INTEGER NOT NULL,
                risk_level      TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                reasons_json    TEXT NOT NULL,
                created_at      TEXT NOT NULL
            )
        """)
        conn.commit()


def _sqlite_save(title, source, raw_text, result):
    created_at = datetime.now(timezone.utc).isoformat()
    with _sqlite_connect() as conn:
        cur = conn.execute("""
            INSERT INTO reports
              (title, source, raw_text, risk_score, risk_level,
               indicators_json, reasons_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            title, source, raw_text,
            int(result.get("risk_score", 0)),
            str(result.get("risk_level", "low")),
            json.dumps(result.get("indicators", [])),
            json.dumps(result.get("reasons",    [])),
            created_at,
        ))
        conn.commit()
        return cur.lastrowid


def _sqlite_get(report_id):
    with _sqlite_connect() as conn:
        row = conn.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        return _sqlite_row_to_report(dict(row)) if row else None


def _sqlite_list(limit):
    with _sqlite_connect() as conn:
        rows = conn.execute("""
            SELECT id, title, source, risk_score, risk_level,
                   indicators_json, created_at
            FROM reports ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["indicators"] = json.loads(item.pop("indicators_json", "[]") or "[]")
        item["indicator_count"] = len(item["indicators"])
        out.append(item)
    return out


def _sqlite_all():
    with _sqlite_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY id ASC"
        ).fetchall()
        return [_sqlite_row_to_report(dict(r)) for r in rows]


def _sqlite_delete(report_id):
    with _sqlite_connect() as conn:
        cur = conn.execute(
            "DELETE FROM reports WHERE id = ?", (int(report_id),)
        )
        conn.commit()
        return cur.rowcount > 0


def _sqlite_row_to_report(row):
    return {
        "id":         row["id"],
        "title":      row["title"],
        "source":     row["source"],
        "raw_text":   row.get("raw_text", ""),
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "indicators": json.loads(row.get("indicators_json", "[]") or "[]"),
        "reasons":    json.loads(row.get("reasons_json",    "[]") or "[]"),
        "created_at": row.get("created_at", ""),
    }


# =========================================================
# Public API  (app.py calls these — interface unchanged)
# =========================================================

def init_db():
    if USE_SUPABASE:
        _sb_init()
    else:
        _sqlite_init()


def save_report(title, source, raw_text, result):
    init_db()
    if USE_SUPABASE:
        return _sb_save(title, source, raw_text, result)
    return _sqlite_save(title, source, raw_text, result)


def get_report(report_id):
    init_db()
    if USE_SUPABASE:
        return _sb_get(report_id)
    return _sqlite_get(report_id)


def list_reports(limit=50):
    init_db()
    limit = max(1, min(int(limit), 200))
    if USE_SUPABASE:
        return _sb_list(limit)
    return _sqlite_list(limit)


def get_all_reports():
    init_db()
    if USE_SUPABASE:
        return _sb_all()
    return _sqlite_all()


def delete_report(report_id):
    """Delete a report by ID. Returns True if a row was deleted."""
    init_db()
    if USE_SUPABASE:
        return _sb_delete(report_id)
    return _sqlite_delete(report_id)
