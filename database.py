"""
database.py - Storage layer for ScamGraph AI
Priority:
  1. Supabase / PostgreSQL -> DATABASE_URL env var
  2. SQLite (local dev / Vercel /tmp fallback)

Add DATABASE_URL in Vercel -> Settings -> Environment Variables.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

# Supabase returns "postgres://" but psycopg2 needs "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

USE_POSTGRES = bool(DATABASE_URL)

# SQLite path for local dev or Vercel /tmp
if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV"):
    SQLITE_PATH = Path("/tmp/scamgraph.db")
else:
    SQLITE_PATH = Path(__file__).resolve().parent / "scamgraph.db"


# =========================================================
# PostgreSQL helpers (Supabase)
# =========================================================

def _pg_connect():
    import psycopg2
    return psycopg2.connect(DATABASE_URL)


def _pg_init():
    conn = _pg_connect()
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id              SERIAL PRIMARY KEY,
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
    conn.close()


def _pg_save(title, source, raw_text, result):
    created_at = datetime.now(timezone.utc).isoformat()
    conn = _pg_connect()
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO reports
                  (title, source, raw_text, risk_score, risk_level,
                   indicators_json, reasons_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (
                title, source, raw_text,
                int(result.get("risk_score", 0)),
                str(result.get("risk_level", "low")),
                json.dumps(result.get("indicators", [])),
                json.dumps(result.get("reasons", [])),
                created_at,
            ))
            report_id = cur.fetchone()[0]
    conn.close()
    return report_id


def _pg_get(report_id):
    conn = _pg_connect()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM reports WHERE id = %s", (report_id,))
        cols = [d[0] for d in cur.description]
        row = cur.fetchone()
    conn.close()
    return _row_to_report(dict(zip(cols, row))) if row else None


def _pg_list(limit):
    conn = _pg_connect()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, title, source, risk_score, risk_level,
                   indicators_json, created_at
            FROM reports ORDER BY id DESC LIMIT %s
        """, (limit,))
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    conn.close()
    out = []
    for item in rows:
        item["indicators"] = json.loads(item.pop("indicators_json") or "[]")
        item["indicator_count"] = len(item["indicators"])
        out.append(item)
    return out


def _pg_all():
    conn = _pg_connect()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM reports ORDER BY id ASC")
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    conn.close()
    return [_row_to_report(r) for r in rows]


def _pg_delete(report_id):
    conn = _pg_connect()
    with conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM reports WHERE id = %s", (int(report_id),))
            deleted = cur.rowcount > 0
    conn.close()
    return deleted


# =========================================================
# SQLite helpers (local dev / Vercel)
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
            json.dumps(result.get("reasons", [])),
            created_at,
        ))
        conn.commit()
        return cur.lastrowid


def _sqlite_get(report_id):
    with _sqlite_connect() as conn:
        row = conn.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        return _row_to_report(dict(row)) if row else None


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
        item["indicators"] = json.loads(item.pop("indicators_json") or "[]")
        item["indicator_count"] = len(item["indicators"])
        out.append(item)
    return out


def _sqlite_all():
    with _sqlite_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY id ASC"
        ).fetchall()
        return [_row_to_report(dict(r)) for r in rows]


def _sqlite_delete(report_id):
    with _sqlite_connect() as conn:
        cur = conn.execute(
            "DELETE FROM reports WHERE id = ?", (int(report_id),)
        )
        conn.commit()
        return cur.rowcount > 0


# =========================================================
# Shared row conversion
# =========================================================

def _row_to_report(row):
    return {
        "id":         row["id"],
        "title":      row["title"],
        "source":     row["source"],
        "raw_text":   row["raw_text"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "indicators": json.loads(row.get("indicators_json", "[]") or "[]"),
        "reasons":    json.loads(row.get("reasons_json",    "[]") or "[]"),
        "created_at": row.get("created_at", ""),
    }


# =========================================================
# Public API (called by app.py — unchanged interface)
# =========================================================

def init_db():
    if USE_POSTGRES:
        _pg_init()
    else:
        _sqlite_init()


def save_report(title, source, raw_text, result):
    init_db()
    return _pg_save(title, source, raw_text, result) if USE_POSTGRES else _sqlite_save(title, source, raw_text, result)


def get_report(report_id):
    init_db()
    return _pg_get(report_id) if USE_POSTGRES else _sqlite_get(report_id)


def list_reports(limit=50):
    init_db()
    limit = max(1, min(int(limit), 200))
    return _pg_list(limit) if USE_POSTGRES else _sqlite_list(limit)


def get_all_reports():
    init_db()
    return _pg_all() if USE_POSTGRES else _sqlite_all()


def delete_report(report_id):
    """Delete a report by ID. Returns True if a row was deleted."""
    init_db()
    return _pg_delete(report_id) if USE_POSTGRES else _sqlite_delete(report_id)
