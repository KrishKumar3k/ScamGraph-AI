"""
Vercel serverless entry point for ScamGraph AI.
This module re-exports the Flask app so Vercel can invoke it.
"""

import sys
from pathlib import Path

# Ensure the project root is on the Python path so that
# app.py, database.py, scamgraph.py etc. can be imported.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import app  # noqa: E402

# Vercel looks for a callable named handler or the WSGI app directly.
handler = app
