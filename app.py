
import logging
import os
import re
from io import BytesIO
from pathlib import Path

import pytesseract
from PIL import Image, ImageOps, UnidentifiedImageError
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from database import (
    init_db,
    save_report,
    get_report,
    list_reports,
    get_all_reports,
)
from scamgraph import (
    analyze_text,
    build_connections,
    make_investigation_summary,
)

# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_TEXT_LENGTH = 20_000
MAX_TITLE_LENGTH = 160
MAX_SOURCE_LENGTH = 50
MAX_IMAGE_PIXELS = 20_000_000

ALLOWED_IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp",
    ".bmp", ".tif", ".tiff"
}

# Tesseract executable path on Windows.
# Change this only if Tesseract was installed elsewhere.
TESSERACT_EXE = Path(
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

if TESSERACT_EXE.exists():
    pytesseract.pytesseract.tesseract_cmd = str(TESSERACT_EXE)


# =========================================================
# COMMON HELPERS
# =========================================================

def error_response(message, status=400):
    return jsonify({
        "ok": False,
        "error": message,
    }), status


def clean_string(value, default, max_length):
    if not isinstance(value, str):
        return default

    value = re.sub(r"\s+", " ", value.strip())

    if not value:
        return default

    return value[:max_length]


def normalize_indicator(indicator):
    """Return a normalized (type, value) indicator pair."""
    if not isinstance(indicator, dict):
        return None

    kind = str(indicator.get("type", "")).strip().lower()
    value = str(indicator.get("value", "")).strip().lower()

    if not kind or not value:
        return None

    return kind, value


def report_title(report):
    """Give every graph node a readable title."""
    title = report.get("title")

    if isinstance(title, str) and title.strip():
        return title.strip()

    return f"Investigation #{report.get('id', '?')}"


# =========================================================
# GRAPH BUILDER
# =========================================================

def make_graph(reports):
    """
    Include every saved report as a graph node.

    Create an edge only when two different reports share an
    exact indicator with the same type. Isolated reports stay
    in the graph and are not treated as safe automatically.
    """

    nodes = []
    edges = []
    indicator_map = {}

    for report in reports:
        report_id = str(report["id"])
        indicators = report.get("indicators") or []

        nodes.append({
            "id": report_id,
            "label": report_title(report),
            "source": report.get("source", "Unknown"),
            "risk_score": report.get("risk_score", 0),
            "risk_level": report.get("risk_level", "unknown"),
            "indicator_count": len(indicators),
            "connected": False,
            "connection_count": 0,
            "created_at": report.get("created_at", ""),
        })

        for indicator in indicators:
            normalized = normalize_indicator(indicator)

            if normalized:
                indicator_map.setdefault(
                    normalized, set()
                ).add(report_id)

    # Group exact matches between report pairs.
    pair_matches = {}

    for (kind, value), report_ids in indicator_map.items():
        ids = sorted(report_ids, key=lambda item: int(item))

        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                pair = (ids[i], ids[j])

                pair_matches.setdefault(pair, []).append({
                    "type": kind,
                    "value": value,
                })

    for (left, right), shared in pair_matches.items():
        edges.append({
            "source": left,
            "target": right,
            "shared_indicators": shared,
            "weight": len(shared),
            "explanation": (
                f"Reports #{left} and #{right} share "
                f"{len(shared)} exact indicator match(es)."
            ),
        })

    # Preserve isolated nodes and calculate node degrees.
    degree = {node["id"]: 0 for node in nodes}

    for edge in edges:
        degree[edge["source"]] += 1
        degree[edge["target"]] += 1

    for node in nodes:
        node["connection_count"] = degree[node["id"]]
        node["connected"] = degree[node["id"]] > 0

    return {
        "ok": True,
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "isolated_nodes": sum(
            1 for node in nodes if not node["connected"]
        ),
    }


# =========================================================
# HOME PAGE
# =========================================================

@app.get("/")
def home():
    return render_template("index.html")


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/api/health")
def health():
    try:
        init_db()

        try:
            pytesseract.get_tesseract_version()
            ocr_available = True
        except Exception:
            ocr_available = False

        return jsonify({
            "ok": True,
            "service": "ScamGraph AI",
            "analysis_engine": "transparent_rule_based_demo",
            "database": "ready",
            "ocr_available": ocr_available,
        })

    except Exception:
        logger.exception("Health check failed")

        return error_response(
            "Backend health check failed. Check the terminal.",
            500,
        )


# =========================================================
# OCR IMAGE ENDPOINT
# =========================================================

@app.post("/api/ocr")
def ocr_image():
    upload = request.files.get("image")

    if upload is None or not upload.filename:
        return error_response(
            "Choose a screenshot image before extracting text."
        )

    extension = Path(upload.filename).suffix.lower()

    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return error_response(
            "Unsupported image. Use PNG, JPG, JPEG, WEBP, BMP or TIFF."
        )

    try:
        raw_bytes = upload.read(
            app.config["MAX_CONTENT_LENGTH"] + 1
        )

        if not raw_bytes:
            return error_response("The selected image is empty.")

        if len(raw_bytes) > app.config["MAX_CONTENT_LENGTH"]:
            return error_response(
                "Image exceeds the 5 MB upload limit.",
                413,
            )

        # Verify the image content.
        with Image.open(BytesIO(raw_bytes)) as original:
            if original.width * original.height > MAX_IMAGE_PIXELS:
                return error_response(
                    "Image dimensions are too large. Use a smaller screenshot."
                )

            original.verify()

        # Prepare the image for OCR.
        with Image.open(BytesIO(raw_bytes)) as original:
            image = ImageOps.exif_transpose(original)
            image = image.convert("RGB")
            image = ImageOps.grayscale(image)
            image = ImageOps.autocontrast(image)

            extracted_text = pytesseract.image_to_string(
                image,
                lang="eng",
                config="--psm 6",
            ).strip()

        extracted_text = re.sub(
            r"\n{3,}",
            "\n\n",
            extracted_text,
        )

        extracted_text = extracted_text[:MAX_TEXT_LENGTH]

        if len(extracted_text) < 5:
            return jsonify({
                "ok": True,
                "text": extracted_text,
                "message": (
                    "Very little text was detected. Try a clearer "
                    "screenshot with the entire message visible."
                ),
            })

        return jsonify({
            "ok": True,
            "text": extracted_text,
            "message": (
                "Text extracted. Review it and correct OCR mistakes "
                "before running the analysis."
            ),
        })

    except pytesseract.TesseractNotFoundError:
        logger.exception("Tesseract executable not found")

        return error_response(
            "Tesseract was not found. Check its installation path "
            "and restart Flask.",
            500,
        )

    except UnidentifiedImageError:
        return error_response(
            "The selected file is not a readable image."
        )

    except Exception:
        logger.exception("OCR failed")

        return error_response(
            "OCR failed. Check Tesseract and the terminal for details.",
            500,
        )


# =========================================================
# ANALYZE MESSAGE AND SAVE REPORT
# =========================================================

@app.post("/api/analyze")
def analyze():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return error_response(
            "Expected JSON containing title, source and text."
        )

    text = payload.get("text", "")

    if not isinstance(text, str):
        return error_response("Message text must be a string.")

    text = text.strip()

    if len(text) < 5:
        return error_response(
            "Enter at least 5 characters to analyze."
        )

    if len(text) > MAX_TEXT_LENGTH:
        return error_response(
            "Maximum message length is 20,000 characters.",
            413,
        )

    title = clean_string(
        payload.get("title"),
        "Untitled investigation",
        MAX_TITLE_LENGTH,
    )

    source = clean_string(
        payload.get("source"),
        "Manual entry",
        MAX_SOURCE_LENGTH,
    )

    try:
        # Existing rule-based analysis engine.
        result = analyze_text(text)

        if not isinstance(result, dict):
            raise ValueError(
                "The analysis engine returned an unexpected result."
            )

        # Save the report using the submitted title.
        report_id = save_report(
            title,
            source,
            text,
            result,
        )

        # Load saved reports and find related investigations.
        all_reports = get_all_reports()

        connections = build_connections(
            report_id,
            result.get("indicators", []),
            all_reports,
        )

        summary = make_investigation_summary(
            result,
            connections,
        )

        risk_level = str(
            result.get("risk_level", "unknown")
        ).capitalize()

        risk_score = result.get("risk_score", 0)

        if connections:
            shared_count = sum(
                len(connection.get("shared_indicators", []))
                for connection in connections
            )

            reply = (
                f"Investigation #{report_id}: {title}. "
                f"Rule-based triage: {risk_level} "
                f"({risk_score}/100). "
                f"Found {len(connections)} related report(s) "
                f"with {shared_count} shared indicator match(es). "
                "Review the evidence before drawing conclusions."
            )
        else:
            reply = (
                f"Investigation #{report_id}: {title}. "
                f"Rule-based triage: {risk_level} "
                f"({risk_score}/100). "
                "No shared indicators were found in the saved reports. "
                "This report remains visible as an isolated graph node. "
                "No connection does not mean the message is safe."
            )

        return jsonify({
            "ok": True,
            "report_id": report_id,
            "title": title,
            "source": source,
            "analysis": result,
            "connections": connections,
            "summary": summary,
            "reply": reply,
            "notice": (
                "This is rule-based triage, not proof of fraud "
                "or a calibrated probability. Shared indicators are "
                "investigative leads, not proof of common ownership."
            ),
        }), 201

    except ValueError as exc:
        return error_response(str(exc))

    except Exception:
        logger.exception("Analysis failed")

        return error_response(
            "Analysis failed. Check the VS Code terminal for details.",
            500,
        )


# =========================================================
# REPORT HISTORY
# =========================================================

@app.get("/api/reports")
def reports():
    try:
        try:
            limit = int(request.args.get("limit", 50))
        except (ValueError, TypeError):
            limit = 50

        limit = max(1, min(limit, 200))

        return jsonify({
            "ok": True,
            "reports": list_reports(limit),
        })

    except Exception:
        logger.exception("Could not load reports")

        return error_response(
            "Could not load investigation reports.",
            500,
        )


# =========================================================
# INDIVIDUAL REPORT DETAILS
# =========================================================

@app.get("/api/reports/<int:report_id>")
def report_detail(report_id):
    try:
        report = get_report(report_id)

        if report is None:
            return error_response("Report not found.", 404)

        connections = build_connections(
            report_id,
            report.get("indicators", []),
            get_all_reports(),
        )

        summary = make_investigation_summary(
            report,
            connections,
        )

        return jsonify({
            "ok": True,
            "report": report,
            "connections": connections,
            "summary": summary,
        })

    except Exception:
        logger.exception(
            "Could not load report %s",
            report_id,
        )

        return error_response(
            "Could not load this report.",
            500,
        )


# =========================================================
# GRAPH DATA ENDPOINT
# =========================================================

@app.get("/api/graph")
def graph_data():
    try:
        reports = get_all_reports()
        return jsonify(make_graph(reports))

    except Exception:
        logger.exception("Graph generation failed")

        return error_response(
            "Could not build the investigation graph.",
            500,
        )


# =========================================================
# UPLOAD SIZE ERROR HANDLER
# =========================================================

@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return error_response(
        "Request too large. Maximum upload size is 5 MB.",
        413,
    )


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
