import logging
import os
import re
import shutil
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
# APPLICATION CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

# Maximum uploaded request size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_TEXT_LENGTH = 20_000
MAX_IMAGE_PIXELS = 20_000_000

ALLOWED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
    ".tif",
    ".tiff",
}


# =========================================================
# TESSERACT OCR CONFIGURATION
# =========================================================

def configure_tesseract():
    """
    Locate the Tesseract executable using:
    1. TESSERACT_CMD environment variable
    2. Common Windows installation locations
    3. System PATH
    """

    candidates = []

    # Optional custom path supplied through an environment variable.
    env_path = os.environ.get("TESSERACT_CMD", "").strip()

    if env_path:
        candidates.append(Path(env_path))

    # Common Windows installation locations.
    candidates.extend([
        Path(
            r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        ),
        Path(
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"
        ),
        (
            Path.home()
            / "AppData"
            / "Local"
            / "Programs"
            / "Tesseract-OCR"
            / "tesseract.exe"
        ),
    ])

    for candidate in candidates:
        if candidate.is_file():
            pytesseract.pytesseract.tesseract_cmd = str(candidate)

            logger.info(
                "Tesseract executable found: %s",
                candidate,
            )

            return str(candidate)

    # Check whether Tesseract is available through PATH.
    path_executable = shutil.which("tesseract")

    if path_executable:
        pytesseract.pytesseract.tesseract_cmd = path_executable

        logger.info(
            "Tesseract found through PATH: %s",
            path_executable,
        )

        return path_executable

    logger.warning(
        "Tesseract was not found. Install Tesseract OCR "
        "or configure TESSERACT_CMD."
    )

    return None


TESSERACT_PATH = configure_tesseract()


# =========================================================
# COMMON RESPONSE HELPER
# =========================================================

def error_response(message, status=400):
    return jsonify({
        "ok": False,
        "error": message,
    }), status


# =========================================================
# OCR HEALTH CHECK
# =========================================================

def get_ocr_status():
    """
    Check whether the Tesseract engine can actually start.
    """

    try:
        version = str(
            pytesseract.get_tesseract_version()
        )

        return {
            "available": True,
            "version": version,
            "error": None,
        }

    except pytesseract.TesseractNotFoundError:
        return {
            "available": False,
            "version": None,
            "error": (
                "Tesseract executable was not found. "
                "Install Tesseract OCR or set TESSERACT_CMD "
                "to the full path of tesseract.exe."
            ),
        }

    except pytesseract.TesseractError as exc:
        logger.exception(
            "Tesseract engine error during health check"
        )

        return {
            "available": False,
            "version": None,
            "error": (
                "Tesseract could not start correctly: "
                f"{exc}"
            ),
        }

    except Exception as exc:
        logger.exception(
            "Could not check Tesseract availability"
        )

        return {
            "available": False,
            "version": None,
            "error": f"OCR check failed: {exc}",
        }


# =========================================================
# GRAPH GENERATION
# =========================================================

def make_graph(reports):
    """
    Create one graph node per report and connect reports
    that share exact indicators of the same type.
    """

    nodes = []
    indicator_map = {}

    for report in reports:
        report_id = str(report["id"])

        indicators = report.get("indicators", []) or []

        nodes.append({
            "id": report_id,
            "label": (
                report.get("title")
                or f"Report {report_id}"
            ),
            "risk_score": report.get("risk_score", 0),
            "risk_level": report.get("risk_level", "low"),
            "indicator_count": len(indicators),
            "connected": False,
            "connection_count": 0,
            "created_at": report.get("created_at", ""),
        })

        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue

            kind = str(
                indicator.get("type", "")
            ).strip().lower()

            value = str(
                indicator.get("value", "")
            ).strip().lower()

            if kind and value:
                key = (kind, value)

                indicator_map.setdefault(
                    key, set()
                ).add(report_id)

    # Find report pairs that share indicators.
    pair_matches = {}

    for (kind, value), report_ids in indicator_map.items():

        ids = sorted(
            report_ids,
            key=lambda item: (
                0, int(item)
            ) if item.isdigit() else (1, item),
        )

        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):

                pair = (ids[i], ids[j])

                pair_matches.setdefault(
                    pair, []
                ).append({
                    "type": kind,
                    "value": value,
                })

    edges = []

    for (left, right), shared in pair_matches.items():

        edges.append({
            "source": left,
            "target": right,
            "shared_indicators": shared,
            "weight": len(shared),
            "explanation": (
                f"These reports share {len(shared)} "
                "exact indicator match(es) of the same type."
            ),
        })

    # Calculate each node's number of connections.
    degree = {
        node["id"]: 0
        for node in nodes
    }

    connected_ids = set()

    for edge in edges:

        connected_ids.add(edge["source"])
        connected_ids.add(edge["target"])

        degree[edge["source"]] = (
            degree.get(edge["source"], 0) + 1
        )

        degree[edge["target"]] = (
            degree.get(edge["target"], 0) + 1
        )

    for node in nodes:

        node["connected"] = (
            node["id"] in connected_ids
        )

        node["connection_count"] = degree.get(
            node["id"], 0
        )

    return {
        "nodes": nodes,
        "edges": edges,
    }


# =========================================================
# HOME PAGE
# =========================================================

@app.get("/")
def home():
    return render_template("index.html")


# =========================================================
# BACKEND AND OCR HEALTH CHECK
# =========================================================

@app.get("/api/health")
def health():

    try:
        init_db()

        ocr = get_ocr_status()

        return jsonify({
            "ok": True,
            "service": "ScamGraph AI",
            "analysis_engine": "transparent_rule_based_demo",
            "database": "ready",
            "ocr_available": ocr["available"],
            "ocr_version": ocr["version"],
            "ocr_error": ocr["error"],
        })

    except Exception:
        logger.exception(
            "Health check failed"
        )

        return jsonify({
            "ok": False,
            "error": "Backend check failed.",
        }), 500


# =========================================================
# OCR IMAGE EXTRACTION
# =========================================================

@app.post("/api/ocr")
def ocr_image():

    upload = request.files.get("image")

    # Check whether the user selected an image.
    if not upload or not upload.filename:
        return error_response(
            "Choose a screenshot image first."
        )

    extension = Path(
        upload.filename
    ).suffix.lower()

    # Validate the file extension.
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return error_response(
            "Unsupported file type. Choose PNG, JPG, JPEG, "
            "WEBP, BMP or TIFF."
        )

    # Check Tesseract before processing the image.
    ocr_status = get_ocr_status()

    if not ocr_status["available"]:
        return error_response(
            ocr_status["error"]
            or "Tesseract OCR is unavailable.",
            500,
        )

    try:

        # Read only up to the configured size limit plus one byte.
        raw_bytes = upload.read(
            app.config["MAX_CONTENT_LENGTH"] + 1
        )

        if not raw_bytes:
            return error_response(
                "The selected image is empty."
            )

        if len(raw_bytes) > app.config["MAX_CONTENT_LENGTH"]:
            return error_response(
                "Image exceeds the 5 MB limit.",
                413,
            )

        # Validate the image and guard against huge dimensions.
        with Image.open(BytesIO(raw_bytes)) as original:

            if (
                original.width * original.height
                > MAX_IMAGE_PIXELS
            ):
                return error_response(
                    "Image dimensions are too large."
                )

            original.verify()

        # Reopen the image after verification.
        with Image.open(BytesIO(raw_bytes)) as original:

            # Correct image orientation.
            image = ImageOps.exif_transpose(
                original
            ).convert("RGB")

            # Improve contrast and convert to grayscale.
            image = ImageOps.grayscale(image)
            image = ImageOps.autocontrast(image)

            # Upscale small screenshots to improve recognition.
            if image.width < 1200:

                scale = min(
                    2,
                    1200 / max(image.width, 1),
                )

                new_size = (
                    int(image.width * scale),
                    int(image.height * scale),
                )

                image = image.resize(
                    new_size,
                    Image.Resampling.LANCZOS,
                )

            # Extract English text from the image.
            extracted = pytesseract.image_to_string(
                image,
                lang="eng",
                config="--oem 3 --psm 6",
            ).strip()

        # Remove excessive blank lines.
        extracted = re.sub(
            r"\n{3,}",
            "\n\n",
            extracted,
        )

        # Enforce the maximum text length.
        extracted = extracted[:MAX_TEXT_LENGTH]

        # Handle images where little or no text was detected.
        if len(extracted.strip()) < 5:

            return jsonify({
                "ok": True,
                "text": extracted,
                "message": (
                    "Very little text was detected. "
                    "Try a clearer image with larger, sharper "
                    "text and the complete message visible."
                ),
            })

        return jsonify({
            "ok": True,
            "text": extracted,
            "message": (
                "Text extracted. Review it before analysis."
            ),
        })

    except pytesseract.TesseractNotFoundError:

        logger.exception(
            "Tesseract executable not found during OCR"
        )

        return error_response(
            "Tesseract executable was not found. "
            "Install it or set TESSERACT_CMD to the full "
            "path of tesseract.exe, then restart Flask.",
            500,
        )

    except pytesseract.TesseractError as exc:

        logger.exception(
            "Tesseract engine error during OCR"
        )

        return error_response(
            "Tesseract could not process this image. "
            "Confirm that English language data is installed. "
            f"Details: {exc}",
            500,
        )

    except UnidentifiedImageError:

        return error_response(
            "The selected file is not a readable image."
        )

    except Exception:

        logger.exception(
            "Unexpected OCR failure"
        )

        return error_response(
            "OCR failed unexpectedly. "
            "Check the VS Code terminal for details.",
            500,
        )


# =========================================================
# MESSAGE ANALYSIS AND REPORT CREATION
# =========================================================

@app.post("/api/analyze")
def analyze():

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return error_response(
            "Submit the message as JSON."
        )

    text = payload.get("text", "")

    if not isinstance(text, str):
        return error_response(
            "Message text must be a string."
        )

    text = text.strip()

    if len(text) < 5:
        return error_response(
            "Enter at least 5 characters."
        )

    if len(text) > MAX_TEXT_LENGTH:
        return error_response(
            "Maximum message length is 20,000 characters.",
            413,
        )

    title = payload.get(
        "title", "Investigation"
    )

    source = payload.get(
        "source", "Manual entry"
    )

    title = (
        title.strip()[:160]
        if isinstance(title, str)
        else "Investigation"
    )

    source = (
        source.strip()[:50]
        if isinstance(source, str)
        else "Manual entry"
    )

    title = title or "Investigation"
    source = source or "Manual entry"

    try:

        # Analyze text using the existing scamgraph.py logic.
        result = analyze_text(text)

        # Save the report in the database.
        report_id = save_report(
            title,
            source,
            text,
            result,
        )

        # Compare the new report with existing reports.
        reports = get_all_reports()

        connections = build_connections(
            report_id,
            result.get("indicators", []),
            reports,
        )

        summary = make_investigation_summary(
            result,
            connections,
        )

        if connections:

            reply = (
                f"Investigation #{report_id} saved. "
                f"{result['risk_level'].capitalize()} "
                f"triage score: {result['risk_score']}/100. "
                f"Found {len(connections)} report(s) "
                "with shared indicators."
            )

        else:

            reply = (
                f"Investigation #{report_id} saved. "
                f"{result['risk_level'].capitalize()} "
                f"triage score: {result['risk_score']}/100. "
                "No shared indicators were found in existing "
                "reports. This report can still appear in the "
                "graph as an isolated node."
            )

        return jsonify({
            "ok": True,
            "report_id": report_id,
            "analysis": result,
            "connections": connections,
            "summary": summary,
            "reply": reply,
            "notice": (
                "Rule-based triage only—not proof of fraud "
                "or a calibrated probability. Review the "
                "evidence independently."
            ),
        }), 201

    except ValueError as exc:

        return error_response(
            str(exc)
        )

    except Exception:

        logger.exception(
            "Analysis failed"
        )

        return error_response(
            "Analysis failed. Check the VS Code terminal.",
            500,
        )


# =========================================================
# LIST INVESTIGATION REPORTS
# =========================================================

@app.get("/api/reports")
def reports():

    try:

        try:
            limit = int(
                request.args.get("limit", 50)
            )
        except ValueError:
            limit = 50

        limit = max(
            1,
            min(limit, 200),
        )

        return jsonify({
            "ok": True,
            "reports": list_reports(limit),
        })

    except Exception:

        logger.exception(
            "Could not list reports"
        )

        return error_response(
            "Could not load reports.",
            500,
        )


# =========================================================
# SINGLE REPORT DETAILS
# =========================================================

@app.get("/api/reports/<int:report_id>")
def report_detail(report_id):

    try:

        report = get_report(report_id)

        if report is None:
            return error_response(
                "Report not found.",
                404,
            )

        connections = build_connections(
            report_id,
            report.get("indicators", []),
            get_all_reports(),
        )

        return jsonify({
            "ok": True,
            "report": report,
            "connections": connections,
            "summary": make_investigation_summary(
                report,
                connections,
            ),
        })

    except Exception:

        logger.exception(
            "Could not load report details"
        )

        return error_response(
            "Could not load report details.",
            500,
        )


# =========================================================
# GRAPH DATA API
# =========================================================

@app.get("/api/graph")
def graph_data():

    try:

        return jsonify(
            make_graph(get_all_reports())
        )

    except Exception:

        logger.exception(
            "Graph generation failed"
        )

        return error_response(
            "Could not build the graph.",
            500,
        )


# =========================================================
# GLOBAL UPLOAD SIZE ERROR HANDLER
# =========================================================

@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):

    return error_response(
        "Upload too large. Maximum request size is 5 MB.",
        413,
    )


# =========================================================
# APPLICATION ENTRY POINT
# =========================================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=int(
            os.environ.get("PORT", "5000")
        ),
        debug=(
            os.environ.get("FLASK_DEBUG") == "1"
        ),
    )