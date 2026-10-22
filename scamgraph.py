import re
from urllib.parse import urlparse


MAX_TEXT_LENGTH = 20000

PATTERNS = {
    "urgency": {
        "regex": r"\b(urgent|immediately|act now|within 24 hours|"
                 r"expires today|blocked today|suspended today|"
                 r"last warning|final warning)\b",
        "points": 20,
        "explanation": "Urgent or threatening language pressures the recipient."
    },
    "credential_request": {
        "regex": r"\b(share|send|provide|enter|confirm|verify|update)"
                 r"\b.{0,45}\b(otp|password|pin|cvv|login details|"
                 r"bank details|verification code)\b",
        "points": 30,
        "explanation": "The message appears to request sensitive credentials."
    },
    "payment_request": {
        "regex": r"\b(pay now|send money|transfer money|processing fee|"
                 r"claim fee|pay a fee|deposit now|upi payment|"
                 r"payment required|account will be debited)\b",
        "points": 20,
        "explanation": "The message includes a payment-related request."
    },
    "prize_or_reward": {
        "regex": r"\b(you have won|claim your prize|free gift|"
                 r"lottery winner|cash reward|selected winner)\b",
        "points": 15,
        "explanation": "The message uses a prize or reward claim."
    },
    "impersonation": {
        "regex": r"\b(bank|police|income tax|customs|government|"
                 r"courier|delivery|customer support|account department)\b",
        "points": 8,
        "explanation": "The message mentions an organization or authority. "
                       "This alone does not establish impersonation."
    },
}

URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\[\]{}\"']+"
)
EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
)
UPI_RE = re.compile(
    r"(?i)(?<![\w.+-])[\w.-]{2,256}@[a-z][a-z0-9.-]{1,63}\b"
)
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+91[\s-]?)?[6-9]\d{9}(?!\w)"
)
PAYMENT_REF_RE = re.compile(
    r"(?i)\b(?:txn|transaction|utr|reference|ref)\s*(?:id|no|number)?"
    r"\s*[:#-]?\s*([A-Z0-9]{8,24})\b"
)


def _clean_indicator(value):
    return value.strip(".,;:!?)]}>\"'").strip()


def _add_indicator(items, seen, kind, value):
    value = _clean_indicator(str(value))
    if not value:
        return

    normalized = value.lower()

    # Avoid duplicate email / UPI values.
    key = (kind, normalized)
    if key in seen:
        return

    seen.add(key)
    items.append({"type": kind, "value": value})


def extract_indicators(text):
    indicators = []
    seen = set()

    # Extract emails first, so they are not duplicated as UPI IDs.
    for value in EMAIL_RE.findall(text):
        _add_indicator(indicators, seen, "email", value)

    for value in URL_RE.findall(text):
        value = _clean_indicator(value)
        # Ignore obviously malformed links.
        if value.lower().startswith("www."):
            value = "https://" + value
        parsed = urlparse(value)
        if parsed.netloc:
            _add_indicator(indicators, seen, "url", value)

    for value in UPI_RE.findall(text):
        # A UPI-style string should not duplicate a full email address.
        if EMAIL_RE.fullmatch(value):
            continue
        _add_indicator(indicators, seen, "upi_id", value)

    for value in PHONE_RE.findall(text):
        normalized = re.sub(r"\D", "", value)
        if normalized.startswith("91") and len(normalized) == 12:
            normalized = normalized[2:]
        _add_indicator(indicators, seen, "phone", normalized)

    for value in PAYMENT_REF_RE.findall(text):
        _add_indicator(indicators, seen, "payment_reference", value)

    return indicators


def analyze_text(text):
    if not isinstance(text, str):
        raise ValueError("Message must be text.")

    text = text.strip()

    if len(text) < 5:
        raise ValueError("Please enter at least 5 characters.")

    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError("Maximum message length is 20,000 characters.")

    lower_text = text.lower()
    reasons = []
    score = 0

    for name, rule in PATTERNS.items():
        if re.search(rule["regex"], lower_text, re.IGNORECASE | re.DOTALL):
            score += rule["points"]
            reasons.append({
                "type": name,
                "points": rule["points"],
                "explanation": rule["explanation"],
            })

    indicators = extract_indicators(text)

    if any(item["type"] == "url" for item in indicators):
        score += 10
        reasons.append({
            "type": "link_present",
            "points": 10,
            "explanation": "A web link is present. Its presence alone "
                           "does not prove it is malicious.",
        })

    score = min(100, score)

    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "reasons": reasons,
        "method": "transparent_rule_based_demo",
        "explanation": (
            f"The rules matched {len(reasons)} configured signal(s) "
            f"and extracted {len(indicators)} indicator(s)."
        ),
        "limitations": [
            "This score is a rule-based triage score, not a probability.",
            "A phone number, email, URL, or UPI ID alone does not prove fraud.",
            "A low score does not guarantee that a message is safe.",
            "OCR mistakes can affect the analysis; verify extracted text.",
        ],
    }


def build_connections(report_id, indicators, reports):
    """Return older reports sharing at least one same-type indicator."""
    target_keys = {
        (str(item.get("type", "")).lower(),
         str(item.get("value", "")).strip().lower())
        for item in indicators
        if item.get("type") and item.get("value")
    }

    connections = []

    for report in reports:
        if int(report["id"]) == int(report_id):
            continue

        other_keys = {
            (str(item.get("type", "")).lower(),
             str(item.get("value", "")).strip().lower())
            for item in report.get("indicators", [])
            if item.get("type") and item.get("value")
        }

        shared = target_keys & other_keys
        if not shared:
            continue

        shared_indicators = [
            {"type": kind, "value": value}
            for kind, value in sorted(shared)
        ]

        connections.append({
            "report_id": report["id"],
            "title": report.get("title", "Untitled report"),
            "risk_score": report.get("risk_score", 0),
            "risk_level": report.get("risk_level", "unknown"),
            "shared_indicators": shared_indicators,
            "connection_strength": min(100, 25 * len(shared)),
            "explanation": (
                f"Shares {len(shared)} exact indicator match(es) "
                "of the same type with this report."
            ),
        })

    connections.sort(
        key=lambda item: (
            len(item["shared_indicators"]),
            item["risk_score"]
        ),
        reverse=True
    )
    return connections


def make_investigation_summary(result, connections):
    indicators = result.get("indicators", [])
    reasons = result.get("reasons", [])

    if indicators:
        evidence = ", ".join(
            f"{item['type'].replace('_', ' ')}: {item['value']}"
            for item in indicators[:8]
        )
        evidence_text = f"Extracted indicators: {evidence}."
    else:
        evidence_text = (
            "No supported phone, URL, email, UPI, or payment-reference "
            "indicators were extracted."
        )

    if reasons:
        language_analysis = " ".join(
            item.get("explanation", "") for item in reasons
        )
    else:
        language_analysis = (
            "No configured suspicious-language patterns matched. "
            "This does not establish that the message is safe."
        )

    if connections:
        cross_report = (
            f"Found {len(connections)} previous report(s) with at least "
            "one exact same-type indicator match."
        )
    else:
        cross_report = (
            "No shared indicators were found in the saved reports. "
            "This report will still appear in the graph as an isolated node."
        )

    return {
        "headline": (
            f"{result['risk_level'].capitalize()} triage level "
            f"({result['risk_score']}/100)"
        ),
        "evidence_found": evidence_text,
        "language_analysis": language_analysis,
        "cross_report_analysis": cross_report,
        "recommended_next_steps": [
            "Preserve the original message and its timestamp.",
            "Do not click suspicious links or share OTPs or passwords.",
            "Verify claims through official contact channels.",
            "If money was lost in India, contact your bank promptly and "
            "consider reporting through the official cybercrime portal.",
        ],
    }