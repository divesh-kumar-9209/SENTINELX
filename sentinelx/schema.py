import json
from datetime import datetime, timezone
from pathlib import Path


REQUIRED_FIELDS = [
    "event_id",
    "timestamp",
    "source",
    "event_type",
    "host",
    "severity",
]

VALID_SEVERITIES = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}


def validate_timestamp(value):
    """Validate an ISO 8601 timestamp and convert it to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Timestamp must be a non-empty string.")

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"Invalid timestamp: {value}")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_event(event):
    """Validate and normalize a single security event."""
    if not isinstance(event, dict):
        raise ValueError("Each event must be a JSON object.")

    missing_fields = [
        field for field in REQUIRED_FIELDS
        if field not in event or event[field] is None or
        (isinstance(event[field], str) and not event[field].strip())
    ]

    if missing_fields:
        raise ValueError(
            "Missing or empty required fields: " + ", ".join(missing_fields)
        )

    normalized = event.copy()

    for field in ("event_id", "source", "event_type", "host"):
        if not isinstance(normalized[field], str):
            raise ValueError(f"{field} must be a string.")

        normalized[field] = normalized[field].strip()

    normalized["timestamp"] = validate_timestamp(normalized["timestamp"])

    if not isinstance(normalized["severity"], str):
        raise ValueError("Severity must be a string.")

    severity = normalized["severity"].strip().lower()

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. "
            f"Allowed values: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    normalized["severity"] = severity

    return normalized


def normalize_events(events):
    """Validate and normalize a list of security events."""
    if not isinstance(events, list):
        raise ValueError("Events data must be a JSON list.")

    if not events:
        raise ValueError("The event list is empty.")

    normalized_events = []
    errors = []

    for index, event in enumerate(events):
        try:
            normalized_events.append(normalize_event(event))
        except ValueError as error:
            errors.append(f"Event {index + 1}: {error}")

    if errors:
        raise ValueError("\n".join(errors))

    return normalized_events


def load_events_from_json(source):
    """
    Load events from a JSON file path or an uploaded file object.
    Accepts either a list of events or an object containing an 'events' list.
    """
    try:
        if hasattr(source, "read"):
            content = source.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8-sig")
        else:
            content = Path(source).read_text(encoding="utf-8-sig")

        data = json.loads(content)

    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON file: {error.msg}") from error
    except UnicodeDecodeError as error:
        raise ValueError("File must use UTF-8 encoding.") from error
    except OSError as error:
        raise ValueError(f"Unable to read file: {error}") from error

    if isinstance(data, dict):
        if "events" not in data:
            raise ValueError("JSON object must contain an 'events' field.")
        data = data["events"]

    return normalize_events(data)