
from datetime import datetime, timezone
from typing import Any


REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "source",
    "event_type",
    "host",
    "severity"
}


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:

    if not isinstance(raw, dict):
        raise ValueError("Event must be a JSON object")

    event = {
        "event_id": str(raw.get("event_id") or ""),
        "timestamp": str(raw.get("timestamp") or ""),
        "source": str(raw.get("source") or "unknown"),
        "event_type": str(raw.get("event_type") or "unknown"),
        "host": str(raw.get("host") or "unknown"),
        "username": raw.get("username"),
        "source_ip": raw.get("source_ip"),
        "destination_ip": raw.get("destination_ip"),
        "source_port": raw.get("source_port"),
        "destination_port": raw.get("destination_port"),
        "protocol": raw.get("protocol"),
        "severity": str(raw.get("severity") or "low").lower(),
        "description": str(raw.get("description") or ""),
        "raw_event": raw.get("raw_event", raw)
    }

    missing = [
        field for field in REQUIRED_FIELDS
        if not event.get(field)
    ]

    if missing:
        raise ValueError(
            "Missing required fields: " + ", ".join(sorted(missing))
        )

    try:
        parsed = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        event["timestamp"] = (
            parsed.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    except ValueError:
        raise ValueError(
            "Timestamp must be a valid ISO-8601 datetime"
        )

    if event["severity"] not in {
        "low", "medium", "high", "critical"
    }:
        raise ValueError("Invalid severity level")

    return event


def normalize_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:

    normalized = []

    for record in records:
        normalized.append(normalize_event(record))

    return normalized
