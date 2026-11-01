
from datetime import datetime


def create_investigation(incident, events):
    event_lookup = {
        event["event_id"]: event
        for event in events
    }

    timeline = []

    for event_id in incident["event_ids"]:
        event = event_lookup.get(event_id)

        if not event:
            continue

        timeline.append({
            "timestamp": event["timestamp"],
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "description": event.get("description", ""),
            "severity": event["severity"]
        })

    timeline.sort(
        key=lambda item: datetime.fromisoformat(
            item["timestamp"].replace("Z", "+00:00")
        )
    )

    return {
        "incident_id": incident["incident_id"],
        "host": incident["host"],
        "severity": incident["severity"],
        "summary": incident["summary"],
        "event_count": len(timeline),
        "timeline": timeline,
        "mitre_techniques": incident["mitre_techniques"],
        "investigation_status": "Pending Review",
        "analyst_note": (
            "Automated analysis generated this incident. "
            "Manual investigation is required before confirming "
            "malicious activity."
        )
    }


def investigate_all(incidents, events):
    investigations = []

    for incident in incidents:
        investigations.append(
            create_investigation(incident, events)
        )

    return investigations
