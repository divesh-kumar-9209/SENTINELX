from datetime import datetime, timezone


VALID_STATUSES = {
    "Pending Review",
    "Under Investigation",
    "Resolved",
}


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
            "severity": event["severity"],
        })

    timeline.sort(
        key=lambda item: datetime.fromisoformat(
            item["timestamp"].replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    )

    return {
        "incident_id": incident["incident_id"],
        "host": incident["host"],
        "severity": incident["severity"],
        "summary": incident["summary"],
        "event_count": len(timeline),
        "timeline": timeline,
        "mitre_techniques": incident["mitre_techniques"],
        "investigation_status": incident.get(
            "status", "Pending Review"
        ),
        "analyst_note": "",
    }


def update_investigation(investigation, status, analyst_note=""):

    if status not in VALID_STATUSES:
        raise ValueError("Invalid investigation status.")

    updated = investigation.copy()
    updated["investigation_status"] = status
    updated["analyst_note"] = analyst_note

    return updated


def investigate_all(incidents, events):

    return [
        create_investigation(incident, events)
        for incident in incidents
    ]