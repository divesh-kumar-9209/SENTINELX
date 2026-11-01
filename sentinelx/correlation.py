from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import uuid4


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def parse_timestamp(value):
    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def correlate_detections(events, detections):
    event_lookup = {
        event["event_id"]: event
        for event in events
    }

    host_detections = defaultdict(list)

    for detection in detections:
        related_events = [
            event_lookup[event_id]
            for event_id in detection["event_ids"]
            if event_id in event_lookup
        ]

        if not related_events:
            continue

        hosts = {event["host"] for event in related_events}

        for host in hosts:
            host_detections[host].append(detection)

    incidents = []

    for host, records in host_detections.items():

        records.sort(
            key=lambda detection: min(
                parse_timestamp(event_lookup[event_id]["timestamp"])
                for event_id in detection["event_ids"]
                if event_id in event_lookup
            )
        )

        groups = []

        for detection in records:
            detection_events = [
                event_lookup[event_id]
                for event_id in detection["event_ids"]
                if event_id in event_lookup
            ]

            detection_start = min(
                parse_timestamp(event["timestamp"])
                for event in detection_events
            )

            matched_group = None

            for group in reversed(groups):
                if detection_start - group["last_time"] <= timedelta(minutes=30):
                    matched_group = group
                    break

            if matched_group is None:
                matched_group = {
                    "detections": [],
                    "last_time": detection_start,
                }
                groups.append(matched_group)

            matched_group["detections"].append(detection)

            matched_group["last_time"] = max(
                matched_group["last_time"],
                max(
                    parse_timestamp(event["timestamp"])
                    for event in detection_events
                ),
            )

        for group in groups:
            group_detections = group["detections"]

            event_ids = {
                event_id
                for detection in group_detections
                for event_id in detection["event_ids"]
                if event_id in event_lookup
            }

            incident_events = [
                event_lookup[event_id]
                for event_id in event_ids
            ]

            incident_events.sort(
                key=lambda event: parse_timestamp(event["timestamp"])
            )

            techniques = {
                detection["mitre"]
                for detection in group_detections
                if detection.get("mitre")
            }

            severity = max(
                (
                    detection["severity"]
                    for detection in group_detections
                ),
                key=lambda value: SEVERITY_RANK.get(value, 0),
            )

            incidents.append({
                "incident_id": str(uuid4()),
                "host": host,
                "severity": severity,
                "detection_ids": [
                    detection["detection_id"]
                    for detection in group_detections
                ],
                "event_ids": sorted(
                    event_ids,
                    key=lambda event_id: parse_timestamp(
                        event_lookup[event_id]["timestamp"]
                    ),
                ),
                "event_count": len(event_ids),
                "detection_count": len(group_detections),
                "start_time": incident_events[0]["timestamp"],
                "end_time": incident_events[-1]["timestamp"],
                "mitre_techniques": sorted(techniques),
                "summary": (
                    f"{len(group_detections)} detection(s) involving "
                    f"{len(event_ids)} event(s) were associated "
                    f"with host {host}."
                ),
                "status": "Open",
            })

    incidents.sort(
        key=lambda incident: SEVERITY_RANK.get(
            incident["severity"], 0
        ),
        reverse=True,
    )

    return incidents