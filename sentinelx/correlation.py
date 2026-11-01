
from collections import defaultdict
from datetime import datetime
from uuid import uuid4


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


def parse_timestamp(value):
    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    return parsed


def correlate_detections(events, detections):
    event_lookup = {
        event["event_id"]: event
        for event in events
    }

    grouped_detections = defaultdict(list)

    for detection in detections:
        related_events = [
            event_lookup[event_id]
            for event_id in detection["event_ids"]
            if event_id in event_lookup
        ]

        if not related_events:
            continue

        hosts = {
            event["host"]
            for event in related_events
        }

        for host in hosts:
            grouped_detections[host].append(detection)

    incidents = []

    for host, host_detections in grouped_detections.items():

        all_event_ids = set()
        all_detection_ids = []
        all_events = []
        techniques = set()

        for detection in host_detections:
            all_detection_ids.append(
                detection["detection_id"]
            )

            all_event_ids.update(
                detection["event_ids"]
            )

            techniques.add(detection["mitre"])

        for event_id in all_event_ids:
            if event_id in event_lookup:
                all_events.append(
                    event_lookup[event_id]
                )

        if not all_events:
            continue

        all_events.sort(
            key=lambda event: parse_timestamp(
                event["timestamp"]
            )
        )

        highest_severity = max(
            (
                detection["severity"]
                for detection in host_detections
            ),
            key=lambda severity: SEVERITY_RANK.get(
                severity, 0
            )
        )

        incident = {
            "incident_id": str(uuid4()),
            "host": host,
            "severity": highest_severity,
            "detection_ids": all_detection_ids,
            "event_ids": sorted(all_event_ids),
            "event_count": len(all_event_ids),
            "detection_count": len(all_detection_ids),
            "start_time": all_events[0]["timestamp"],
            "end_time": all_events[-1]["timestamp"],
            "mitre_techniques": sorted(techniques),
            "summary": (
                f"{len(all_detection_ids)} detection(s) involving "
                f"{len(all_event_ids)} event(s) were associated "
                f"with host {host}."
            )
        }

        incidents.append(incident)

    incidents.sort(
        key=lambda incident: SEVERITY_RANK.get(
            incident["severity"], 0
        ),
        reverse=True
    )

    return incidents
