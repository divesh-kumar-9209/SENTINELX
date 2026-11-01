
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import uuid4


def parse_timestamp(value):
    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def create_detection(name, severity, events, reason, mitre):
    return {
        "detection_id": str(uuid4()),
        "name": name,
        "severity": severity,
        "event_ids": [
            event["event_id"] for event in events
        ],
        "reason": reason,
        "mitre": mitre
    }


def detect_repeated_login_failures(events):
    detections = []

    grouped = defaultdict(list)

    for event in events:
        if event["event_type"].lower() in {
            "login_failure",
            "authentication_failure"
        }:
            key = (
                event.get("username"),
                event.get("source_ip"),
                event.get("host")
            )
            grouped[key].append(event)

    for key, records in grouped.items():
        records.sort(
            key=lambda x: parse_timestamp(x["timestamp"])
        )

        for index, first_event in enumerate(records):
            window_start = parse_timestamp(
                first_event["timestamp"]
            )

            matching = [
                event for event in records[index:]
                if parse_timestamp(event["timestamp"])
                <= window_start + timedelta(minutes=5)
            ]

            if len(matching) >= 5:
                detections.append(
                    create_detection(
                        name="Repeated Login Failures",
                        severity="high",
                        events=matching,
                        reason=(
                            f"{len(matching)} failed login attempts "
                            f"were observed for the same user and "
                            f"source IP within five minutes."
                        ),
                        mitre="T1110"
                    )
                )
                break

    return detections


def detect_failure_followed_by_success(events):
    detections = []

    grouped = defaultdict(list)

    for event in events:
        if event["event_type"].lower() in {
            "login_failure",
            "authentication_failure",
            "login_success",
            "authentication_success"
        }:
            key = (
                event.get("username"),
                event.get("source_ip"),
                event.get("host")
            )
            grouped[key].append(event)

    for key, records in grouped.items():
        records.sort(
            key=lambda x: parse_timestamp(x["timestamp"])
        )

        for index, event in enumerate(records):
            if event["event_type"].lower() not in {
                "login_failure",
                "authentication_failure"
            }:
                continue

            start_time = parse_timestamp(event["timestamp"])
            window = [
                item for item in records[index:]
                if parse_timestamp(item["timestamp"])
                <= start_time + timedelta(minutes=10)
            ]

            failures = [
                item for item in window
                if item["event_type"].lower() in {
                    "login_failure",
                    "authentication_failure"
                }
            ]

            successes = [
                item for item in window
                if item["event_type"].lower() in {
                    "login_success",
                    "authentication_success"
                }
            ]

            if len(failures) >= 3 and successes:
                detections.append(
                    create_detection(
                        name="Failed Logins Followed by Success",
                        severity="critical",
                        events=failures + [successes[0]],
                        reason=(
                            "Multiple failed login attempts were "
                            "followed by a successful login within "
                            "ten minutes."
                        ),
                        mitre="T1110"
                    )
                )
                break

    return detections


def detect_port_scanning(events):
    detections = []

    grouped = defaultdict(list)

    for event in events:
        if event.get("destination_port") is not None:
            key = (
                event.get("source_ip"),
                event.get("host")
            )
            grouped[key].append(event)

    for key, records in grouped.items():
        unique_ports = {
            event.get("destination_port")
            for event in records
        }

        if len(unique_ports) >= 8:
            detections.append(
                create_detection(
                    name="Possible Port Scanning",
                    severity="high",
                    events=records,
                    reason=(
                        f"The source IP contacted "
                        f"{len(unique_ports)} distinct destination "
                        f"ports on the same host."
                    ),
                    mitre="T1046"
                )
            )

    return detections


def detect_account_creation(events):
    detections = []

    for event in events:
        if event["event_type"].lower() in {
            "account_created",
            "user_created"
        }:
            detections.append(
                create_detection(
                    name="New Account Created",
                    severity="medium",
                    events=[event],
                    reason=(
                        "An account creation event was recorded."
                    ),
                    mitre="T1136"
                )
            )

    return detections


def detect_privilege_changes(events):
    detections = []

    for event in events:
        if event["event_type"].lower() in {
            "privilege_change",
            "privilege_escalation",
            "role_assigned"
        }:
            detections.append(
                create_detection(
                    name="Privilege Change Detected",
                    severity="high",
                    events=[event],
                    reason=(
                        "A privilege or role change event was recorded."
                    ),
                    mitre="T1098"
                )
            )

    return detections


def run_detections(events):
    detections = []

    detection_functions = [
        detect_repeated_login_failures,
        detect_failure_followed_by_success,
        detect_port_scanning,
        detect_account_creation,
        detect_privilege_changes
    ]

    for detection_function in detection_functions:
        detections.extend(
            detection_function(events)
        )

    return detections
