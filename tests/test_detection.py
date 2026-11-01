import unittest

from sentinelx.detection import (
    detect_repeated_login_failures,
    detect_failure_followed_by_success,
    detect_port_scanning,
    detect_account_creation,
    detect_privilege_changes,
    run_detections,
)


def make_event(event_id, event_type, timestamp, **extra):
    event = {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": "Test Source",
        "event_type": event_type,
        "host": "SERVER01",
        "severity": "medium",
    }
    event.update(extra)
    return event


class TestThreatDetection(unittest.TestCase):

    def test_repeated_login_failures(self):
        events = [
            make_event(
                f"E{i}",
                "login_failure",
                f"2026-11-01T10:0{i}:00Z",
                username="admin",
                source_ip="192.168.1.10",
            )
            for i in range(5)
        ]

        result = detect_repeated_login_failures(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["mitre"], "T1110")
        self.assertEqual(result[0]["severity"], "high")

    def test_failure_followed_by_success(self):
        events = [
            make_event(
                f"E{i}",
                "login_failure",
                f"2026-11-01T10:0{i}:00Z",
                username="admin",
                source_ip="192.168.1.10",
            )
            for i in range(3)
        ]

        events.append(
            make_event(
                "E4",
                "login_success",
                "2026-11-01T10:04:00Z",
                username="admin",
                source_ip="192.168.1.10",
            )
        )

        result = detect_failure_followed_by_success(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "critical")
        self.assertEqual(result[0]["mitre"], "T1110")

    def test_port_scanning(self):
        events = [
            make_event(
                f"E{i}",
                "network_connection",
                "2026-11-01T10:00:00Z",
                source_ip="192.168.1.10",
                destination_port=port,
            )
            for i, port in enumerate(range(20, 28))
        ]

        result = detect_port_scanning(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["mitre"], "T1046")

    def test_account_creation(self):
        events = [
            make_event(
                "E1",
                "account_created",
                "2026-11-01T10:00:00Z",
            )
        ]

        result = detect_account_creation(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["mitre"], "T1136")

    def test_privilege_change(self):
        events = [
            make_event(
                "E1",
                "privilege_change",
                "2026-11-01T10:00:00Z",
            )
        ]

        result = detect_privilege_changes(events)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["mitre"], "T1098")

    def test_all_detection_rules(self):
        events = [
            make_event(
                f"L{i}",
                "login_failure",
                f"2026-11-01T10:0{i}:00Z",
                username="admin",
                source_ip="192.168.1.10",
            )
            for i in range(5)
        ]

        events.append(
            make_event(
                "L6",
                "login_success",
                "2026-11-01T10:05:00Z",
                username="admin",
                source_ip="192.168.1.10",
            )
        )

        events.extend([
            make_event(
                f"P{i}",
                "network_connection",
                "2026-11-01T10:10:00Z",
                source_ip="192.168.1.20",
                destination_port=port,
            )
            for i, port in enumerate(range(20, 28))
        ])

        events.append(
            make_event("A1", "account_created", "2026-11-01T10:20:00Z")
        )

        events.append(
            make_event("R1", "privilege_change", "2026-11-01T10:21:00Z")
        )

        result = run_detections(events)

        self.assertEqual(len(result), 5)

    def test_detection_has_required_fields(self):
        event = make_event(
            "E1",
            "account_created",
            "2026-11-01T10:00:00Z",
        )

        result = detect_account_creation([event])

        required = {
            "detection_id",
            "name",
            "severity",
            "event_ids",
            "reason",
            "mitre",
        }

        self.assertTrue(required.issubset(result[0].keys()))

    def test_no_detection_for_empty_events(self):
        self.assertEqual(run_detections([]), [])


if __name__ == "__main__":
    unittest.main()