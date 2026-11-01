import json
import tempfile
import unittest

from sentinelx.schema import (
    normalize_event,
    normalize_events,
    load_events_from_json,
)


class TestEventSchema(unittest.TestCase):

    def setUp(self):
        self.valid_event = {
            "event_id": "TEST001",
            "timestamp": "2026-11-01T10:00:00Z",
            "source": "Windows",
            "event_type": "login_failed",
            "host": "SERVER01",
            "severity": "HIGH",
            "username": "testuser",
            "source_ip": "192.168.1.10",
        }

    def test_valid_event(self):
        result = normalize_event(self.valid_event)
        self.assertEqual(result["severity"], "high")

    def test_timestamp_normalization(self):
        event = self.valid_event.copy()
        event["timestamp"] = "2026-11-01T15:30:00+05:30"

        result = normalize_event(event)

        self.assertEqual(result["timestamp"], "2026-11-01T10:00:00Z")

    def test_missing_required_field(self):
        event = self.valid_event.copy()
        del event["host"]

        with self.assertRaises(ValueError):
            normalize_event(event)

    def test_invalid_timestamp(self):
        event = self.valid_event.copy()
        event["timestamp"] = "not-a-date"

        with self.assertRaises(ValueError):
            normalize_event(event)

    def test_invalid_severity(self):
        event = self.valid_event.copy()
        event["severity"] = "extreme"

        with self.assertRaises(ValueError):
            normalize_event(event)

    def test_empty_event_list(self):
        with self.assertRaises(ValueError):
            normalize_events([])

    def test_non_list_input(self):
        with self.assertRaises(ValueError):
            normalize_events({"event": self.valid_event})

    def test_invalid_event_in_list(self):
        event = self.valid_event.copy()
        del event["event_id"]

        with self.assertRaises(ValueError):
            normalize_events([event])

    def test_json_file_loading(self):
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            encoding="utf-8",
            delete=False
        ) as file:
            json.dump([self.valid_event], file)
            file_path = file.name

        try:
            result = load_events_from_json(file_path)
            self.assertEqual(len(result), 1)
        finally:
            import os
            os.remove(file_path)

    def test_invalid_json_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            encoding="utf-8",
            delete=False
        ) as file:
            file.write("{invalid json")
            file_path = file.name

        try:
            with self.assertRaises(ValueError):
                load_events_from_json(file_path)
        finally:
            import os
            os.remove(file_path)


if __name__ == "__main__":
    unittest.main()