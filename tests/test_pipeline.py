
import json
import unittest
from pathlib import Path

from sentinelx.pipeline import run_pipeline


class TestSentinelX(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        file_path = (
            Path(__file__).parent.parent
            / "data"
            / "sample_events.json"
        )

        with open(file_path, "r", encoding="utf-8") as file:
            cls.events = json.load(file)

        cls.results = run_pipeline(cls.events)

    def test_event_normalization(self):
        self.assertEqual(
            self.results["statistics"]["total_events"], 16
        )

    def test_detection_generation(self):
        self.assertEqual(
            self.results["statistics"]["total_detections"], 5
        )

    def test_incident_generation(self):
        self.assertEqual(
            self.results["statistics"]["total_incidents"], 2
        )

    def test_critical_incident_exists(self):
        critical = [
            incident for incident in self.results["incidents"]
            if incident["severity"] == "critical"
        ]

        self.assertGreaterEqual(len(critical), 1)

    def test_investigation_timeline(self):
        self.assertEqual(
            len(self.results["investigations"]), 2
        )

        for investigation in self.results["investigations"]:
            self.assertGreater(investigation["event_count"], 0)


if __name__ == "__main__":
    unittest.main()
