
from sentinelx.schema import normalize_events
from sentinelx.detection import run_detections
from sentinelx.correlation import correlate_detections
from sentinelx.investigation import investigate_all


def run_pipeline(raw_events):
    normalized_events = normalize_events(raw_events)

    detections = run_detections(normalized_events)

    incidents = correlate_detections(
        normalized_events,
        detections
    )

    investigations = investigate_all(
        incidents,
        normalized_events
    )

    return {
        "events": normalized_events,
        "detections": detections,
        "incidents": incidents,
        "investigations": investigations,
        "statistics": {
            "total_events": len(normalized_events),
            "total_detections": len(detections),
            "total_incidents": len(incidents)
        }
    }
