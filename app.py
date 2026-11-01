
import json
import hashlib
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinelx.pipeline import run_pipeline
from sentinelx.storage import (
    get_investigation,
    save_investigation
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SENTINELX | Security Operations",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# INCIDENT FINGERPRINT
# --------------------------------------------------

def incident_fingerprint(incident):
    """Generate a stable identifier for an incident."""

    fingerprint_data = {
        "host": incident.get("host", ""),
        "event_ids": sorted(
            incident.get("event_ids", [])
        ),
        "detection_ids": sorted(
            incident.get("detection_ids", [])
        )
    }

    fingerprint_string = json.dumps(
        fingerprint_data,
        sort_keys=True
    )

    return hashlib.sha256(
        fingerprint_string.encode("utf-8")
    ).hexdigest()


# --------------------------------------------------
# PAGE HEADER
# --------------------------------------------------

st.title("🛡️ SENTINELX")

st.subheader(
    "Behavioral Threat Detection and Incident Investigation Platform"
)

st.caption(
    "Security Monitoring | Event Correlation | Incident Analysis"
)

st.divider()


# --------------------------------------------------
# LOAD SAMPLE EVENTS
# --------------------------------------------------

def load_sample_events():

    file_path = (
        Path(__file__).parent
        / "data"
        / "sample_events.json"
    )

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


# --------------------------------------------------
# EVENT DATA INPUT
# --------------------------------------------------

st.sidebar.header("Event Data")

uploaded_file = st.sidebar.file_uploader(
    "Upload security logs (JSON)",
    type=["json"]
)

if uploaded_file:

    try:
        raw_events = json.load(uploaded_file)

        if isinstance(raw_events, dict) and "events" in raw_events:
            raw_events = raw_events["events"]

        if not isinstance(raw_events, list):
            st.error("JSON file must contain a list of events.")
            st.stop()

        if not raw_events:
            st.error("Uploaded file contains no events.")
            st.stop()

        st.sidebar.success("Custom event file loaded.")

    except json.JSONDecodeError:
        st.error("Invalid JSON file. Please upload valid JSON.")
        st.stop()

else:

    raw_events = load_sample_events()

    st.sidebar.info(
        "Using built-in sample security events."
    )


# --------------------------------------------------
# PROCESS EVENTS
# --------------------------------------------------

try:

    results = run_pipeline(raw_events)

except (ValueError, KeyError, TypeError) as error:

    st.error(f"Event processing failed: {error}")
    st.stop()

except Exception as error:

    st.error(f"Unexpected processing error: {error}")
    st.stop()


events = results["events"]
detections = results["detections"]
incidents = results["incidents"]
investigations = results["investigations"]
stats = results["statistics"]


# --------------------------------------------------
# SECURITY OVERVIEW
# --------------------------------------------------

st.header("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    stats["total_events"]
)

col2.metric(
    "Detections",
    stats["total_detections"]
)

col3.metric(
    "Incidents",
    stats["total_incidents"]
)

critical_count = sum(
    1
    for incident in incidents
    if incident["severity"] == "critical"
)

col4.metric(
    "Critical Incidents",
    critical_count
)


st.divider()


# --------------------------------------------------
# SECURITY EVENTS
# --------------------------------------------------

st.header("Security Events")

event_df = pd.DataFrame(events)

st.dataframe(
    event_df.drop(
        columns=["raw_event"],
        errors="ignore"
    ),
    width="stretch",
    hide_index=True
)


st.divider()


# --------------------------------------------------
# SECURITY DETECTIONS
# --------------------------------------------------

st.header("Security Detections")

if detections:

    detection_data = [
        {
            "Detection": item["name"],
            "Severity": item["severity"].upper(),
            "Reason": item["reason"],
            "MITRE Technique": item["mitre"],
            "Detection ID": item["detection_id"]
        }
        for item in detections
    ]

    detection_df = pd.DataFrame(detection_data)

    st.dataframe(
        detection_df,
        width="stretch",
        hide_index=True
    )

    st.download_button(
        "Download Detection Report",
        data=detection_df.to_csv(index=False),
        file_name="sentinelx_detections.csv",
        mime="text/csv"
    )

else:

    st.success("No suspicious activities detected.")


st.divider()


# --------------------------------------------------
# INCIDENT MANAGEMENT
# --------------------------------------------------

st.header("Incident Management")

if incidents:

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:

        severity_options = sorted({
            incident["severity"].upper()
            for incident in incidents
        })

        selected_severity = st.multiselect(
            "Filter by severity",
            severity_options,
            default=severity_options
        )

    with filter_col2:

        host_options = sorted({
            incident["host"]
            for incident in incidents
        })

        selected_hosts = st.multiselect(
            "Filter by host",
            host_options,
            default=host_options
        )

    filtered_incidents = [
        incident
        for incident in incidents
        if incident["severity"].upper() in selected_severity
        and incident["host"] in selected_hosts
    ]

    for incident in filtered_incidents:

        with st.expander(
            f'{incident["severity"].upper()} | '
            f'{incident["host"]} | '
            f'{incident["incident_id"][:8]}'
        ):

            st.write(incident["summary"])

            st.write(
                f'**Events:** {incident["event_count"]}'
            )

            st.write(
                f'**Detections:** {incident["detection_count"]}'
            )

            st.write(
                f'**MITRE Techniques:** '
                f'{", ".join(incident["mitre_techniques"])}'
            )

            st.write(
                f'**Start:** {incident["start_time"]}'
            )

            st.write(
                f'**End:** {incident["end_time"]}'
            )

    incident_df = pd.DataFrame([
        {
            "Incident ID": item["incident_id"],
            "Host": item["host"],
            "Severity": item["severity"],
            "Event Count": item["event_count"],
            "Detection Count": item["detection_count"],
            "MITRE Techniques": ", ".join(
                item["mitre_techniques"]
            ),
            "Summary": item["summary"]
        }
        for item in filtered_incidents
    ])

    st.download_button(
        "Download Incident Report",
        data=incident_df.to_csv(index=False),
        file_name="sentinelx_incidents.csv",
        mime="text/csv"
    )

else:

    st.success("No security incidents generated.")


st.divider()


# --------------------------------------------------
# INVESTIGATION WORKSPACE
# --------------------------------------------------

st.header("Investigation Workspace")

if investigations:

    selected_incident = st.selectbox(
        "Select an incident",
        options=range(len(investigations)),
        format_func=lambda index: (
            f'{investigations[index]["host"]} | '
            f'{investigations[index]["severity"].upper()} | '
            f'{investigations[index]["incident_id"][:8]}'
        )
    )

    investigation = investigations[selected_incident]

    fingerprint = incident_fingerprint(investigation)

    incident_id = str(investigation["incident_id"])

    # Retrieve saved investigation from Supabase

    try:

        saved_record = get_investigation(fingerprint)

    except Exception as error:

        st.error(
            "Could not retrieve investigation from Supabase."
        )

        st.exception(error)

        saved_record = None

    # Use database values if available.
    # Otherwise use the pipeline defaults.

    if saved_record:

        current_status = saved_record["status"]

        current_notes = saved_record.get(
            "analyst_notes",
            ""
        )

        st.success(
            "Saved investigation loaded from Supabase."
        )

    else:

        current_status = investigation.get(
            "investigation_status",
            "Pending Review"
        )

        current_notes = investigation.get(
            "analyst_note",
            ""
        )

        st.info(
            "No saved investigation found. "
            "Showing default investigation details."
        )

    # Ensure the selected status is one of the supported values.
    valid_statuses = [
        "Pending Review",
        "Under Investigation",
        "Resolved"
    ]

    if current_status not in valid_statuses:
        current_status = "Pending Review"

    st.write("### Incident Details")

    st.write(
        f'**Host:** {investigation["host"]}'
    )

    st.write(
        f'**Severity:** {investigation["severity"].upper()}'
    )

    st.write(
        f'**Incident ID:** {incident_id}'
    )

    st.divider()

    st.write("### Investigation Details")

    with st.form(
        key=f"investigation_form_{fingerprint}"
    ):

        selected_status = st.selectbox(
            "Investigation Status",
            options=[
                "Pending Review",
                "Under Investigation",
                "Resolved"
            ],
            index=valid_statuses.index(current_status)
        )

        analyst_notes = st.text_area(
            "Analyst Notes",
            value=current_notes,
            height=150,
            placeholder=(
                "Enter investigation observations, "
                "findings and actions taken..."
            )
        )

        save_button = st.form_submit_button(
            "Save Investigation Changes",
            type="primary"
        )

    if save_button:

        try:

            save_investigation(
                fingerprint=fingerprint,
                incident_id=incident_id,
                status=selected_status,
                analyst_notes=analyst_notes
            )

            st.success(
                "Investigation successfully saved to Supabase!"
            )

            st.rerun()

        except Exception as error:

            st.error(
                "Unable to save investigation."
            )

            st.exception(error)

    st.divider()

    # Display current saved information

    st.write("### Current Investigation Status")

    st.write(f"**Status:** {current_status}")

    st.write("**Analyst Notes:**")

    st.write(
        current_notes if current_notes else "No notes added yet."
    )

    st.divider()

    # Investigation timeline

    st.write("### Investigation Timeline")

    timeline_df = pd.DataFrame(
        investigation["timeline"]
    )

    st.dataframe(
        timeline_df,
        width="stretch",
        hide_index=True
    )

    st.download_button(
        "Download Investigation Timeline",
        data=timeline_df.to_csv(index=False),
        file_name="sentinelx_investigation.csv",
        mime="text/csv"
    )

else:

    st.info("No investigation timeline available.")


# --------------------------------------------------
# EXPORT COMPLETE ANALYSIS
# --------------------------------------------------

complete_report = json.dumps(
    {
        "statistics": stats,
        "detections": detections,
        "incidents": incidents,
        "investigations": investigations
    },
    indent=4,
    default=str
)

st.header("Export Analysis")

st.download_button(
    "Download Complete Security Analysis (JSON)",
    data=complete_report,
    file_name="sentinelx_complete_report.json",
    mime="application/json"
)


st.divider()


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.caption(
    "SENTINELX | Academic Cybersecurity Project | "
    "Automated analysis of security event data"
)

import json
import hashlib
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinelx.pipeline import run_pipeline
from sentinelx.storage import (
    get_investigation,
    save_investigation
)