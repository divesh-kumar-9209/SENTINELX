
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
# SENTINELX THEME-AWARE DESIGN SYSTEM
# --------------------------------------------------

st.markdown("""
<style>
/* Use Streamlit's active theme variables so both light and dark modes work. */
.stApp {
    background: var(--background-color);
    color: var(--text-color);
}

.block-container {
    max-width: 1550px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Typography */
h1 {
    font-weight: 800 !important;
    letter-spacing: -1px;
}

h2, h3 {
    color: var(--primary-color) !important;
    font-weight: 750 !important;
}

[data-testid="stCaptionContainer"] {
    opacity: 0.78;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: var(--secondary-background-color);
    border-right: 1px solid color-mix(in srgb, var(--text-color) 14%, transparent);
}

/* Top brand area */
.sentinel-brand {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 8px 0 18px 0;
}

.sentinel-brand-icon {
    font-size: 42px;
    line-height: 1;
}

.sentinel-brand-name {
    font-size: clamp(30px, 4vw, 42px);
    line-height: 1.1;
    font-weight: 850;
    letter-spacing: 1px;
    color: var(--text-color);
}

.sentinel-subtitle {
    color: var(--primary-color);
    font-size: clamp(18px, 2vw, 25px);
    font-weight: 750;
    line-height: 1.35;
    margin-top: 4px;
}

.sentinel-tagline {
    color: var(--text-color);
    opacity: 0.68;
    font-size: 13px;
    margin-top: 10px;
}

/* Security overview cards */
.metric-card {
    background: var(--secondary-background-color);
    color: var(--text-color);
    border: 1px solid color-mix(in srgb, var(--text-color) 15%, transparent);
    border-left: 4px solid var(--accent);
    border-radius: 14px;
    padding: 19px 20px;
    min-height: 145px;
    box-shadow: 0 5px 18px rgba(0, 0, 0, 0.07);
    transition: transform 160ms ease, box-shadow 160ms ease;
}

.metric-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 9px 24px rgba(0, 0, 0, 0.12);
}

.metric-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    color: var(--text-color);
    opacity: 0.76;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.8px;
}

.metric-icon {
    font-size: 21px;
    opacity: 1;
}

.metric-value {
    color: var(--text-color);
    font-size: 36px;
    font-weight: 850;
    line-height: 1.2;
    margin-top: 15px;
}

.metric-description {
    color: var(--text-color);
    opacity: 0.68;
    font-size: 12px;
    margin-top: 5px;
}

.metric-blue { --accent: #3b82f6; }
.metric-cyan { --accent: #06b6d4; }
.metric-purple { --accent: #8b5cf6; }
.metric-red { --accent: #ef4444; }

/* Expanders and containers */
[data-testid="stExpander"] {
    background: var(--secondary-background-color);
    border: 1px solid color-mix(in srgb, var(--text-color) 16%, transparent);
    border-radius: 11px;
}

[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 12px;
}

/* Buttons */
.stButton > button,
.stDownloadButton > button,
[data-testid="stFormSubmitButton"] > button {
    border-radius: 9px;
    font-weight: 650;
    transition: transform 150ms ease, box-shadow 150ms ease;
}

.stButton > button:hover,
.stDownloadButton > button:hover,
[data-testid="stFormSubmitButton"] > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 5px 14px rgba(0, 0, 0, 0.12);
}

/* Inputs retain active theme backgrounds and foregrounds. */
.stTextArea textarea,
.stTextInput input,
[data-baseweb="select"] > div {
    border-radius: 8px;
}

/* Tables */
[data-testid="stDataFrame"] {
    border: 1px solid color-mix(in srgb, var(--text-color) 15%, transparent);
    border-radius: 10px;
    overflow: hidden;
}

/* Dividers */
hr {
    border-color: color-mix(in srgb, var(--text-color) 18%, transparent) !important;
}

/* Status callouts */
[data-testid="stAlert"] {
    border-radius: 10px;
}

/* Footer */
.sentinel-footer {
    text-align: center;
    color: var(--text-color);
    opacity: 0.62;
    font-size: 12px;
    padding: 12px 0;
}

@media (max-width: 900px) {
    .block-container {
        padding-left: 1rem;
        padding-right: 1rem;
    }
    .metric-card {
        min-height: 125px;
        padding: 15px;
    }
    .metric-value {
        font-size: 30px;
    }
}
</style>
""", unsafe_allow_html=True)


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

st.markdown("""
<div class="sentinel-brand">
    <div class="sentinel-brand-icon">🛡️</div>
    <div class="sentinel-brand-name">SENTINELX</div>
</div>
<div class="sentinel-subtitle">
    Behavioral Threat Detection and Incident Investigation Platform
</div>
<div class="sentinel-tagline">
    SECURITY MONITORING&nbsp;&nbsp;|&nbsp;&nbsp;EVENT CORRELATION&nbsp;&nbsp;|&nbsp;&nbsp;INCIDENT ANALYSIS
</div>
""", unsafe_allow_html=True)

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

critical_count = sum(
    1
    for incident in incidents
    if incident["severity"] == "critical"
)

metric_columns = st.columns(4)

metric_cards = [
    ("TOTAL EVENTS", stats["total_events"], "📊", "All processed security events", "metric-blue"),
    ("DETECTIONS", stats["total_detections"], "🔍", "Suspicious activities identified", "metric-cyan"),
    ("INCIDENTS", stats["total_incidents"], "🚨", "Correlated security incidents", "metric-purple"),
    ("CRITICAL INCIDENTS", critical_count, "⚠️", "Require priority attention", "metric-red"),
]

for column, (label, value, symbol, description, style_class) in zip(metric_columns, metric_cards):
    with column:
        st.markdown(f"""
        <div class="metric-card {style_class}">
            <div class="metric-top">
                <span>{label}</span>
                <span class="metric-icon">{symbol}</span>
            </div>
            <div class="metric-value">{value}</div>
            <div class="metric-description">{description}</div>
        </div>
        """, unsafe_allow_html=True)


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

st.markdown("""
<div class="sentinel-footer">
    SENTINELX&nbsp; | &nbsp;Academic Cybersecurity Project&nbsp; | &nbsp;Automated analysis of security event data
</div>
""", unsafe_allow_html=True)
