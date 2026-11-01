
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinelx.pipeline import run_pipeline


st.set_page_config(
    page_title="SENTINELX | Security Operations",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ SENTINELX")
st.subheader(
    "Behavioral Threat Detection and Incident Investigation Platform"
)

st.caption("Security Monitoring | Event Correlation | Incident Analysis")

st.divider()


@st.cache_data
def load_sample_events():
    file_path = (
        Path(__file__).parent
        / "data"
        / "sample_events.json"
    )

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


try:
    raw_events = load_sample_events()
    results = run_pipeline(raw_events)

except Exception as error:
    st.error(f"Unable to process security events: {error}")
    st.stop()


stats = results["statistics"]
detections = results["detections"]
incidents = results["incidents"]
investigations = results["investigations"]


st.header("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", stats["total_events"])
col2.metric("Detections", stats["total_detections"])
col3.metric("Incidents", stats["total_incidents"])

critical_count = sum(
    1 for item in incidents
    if item["severity"] == "critical"
)

col4.metric("Critical Incidents", critical_count)


st.divider()

st.header("Security Detections")

if detections:
    detection_data = [
        {
            "Detection": item["name"],
            "Severity": item["severity"].upper(),
            "Reason": item["reason"],
            "MITRE Technique": item["mitre"]
        }
        for item in detections
    ]

    st.dataframe(
        pd.DataFrame(detection_data),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No security detections found.")


st.divider()

st.header("Incident Management")

if incidents:
    for incident in incidents:
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
else:
    st.info("No incidents generated.")


st.divider()

st.header("Investigation Timeline")

if investigations:
    selected_incident = st.selectbox(
        "Select an incident",
        options=range(len(investigations)),
        format_func=lambda index: (
            f'{investigations[index]["host"]} | '
            f'{investigations[index]["severity"].upper()}'
        )
    )

    investigation = investigations[selected_incident]

    st.write(investigation["analyst_note"])

    timeline_data = investigation["timeline"]

    if timeline_data:
        st.dataframe(
            pd.DataFrame(timeline_data),
            use_container_width=True,
            hide_index=True
        )
else:
    st.info("No investigation timeline available.")


st.divider()

st.caption(
    "SENTINELX | Academic Cybersecurity Project | "
    "Synthetic sample security events"
)
