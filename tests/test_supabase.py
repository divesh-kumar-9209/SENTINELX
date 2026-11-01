import streamlit as st
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sentinelx.storage import (
    save_investigation,
    get_investigation
)

st.title("SENTINELX Database Storage Test")

if st.button("Save Test Investigation"):

    try:
        result = save_investigation(
            incident_id="TEST-001",
            status="Under Investigation",
            analyst_notes="Testing Supabase data storage."
        )

        st.success("Investigation saved successfully!")
        st.json(result)

    except Exception as error:
        st.error("Could not save investigation.")
        st.exception(error)


if st.button("Retrieve Test Investigation"):

    try:
        result = get_investigation("TEST-001")

        if result:
            st.success("Investigation retrieved successfully!")
            st.json(result)
        else:
            st.warning("No investigation found.")

    except Exception as error:
        st.error("Could not retrieve investigation.")
        st.exception(error)