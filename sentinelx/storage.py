import streamlit as st
from supabase import create_client
from datetime import datetime, timezone


VALID_STATUSES = [
    "Pending Review",
    "Under Investigation",
    "Resolved"
]


def get_supabase_client():
    """Create a connection to Supabase."""

    try:
        supabase_url = st.secrets["SUPABASE_URL"]
        supabase_key = st.secrets["SUPABASE_KEY"]

        return create_client(
            supabase_url,
            supabase_key
        )

    except Exception as error:
        raise RuntimeError(
            f"Supabase connection failed: {error}"
        )


def get_investigation(fingerprint):
    """Retrieve investigation using its fingerprint."""

    client = get_supabase_client()

    response = (
        client.table("investigations")
        .select("*")
        .eq("fingerprint", fingerprint)
        .execute()
    )

    if response.data:
        return response.data[0]

    return None


def save_investigation(
    fingerprint,
    incident_id,
    status,
    analyst_notes
):
    """Save or update an investigation."""

    if status not in VALID_STATUSES:
        raise ValueError("Invalid investigation status.")

    client = get_supabase_client()

    record = {
        "fingerprint": fingerprint,
        "incident_id": str(incident_id),
        "status": status,
        "analyst_notes": analyst_notes,
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat()
    }

    response = (
        client.table("investigations")
        .upsert(
            record,
            on_conflict="fingerprint"
        )
        .execute()
    )

    return response.data[0] if response.data else record