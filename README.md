
# SENTINELX

## Behavioral Threat Detection, Event Correlation and Incident Investigation Platform

### Project Overview

SENTINELX is a Python-based cybersecurity monitoring and incident investigation prototype designed to identify suspicious activities, correlate security events, prioritize incidents and support security analysts during investigations.

The platform processes structured security event logs, applies rule-based threat detection, maps detected activities to MITRE ATT&CK techniques and presents the results through an interactive Streamlit dashboard.

It also integrates Supabase to persist investigation statuses and analyst notes.

### Key Features

1. Security Event Normalization and Validation
2. Repeated Login Failure Detection
3. Failed Login Followed by Successful Login Detection
4. Possible Port Scanning Detection
5. Account Creation Monitoring
6. Privilege Change Detection
7. Security Incident Correlation
8. Incident Severity Classification and Prioritization
9. MITRE ATT&CK Technique Mapping
10. Chronological Investigation Timeline
11. Interactive Security Monitoring Dashboard
12. Incident Filtering and Analysis
13. Investigation Status Management
14. Analyst Notes Management
15. Supabase-Based Investigation Persistence
16. CSV and JSON Report Exports
17. Automated Unit Testing

### Technology Stack

- Python
- Streamlit
- Pandas
- JSON
- Supabase
- PostgreSQL
- MITRE ATT&CK Framework
- Git and GitHub

### Project Structure

```text
SENTINELX/
├── app.py
├── README.md
├── requirements.txt
├── PROJECT_REPORT.md
├── .gitignore
├── .streamlit/
│   └── secrets.toml
├── data/
│   └── sample_events.json
├── sentinelx/
│   ├── __init__.py
│   ├── schema.py
│   ├── detection.py
│   ├── correlation.py
│   ├── investigation.py
│   ├── pipeline.py
│   └── storage.py
└── tests/
    ├── test_pipeline.py
    ├── test_schema.py
    ├── test_detection.py
    └── test_supabase.py
```

### Installation

Clone the repository:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SENTINELX
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Supabase Configuration

SENTINELX uses Supabase to store investigation records.

Create a Supabase project and configure the following environment secrets in:

`.streamlit/secrets.toml`

```toml
SUPABASE_URL = "YOUR_SUPABASE_PROJECT_URL"
SUPABASE_KEY = "YOUR_SUPABASE_SECRET_KEY"
```

Do not commit this file or expose your Supabase credentials publicly.

Create the investigations table in the Supabase SQL Editor:

```sql
CREATE TABLE public.investigations (
    incident_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'Pending Review',
    analyst_notes TEXT DEFAULT '',
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    fingerprint TEXT UNIQUE
);

ALTER TABLE public.investigations
ENABLE ROW LEVEL SECURITY;
```

Configure appropriate Row Level Security policies before deploying the application for multi-user or public access.

### Run the Application

```bash
python -m streamlit run app.py
```

Open the local URL displayed in the terminal.

### Running Tests

Run the automated test suite:

```bash
python -m unittest discover -s tests -v
```

The current test suite contains 23 automated tests covering event normalization, threat detection, incident generation and investigation timelines.

### Current Implementation

The current prototype processes synthetic security event logs in JSON format.

It demonstrates:

- Automated rule-based threat detection.
- Security event correlation.
- Incident severity prioritization.
- MITRE ATT&CK technique mapping.
- Chronological investigation timelines.
- Analyst-controlled investigation statuses.
- Persistent investigation notes using Supabase.
- Security analysis and report exports.

### Limitations

- The current implementation uses synthetic security event data.
- It does not directly integrate with live Microsoft Sentinel or other SIEM infrastructure.
- Detection is based on predefined rules rather than machine learning.
- Detection results require human review before an incident can be confirmed as malicious.
- The prototype is intended for demonstration and educational purposes, not production security monitoring.

### Future Enhancements

- Live SIEM integration.
- Real-time security event ingestion.
- Advanced behavioral analytics.
- Machine learning-based anomaly detection.
- Multi-user analyst access and authentication.
- Advanced incident investigation and reporting.

### Project Status

Developed as a cybersecurity monitoring and incident investigation prototype.
