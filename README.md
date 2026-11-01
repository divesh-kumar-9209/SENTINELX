
# SENTINELX

## Behavioral Threat Detection, Event Correlation and Incident Investigation Platform

### Project Overview

SENTINELX is a cybersecurity monitoring prototype designed to identify suspicious activities, correlate security events, prioritize incidents and support security investigations.

The platform uses Python-based detection rules and a Streamlit dashboard to present security information.

### Key Features

1. Security Event Normalization
2. Repeated Login Failure Detection
3. Failed Login Followed by Successful Login Detection
4. Possible Port Scanning Detection
5. Account Creation Monitoring
6. Privilege Change Detection
7. Security Incident Correlation
8. Chronological Investigation Timeline
9. MITRE ATT&CK Technique Mapping
10. Interactive Security Dashboard

### Technology Stack

- Python
- Streamlit
- Pandas
- JSON
- MITRE ATT&CK Framework

### Project Structure

```text
SENTINELX/
├── app.py
├── requirements.txt
├── data/
│   └── sample_events.json
└── sentinelx/
    ├── __init__.py
    ├── schema.py
    ├── detection.py
    ├── correlation.py
    ├── investigation.py
    └── pipeline.py
```

### Installation

```bash
pip install -r requirements.txt
```

### Run the Application

```bash
python -m streamlit run app.py
```

### Current Implementation

The current prototype processes synthetic security events and demonstrates automated detection, event correlation, incident prioritization and investigation timelines.

### Limitations

The current version does not connect to live security infrastructure or Microsoft Sentinel. Detection results require human review before an incident can be confirmed as malicious activity.
