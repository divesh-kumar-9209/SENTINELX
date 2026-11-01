
# SENTINELX
## Behavioral Threat Detection, Event Correlation and Incident Investigation Platform

### 1. Abstract

SENTINELX is a Python-based cybersecurity monitoring prototype designed to identify suspicious activities through security event analysis. The platform uses predefined detection rules to identify potentially malicious behaviour, correlates related detections into incidents and generates chronological investigation timelines.

A Streamlit dashboard provides a visual interface for monitoring events, reviewing detections and examining incidents.

### 2. Introduction

Modern organisations generate large volumes of security logs from computers, servers and network devices. Analysing these logs manually can be time-consuming and may make it difficult to identify suspicious patterns.

SENTINELX addresses this challenge through automated event normalization, rule-based threat detection, event correlation and incident investigation.

### 3. Objectives

1. To normalize security event data into a consistent format.
2. To identify suspicious authentication activities.
3. To detect possible network port scanning.
4. To monitor account creation and privilege changes.
5. To correlate related detections into security incidents.
6. To generate chronological investigation timelines.
7. To provide a dashboard for security monitoring.

### 4. Technologies Used

Python: Core programming language.

Streamlit: Interactive dashboard development.

Pandas: Tabular data presentation.

JSON: Security event storage and input.

MITRE ATT&CK: Mapping detected activities to relevant adversary techniques.

### 5. System Architecture

The platform follows a modular processing pipeline:

1. Security Event Input
2. Event Normalization
3. Rule-Based Threat Detection
4. Detection Correlation
5. Incident Generation
6. Investigation Timeline
7. Streamlit Dashboard

### 6. Detection Rules

The prototype implements five detection categories:

1. Repeated Login Failures: Identifies five or more failed authentication attempts within five minutes for the same user, source IP and host.

2. Failed Logins Followed by Success: Identifies multiple failed login attempts followed by a successful login within ten minutes.

3. Possible Port Scanning: Identifies a source IP contacting eight or more distinct destination ports on the same host.

4. New Account Creation: Identifies account creation events.

5. Privilege Change Detection: Identifies privilege or role change events.

### 7. Incident Correlation

The correlation module groups detections associated with the same host into security incidents. It consolidates event identifiers, detection identifiers, severity levels and MITRE ATT&CK technique references.

The incident severity is determined by the highest severity among its associated detections.

### 8. Investigation Module

The investigation module generates a chronological timeline of events associated with each incident.

It displays timestamps, event identifiers, event types, usernames, source IP addresses, descriptions and severity levels.

Automated findings are presented for analyst review rather than being treated as confirmed malicious activity.

### 9. Results

The prototype was tested using 16 synthetic security events.

Observed results:

- Total events processed: 16
- Total detections generated: 5
- Total incidents generated: 2
- Critical incidents: 1

The dashboard successfully displayed security detections, incident information and investigation timelines.

### 10. Limitations

1. The current implementation uses synthetic security events.
2. It does not collect live endpoint or network telemetry.
3. It does not have a live Microsoft Sentinel or Azure integration.
4. Detection is based on predefined rules rather than machine learning.
5. Automated findings require manual analyst verification.

### 11. Future Scope

1. Integration with Microsoft Sentinel and Azure Log Analytics.
2. Real-time security event ingestion.
3. Machine learning-based behavioural anomaly detection.
4. User and entity behaviour analytics.
5. Automated incident response capabilities.
6. Advanced threat intelligence integration.

### 12. Conclusion

SENTINELX demonstrates how security event normalization, rule-based threat detection, incident correlation and investigation timelines can be combined into a unified monitoring prototype.

The project provides a foundation for developing a more advanced Security Operations Centre monitoring platform.
