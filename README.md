# Automated Log Analysis & Threat Detection Engine

An automated Python script engineered to ingest, parse, and triage web server authentication events (Apache/Nginx logs) to accelerate incident response tasks for Security Operations Centers (SOC).

## Technical Overview
* **Language:** Python 3
* **Libraries:** Native `os`, `re` (Regular Expressions), `datetime`
* **Log Standardization:** RegEx-parsed tokenization mapped to IP addresses, HTTP verbs, uniform resource identifiers (URIs), and HTTP response codes.

## Security Capabilities Implemented
1. **Anomaly Exposure:** Scans ingested entries for unauthorized `401` access restrictions or administrative directory privilege bypass attempts (`403`).
2. **Correlation Tracking:** Groups concurrent auth requests dynamically by unique source hosts.
3. **Threshold Violations:** Triggers prioritized `[CRITICAL]` behavioral indicator alerts when any distinct endpoint triggers 3+ authentication validation errors on critical directory paths.

## Output Generation
The script exports parsed alerts directly into a clean, triage-ready text file (`security_alert_report.txt`) to simulate high-priority log ingestion workflows used by SIEM or automated SOAR orchestration engines.
