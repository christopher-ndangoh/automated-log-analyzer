#!/usr/bin/env python3
"""
Automated Log Analysis & Security Incident Triage Script
Author: UMGC Cyber Team Member
Description: Parses raw web server logs to programmatically flag malicious
             brute-force attempts and suspicious unauthorized system access.
"""

import os
import re
from datetime import datetime

# Production-grade mock data simulating server access logs
MOCK_LOGS = """
192.168.1.10 - - [10/Nov/2026:14:32:10] "GET /index.html HTTP/1.1" 200 4324
10.0.0.45 - - [10/Nov/2026:14:33:15] "POST /login.php HTTP/1.1" 401 512
198.51.100.12 - - [10/Nov/2026:14:35:22] "POST /admin/login.php HTTP/1.1" 401 324
198.51.100.12 - - [10/Nov/2026:14:35:25] "POST /admin/login.php HTTP/1.1" 401 324
192.168.1.15 - - [10/Nov/2026:14:36:01] "GET /images/logo.png HTTP/1.1" 200 12043
198.51.100.12 - - [10/Nov/2026:14:36:12] "POST /admin/login.php HTTP/1.1" 401 324
203.0.113.88 - - [10/Nov/2026:14:40:00] "GET /secret_file.txt HTTP/1.1" 403 210
198.51.100.12 - - [10/Nov/2026:14:41:00] "GET /admin/dashboard.php HTTP/1.1" 200 5400
"""

LOG_FILE = "server_access.log"
REPORT_FILE = "security_alert_report.txt"

def initialize_environment():
    """Generates localized sample production logs for analysis."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write(MOCK_LOGS.strip())
        print(f"[+] Initialized live tracking log file: {LOG_FILE}")

def run_log_analysis():
    """Parses target logs using structured regex to isolate brute-force vectors."""
    print(f"[*] Extracting forensic indicators from {LOG_FILE}...")

    # Standard Apache/Nginx Access Log Regex Pattern
    log_pattern = re.compile(
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[(?P<date>.*?)\] '
        r'"(?P<method>\w+) (?P<url>.*?) HTTP/.*?" (?P<status>\d{3})'
    )

    security_alerts = []
    failed_login_matrix = {}
    brute_force_threshold = 3

    with open(LOG_FILE, "r") as src:
        for line in src:
            match = log_pattern.search(line)
            if not match:
                continue

            data = match.groupdict()
            ip_address = data["ip"]
            http_status = data["status"]
            requested_url = data["url"]
            timestamp = data["date"]

            # Triage Rule 1: Flag Unauthorized (401) and Forbidden (403) events
            if http_status in ["401", "403"]:
                alert_entry = (
                    f"[ALERT] Audit Failure -> Source IP: {ip_address} | "
                    f"Status: {http_status} | Target: {requested_url} | Time: {timestamp}\n"
                )
                security_alerts.append(alert_entry)

                # Triage Rule 2: Track structural indicators of brute-force vectors
                if "login" in requested_url and http_status == "401":
                    failed_login_matrix[ip_address] = failed_login_matrix.get(ip_address, 0) + 1

    # Evaluate compiled threshold metrics
    for ip, failure_count in failed_login_matrix.items():
        if failure_count >= brute_force_threshold:
            critical_alert = (
                f"[CRITICAL] Threat Detected -> Active Brute Force Vector from IP: {ip} "
                f"({failure_count} concurrent auth failures logged)\n"
            )
            security_alerts.insert(0, critical_alert) # Push critical items to top of file

    # Output alert matrix to Tier 1 Triage file
    if security_alerts:
        with open(REPORT_FILE, "w") as out:
            out.write(f"=== SOC ALERT TRIAGE REPORT - GENERATED {datetime.now()} ===\n\n")
            out.writelines(security_alerts)
        print(f"[+] Security analysis complete. Alerts exported to: {REPORT_FILE}")
    else:
        print("[+] Log parsing complete. Zero indicators of compromise detected.")

if __name__ == "__main__":
    initialize_environment()
    run_log_analysis()
