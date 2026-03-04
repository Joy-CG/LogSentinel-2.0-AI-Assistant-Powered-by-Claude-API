# 🛡️ LogSentinel 2.0 — AI-Powered Log Analyzer & Threat Detection

A desktop log analyzer built with Python and Tkinter featuring an AI-powered SOC triage assistant using the Claude API. Designed as a cybersecurity portfolio project covering threat detection, MITRE ATT&CK mapping, GeoIP analysis, and log forensics.

---

## Features

-  **Multi-format support** — Apache/Nginx, Windows Event Logs, syslog, generic text logs
-  **AI Triage Assistant** — Claude-powered SOC chatbot that analyzes alerts, maps to MITRE ATT&CK, and walks through triage steps
-  **Failed login detection** — flags authentication failures across all log types
-  **IP threat reporting** — tracks failed attempts per IP, flags brute force attackers
-  **GeoIP lookup** — resolves country, city, and ISP for every suspicious IP
-  **IP whitelist / blacklist** — persistent lists that tag IPs across all reports
-  **Keyword / regex search** — search for any term or pattern across the entire log
-  **Live log monitoring** — real-time tail -f style monitoring with color-coded alerts
-  **SIEM-style dashboard** — stat cards, bar charts, and threat timeline
-  **Email alerts** — sends SMTP email reports on critical findings
-  **Export reports** — save findings as `.txt` or `.csv`

---

## Setup

No external dependencies — uses Python standard library only.

```bash
python main.py
```

To use the AI Triage Assistant, get a free API key at **console.anthropic.com** and enter it via the `[ API KEY ]` button in the triage tab.

---

## AI Triage Assistant

The AI Triage tab lets you paste any raw alert or log line and get back a full SOC-style analysis including:

| Output | Description |
|---|---|
| Threat Classification | What type of attack or event this is |
| Severity Rating | CRITICAL / HIGH / MEDIUM / LOW with justification |
| Triage Steps | Step-by-step investigation walkthrough |
| Recommended Actions | Block IP, escalate, investigate host, etc. |
| MITRE ATT&CK Mapping | Technique IDs e.g. T1110 - Brute Force |
| False Positive Check | Indicators that could make this benign |

Supports multi-turn conversation — ask follow-up questions and it remembers context. Use **From Report** to automatically load your latest analysis findings into the triage input.

---

## Dashboard

The SIEM-style dashboard shows:

| Widget | Description |
|---|---|
| Stat cards | Flagged events, brute force IPs, failed auth, suspicious IPs, keyword hits |
| Top Threat IPs | Horizontal bar chart of most active threat IPs |
| Event Breakdown | Bar chart of threat types |
| Threat Timeline | Line chart of flagged events across the log |

---

## Detection Capabilities

| Threat | Method |
|---|---|
| Brute force login | Counts failed logins per IP, alerts over threshold |
| Failed authentication | Regex: "Failed password", "Audit Failure", HTTP 401 etc. |
| Path traversal | Detects `../../` patterns in web logs |
| SQL injection | Detects `UNION SELECT` and similar patterns |
| XSS attempts | Detects `<script>` in request paths |
| Sensitive file access | Flags `.env`, `.git`, `/etc/passwd` requests |
| Admin probing | Flags `/admin`, `/wp-login` scans |

---

## Email Alerts

Click **EMAIL CONFIG** in the top bar to configure SMTP settings.

- Works with Gmail, Outlook, or any SMTP server
- For Gmail: generate an **App Password** at myaccount.google.com/apppasswords
- Click **[ SEND ALERT ]** after running an analysis to fire off a report

---

## File Structure

```
LogSentinel2.0/
├── main.py          # Entry point
├── parser.py        # Log parsing and threat detection engine
├── ui.py            # Tkinter GUI
├── triage.py        # AI triage assistant (Claude API)
├── geoip.py         # GeoIP lookup via ip-api.com
├── iplist.py        # Whitelist / blacklist management
├── alerter.py       # Email alert system
├── exporter.py      # TXT and CSV report export
├── sample.log       # Sample log with planted threats for testing
└── README.md
```

---
