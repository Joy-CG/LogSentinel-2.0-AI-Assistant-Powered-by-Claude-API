"""
alerter.py — Email alerts for critical findings via SMTP.

Supports Gmail (app passwords), Outlook, and generic SMTP.
Config stored in alert_config.json (never store plain passwords in code).
"""

import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from parser import AnalysisReport

CONFIG_FILE = "alert_config.json"


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "enabled":   False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username":  "",
        "password":  "",
        "from_addr": "",
        "to_addr":   "",
    }


def save_config(config: dict) -> None:
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def send_alert(report: AnalysisReport, config: dict) -> tuple[bool, str]:
    """
    Send an email alert summarising critical findings.
    Returns (success: bool, message: str).
    """
    if not config.get("enabled"):
        return False, "Email alerts are disabled."

    required = ["smtp_host", "smtp_port", "username", "password", "from_addr", "to_addr"]
    for field in required:
        if not config.get(field):
            return False, f"Missing config field: {field}"

    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subj  = f"[LogSentinel] {len(report.brute_force_ips)} brute force IP(s) detected — {now}"

    body_lines = [
        f"LogSentinel Alert — {now}",
        "=" * 50,
        "",
        "THREAT SUMMARY",
        f"  Flagged events   : {report.flagged_lines}",
        f"  Failed logins    : {report.failed_logins}",
        f"  Suspicious IPs   : {len(report.suspicious_ips)}",
        f"  Brute force IPs  : {len(report.brute_force_ips)}",
        f"  Keyword matches  : {len(report.keyword_matches)}",
        "",
    ]

    if report.brute_force_ips:
        body_lines += ["BRUTE FORCE ALERTS", "-" * 30]
        for ip in report.brute_force_ips:
            count = report.suspicious_ips.get(ip, "?")
            body_lines.append(f"  [!] {ip}  —  {count} failed attempts")
        body_lines.append("")

    if report.suspicious_ips:
        body_lines += ["ALL SUSPICIOUS IPs", "-" * 30]
        for ip, count in sorted(report.suspicious_ips.items(),
                                key=lambda x: x[1], reverse=True):
            body_lines.append(f"  {ip:<20} {count} failed attempt(s)")
        body_lines.append("")

    body = "\n".join(body_lines)

    try:
        msg = MIMEMultipart()
        msg["From"]    = config["from_addr"]
        msg["To"]      = config["to_addr"]
        msg["Subject"] = subj
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(config["smtp_host"], int(config["smtp_port"])) as server:
            server.ehlo()
            server.starttls()
            server.login(config["username"], config["password"])
            server.sendmail(config["from_addr"], config["to_addr"], msg.as_string())

        return True, f"Alert sent to {config['to_addr']}"
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed. Check username/password.\nFor Gmail use an App Password, not your main password."
    except Exception as e:
        return False, f"Failed to send email: {e}"
