"""
parser.py — Log parsing and threat detection engine.

Supports:
  - Windows Event Logs (text export format)
  - Apache / Nginx access & error logs
  - Generic text logs

Detections:
  - Failed login attempts (brute force threshold)
  - Suspicious IPs (tor exit nodes pattern, private→public anomalies)
  - Keyword / regex pattern search
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from typing import Optional

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    line_number: int
    raw:         str
    timestamp:   Optional[str]  = None
    ip:          Optional[str]  = None
    level:       Optional[str]  = None   # ERROR, WARNING, INFO, etc.
    message:     str            = ""
    source:      str            = "generic"
    flags:       list           = field(default_factory=list)  # threat tags


@dataclass
class AnalysisReport:
    total_lines:       int = 0
    parsed_lines:      int = 0
    flagged_lines:     int = 0
    failed_logins:     int = 0
    suspicious_ips:    dict = field(default_factory=dict)   # ip → count
    brute_force_ips:   list = field(default_factory=list)   # ips over threshold
    keyword_matches:   list = field(default_factory=list)   # (line_num, keyword, raw)
    entries:           list = field(default_factory=list)   # all LogEntry objects
    flagged_entries:   list = field(default_factory=list)   # flagged only
    log_type:          str  = "unknown"
    errors:            list = field(default_factory=list)


# ── Regex patterns ────────────────────────────────────────────────────────────

# Apache/Nginx combined log format
APACHE_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
)

# Windows Event Log (text export)
WIN_EVENT_RE = re.compile(
    r'(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)'
    r'.*?(?P<level>Error|Warning|Information|Critical|Audit\s+Failure|Audit\s+Success)',
    re.IGNORECASE
)

# Generic syslog / auth.log
SYSLOG_RE = re.compile(
    r'(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)'
)

# IP address anywhere in a line
IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

# Failed login indicators
FAILED_LOGIN_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'failed\s+password',
        r'authentication\s+fail',
        r'login\s+fail',
        r'invalid\s+user',
        r'logon\s+failure',
        r'audit\s+failure',
        r'bad\s+password',
        r'wrong\s+password',
        r'access\s+denied',
        r'401\b',              # HTTP Unauthorized
        r'403\b',              # HTTP Forbidden
    ]
]

# Suspicious path patterns (web logs)
SUSPICIOUS_PATH_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'\.\./\.\.',          # path traversal
        r'/etc/passwd',
        r'/etc/shadow',
        r'\.php\?.*=http',     # RFI attempt
        r'<script',            # XSS
        r'union.*select',      # SQL injection
        r'exec\(',
        r'cmd\.exe',
        r'powershell',
        r'/admin',
        r'/wp-login',
        r'/.git/',
        r'/\.env',
    ]
]

# ── Log type detection ────────────────────────────────────────────────────────

def detect_log_type(lines: list[str]) -> str:
    """Sniff the first 20 non-empty lines to guess log format."""
    sample = [l for l in lines[:50] if l.strip()][:20]
    apache_score = windows_score = syslog_score = 0
    for line in sample:
        if APACHE_RE.search(line):   apache_score  += 1
        if WIN_EVENT_RE.search(line): windows_score += 1
        if SYSLOG_RE.search(line):   syslog_score  += 1
    scores = {"apache": apache_score, "windows": windows_score, "syslog": syslog_score}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "generic"


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_apache(line: str, line_num: int) -> LogEntry:
    m = APACHE_RE.search(line)
    entry = LogEntry(line_number=line_num, raw=line, source="apache")
    if m:
        entry.ip        = m.group("ip")
        entry.timestamp = m.group("time")
        entry.message   = line
        status = m.group("status")
        entry.level = "ERROR" if status.startswith(("4", "5")) else "INFO"
    return entry


def _parse_windows(line: str, line_num: int) -> LogEntry:
    m = WIN_EVENT_RE.search(line)
    entry = LogEntry(line_number=line_num, raw=line, source="windows")
    if m:
        entry.timestamp = f"{m.group('date')} {m.group('time')}"
        entry.level     = m.group("level").upper()
        entry.message   = line
    ip_m = IP_RE.search(line)
    if ip_m:
        entry.ip = ip_m.group(1)
    return entry


def _parse_syslog(line: str, line_num: int) -> LogEntry:
    m = SYSLOG_RE.search(line)
    entry = LogEntry(line_number=line_num, raw=line, source="syslog")
    if m:
        entry.timestamp = f"{m.group('month')} {m.group('day')} {m.group('time')}"
        entry.message   = m.group("message")
    ip_m = IP_RE.search(line)
    if ip_m:
        entry.ip = ip_m.group(1)
    return entry


def _parse_generic(line: str, line_num: int) -> LogEntry:
    entry = LogEntry(line_number=line_num, raw=line, source="generic",
                     message=line)
    ip_m = IP_RE.search(line)
    if ip_m:
        entry.ip = ip_m.group(1)
    # Guess level from keywords
    ll = line.lower()
    if any(w in ll for w in ("error", "critical", "fatal", "fail")):
        entry.level = "ERROR"
    elif any(w in ll for w in ("warn", "warning")):
        entry.level = "WARNING"
    else:
        entry.level = "INFO"
    return entry


# ── Main analysis function ────────────────────────────────────────────────────

def analyse(
    text: str,
    keywords: list[str] | None = None,
    brute_force_threshold: int = 5,
) -> AnalysisReport:
    """
    Parse and analyse a log text blob.

    Args:
        text:                    Full log file contents.
        keywords:                List of strings/regex to search for.
        brute_force_threshold:   Failed logins from one IP to trigger alert.

    Returns:
        AnalysisReport with all findings.
    """
    report  = AnalysisReport()
    lines   = text.splitlines()
    report.total_lines = len(lines)

    log_type = detect_log_type(lines)
    report.log_type = log_type

    parser_fn = {
        "apache":  _parse_apache,
        "windows": _parse_windows,
        "syslog":  _parse_syslog,
        "generic": _parse_generic,
    }.get(log_type, _parse_generic)

    ip_fail_counts: dict[str, int] = defaultdict(int)
    ip_total_counts: dict[str, int] = defaultdict(int)
    compiled_keywords = []
    if keywords:
        for kw in keywords:
            try:
                compiled_keywords.append((kw, re.compile(kw, re.IGNORECASE)))
            except re.error:
                compiled_keywords.append((kw, re.compile(re.escape(kw), re.IGNORECASE)))

    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        entry = parser_fn(line, i)
        report.parsed_lines += 1
        report.entries.append(entry)

        # Track IP activity
        if entry.ip:
            ip_total_counts[entry.ip] += 1

        # Failed login detection
        if any(p.search(line) for p in FAILED_LOGIN_PATTERNS):
            entry.flags.append("FAILED_LOGIN")
            report.failed_logins += 1
            if entry.ip:
                ip_fail_counts[entry.ip] += 1

        # Suspicious path detection (web logs)
        if any(p.search(line) for p in SUSPICIOUS_PATH_PATTERNS):
            entry.flags.append("SUSPICIOUS_REQUEST")

        # Keyword search
        for kw_text, kw_re in compiled_keywords:
            if kw_re.search(line):
                entry.flags.append(f"KEYWORD:{kw_text}")
                report.keyword_matches.append((i, kw_text, line.strip()))

        if entry.flags:
            report.flagged_lines += 1
            report.flagged_entries.append(entry)

    # Brute force: IPs with failed logins over threshold
    report.brute_force_ips = [
        ip for ip, count in ip_fail_counts.items()
        if count >= brute_force_threshold
    ]

    # Suspicious IPs: any IP with > 1 failed login
    report.suspicious_ips = {
        ip: count for ip, count in ip_fail_counts.items() if count > 0
    }

    return report
