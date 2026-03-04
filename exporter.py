"""
exporter.py — Export analysis reports to TXT or CSV.
"""

import csv
import io
from datetime import datetime
from parser import AnalysisReport


def export_txt(report: AnalysisReport, filename: str) -> None:
    """Write a human-readable report to a .txt file."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 70)
    lines.append("  LOG ANALYSIS REPORT")
    lines.append(f"  Generated: {now}")
    lines.append("=" * 70)
    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Log type detected   : {report.log_type.upper()}")
    lines.append(f"  Total lines         : {report.total_lines}")
    lines.append(f"  Parsed lines        : {report.parsed_lines}")
    lines.append(f"  Flagged lines       : {report.flagged_lines}")
    lines.append(f"  Failed login events : {report.failed_logins}")
    lines.append(f"  Suspicious IPs      : {len(report.suspicious_ips)}")
    lines.append(f"  Brute force IPs     : {len(report.brute_force_ips)}")
    lines.append(f"  Keyword matches     : {len(report.keyword_matches)}")
    lines.append("")

    if report.brute_force_ips:
        lines.append("BRUTE FORCE ALERTS")
        lines.append("-" * 40)
        for ip in report.brute_force_ips:
            count = report.suspicious_ips.get(ip, "?")
            lines.append(f"  [!] {ip}  —  {count} failed login attempts")
        lines.append("")

    if report.suspicious_ips:
        lines.append("SUSPICIOUS IP ACTIVITY")
        lines.append("-" * 40)
        for ip, count in sorted(report.suspicious_ips.items(),
                                key=lambda x: x[1], reverse=True):
            lines.append(f"  {ip:<20} {count} failed attempt(s)")
        lines.append("")

    if report.keyword_matches:
        lines.append("KEYWORD MATCHES")
        lines.append("-" * 40)
        for line_num, keyword, raw in report.keyword_matches:
            lines.append(f"  Line {line_num:<6} [{keyword}]  {raw[:80]}")
        lines.append("")

    if report.flagged_entries:
        lines.append("FLAGGED LOG ENTRIES")
        lines.append("-" * 40)
        for entry in report.flagged_entries:
            flags = ", ".join(entry.flags)
            lines.append(f"  Line {entry.line_number:<6} [{flags}]")
            lines.append(f"    {entry.raw.strip()[:100]}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def export_csv(report: AnalysisReport, filename: str) -> None:
    """Write flagged entries to a .csv file."""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["line_number", "timestamp", "ip", "level",
                         "flags", "message"])
        for entry in report.flagged_entries:
            writer.writerow([
                entry.line_number,
                entry.timestamp or "",
                entry.ip or "",
                entry.level or "",
                "|".join(entry.flags),
                entry.raw.strip()[:200],
            ])
