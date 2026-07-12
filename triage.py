"""
windows-event-log-triage
-------------------------
Reads a CSV export of Windows Security event log entries and flags
suspicious activity: possible brute-force attempts, off-hours privileged
logons, and account lockouts.

Expected input columns (matches a typical `Get-WinEvent` export):
    TimeCreated, EventID, Account, IpAddress, LogonType, Result

Common event IDs used here:
    4624 = successful logon
    4625 = failed logon
    4740 = account lockout

Usage:
    python triage.py sample_data/sample_events.csv
"""

import argparse
import csv
from collections import defaultdict
from datetime import datetime

FAILED_LOGON_THRESHOLD = 5   # failures from one IP against one account = suspicious
OFF_HOURS_START = 22          # 22:00
OFF_HOURS_END = 6             # 06:00
PRIVILEGED_ACCOUNTS = {"administrator", "svc_backup"}


def load_events(path):
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return [row for row in reader]


def find_brute_force_patterns(events):
    """Group failed logons by (account, source IP) and flag clusters over
    the threshold. Also flags if a success follows a failure cluster from
    the same IP -- a classic compromise indicator."""
    failures = defaultdict(list)
    successes = defaultdict(list)

    for e in events:
        key = (e["Account"], e["IpAddress"])
        if e["EventID"] == "4625":
            failures[key].append(e["TimeCreated"])
        elif e["EventID"] == "4624":
            successes[key].append(e["TimeCreated"])

    findings = []
    for key, times in failures.items():
        if len(times) >= FAILED_LOGON_THRESHOLD:
            account, ip = key
            finding = (
                f"[BRUTE-FORCE PATTERN] {len(times)} failed logons for "
                f"'{account}' from {ip} between {min(times)} and {max(times)}"
            )
            later_successes = [s for s in successes.get(key, []) if s > max(times)]
            if later_successes:
                success_time = min(later_successes)
                finding += (
                    f"  -> FOLLOWED BY SUCCESSFUL LOGON at {success_time} "
                    f"(possible compromise)"
                )
            findings.append(finding)
    return findings


def find_off_hours_privileged_logons(events):
    findings = []
    for e in events:
        if e["EventID"] != "4624":
            continue
        if e["Account"].lower() not in PRIVILEGED_ACCOUNTS:
            continue
        try:
            hour = datetime.fromisoformat(e["TimeCreated"]).hour
        except ValueError:
            continue
        if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
            findings.append(
                f"[OFF-HOURS PRIVILEGED LOGON] '{e['Account']}' logged in at "
                f"{e['TimeCreated']} from {e['IpAddress']}"
            )
    return findings


def find_lockouts(events):
    findings = []
    for e in events:
        if e["EventID"] == "4740":
            findings.append(
                f"[ACCOUNT LOCKOUT] '{e['Account']}' locked out at "
                f"{e['TimeCreated']} (source: {e['IpAddress']})"
            )
    return findings


def main():
    parser = argparse.ArgumentParser(description="Triage a Windows Security event log CSV export.")
    parser.add_argument("csv_path", help="Path to the event log CSV export")
    args = parser.parse_args()

    events = load_events(args.csv_path)
    print(f"Loaded {len(events)} events from {args.csv_path}\n")

    all_findings = (
        find_brute_force_patterns(events)
        + find_off_hours_privileged_logons(events)
        + find_lockouts(events)
    )

    if not all_findings:
        print("No suspicious activity detected.")
        return

    print(f"{len(all_findings)} finding(s):\n")
    for f in all_findings:
        print(f" - {f}")


if __name__ == "__main__":
    main()
