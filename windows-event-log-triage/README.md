# windows-event-log-triage

A Python tool that ingests a CSV export of Windows Security event logs and automatically flags suspicious activity — the same kind of triage I do manually as part of my day-to-day SOC work, turned into a repeatable script.

## Why I built this

Investigating phishing, malware, and account-compromise alerts is a core part of my current role, where I triage security incidents across an 800+ user environment. This project automates the first-pass triage I do by hand: spotting brute-force patterns, catching privileged accounts logging in outside normal hours, and surfacing account lockouts — the kind of signals that would otherwise take manual log review to notice.

**Note:** the data in `sample_data/` is entirely synthetic, generated for this project. No real organization, user, or log data is used anywhere in this repo.

## What it detects

- **Brute-force patterns** — clusters of failed logons (event ID 4625) against the same account from the same source IP, above a configurable threshold. If a successful logon (4624) follows the cluster, it's flagged as a possible compromise.
- **Off-hours privileged logons** — successful logons by privileged accounts (e.g. `administrator`) outside a configurable normal-hours window.
- **Account lockouts** — event ID 4740 entries.

## How to run it

```bash
git clone https://github.com/<your-username>/windows-event-log-triage.git
cd windows-event-log-triage
python triage.py sample_data/sample_events.csv
```

No dependencies beyond the Python standard library.

## Example output

```
Loaded 81 events from sample_data/sample_events.csv

8 finding(s):

 - [BRUTE-FORCE PATTERN] 18 failed logons for 'administrator' from 203.0.113.77
   between 2026-06-10T02:13:00 and 2026-06-10T02:14:59
   -> FOLLOWED BY SUCCESSFUL LOGON at 2026-06-10T02:15:11 (possible compromise)
 - [OFF-HOURS PRIVILEGED LOGON] 'administrator' logged in at 2026-06-14T03:41:00 from 10.20.1.44
 - [ACCOUNT LOCKOUT] 'pwalker' locked out at 2026-06-16T09:05:00 (source: 10.20.1.22)
```

## Using it on real data

Export Security log events with PowerShell, e.g.:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4740} |
  Select-Object TimeCreated, Id, @{n='Account';e={$_.Properties[5].Value}}, `
    @{n='IpAddress';e={$_.Properties[19].Value}} |
  Export-Csv events.csv -NoTypeInformation
```

Then adjust column names in `triage.py` to match your export format.

## What this demonstrates

- Python scripting for security automation
- Understanding of Windows Security event IDs and logon analysis
- Detection logic design (thresholding, correlation between failure/success events)
- Clean, documented, runnable code — not just a snippet

## Roadmap

- [ ] Add CSV → JSON report export
- [ ] Add unit tests
- [ ] Extend detection rules (impossible travel, new-IP-for-account)

## License

MIT — see [LICENSE](LICENSE)
