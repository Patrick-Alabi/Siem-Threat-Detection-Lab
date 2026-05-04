# Detection Rule — Brute Force Login

## Overview
| Field | Value |
|---|---|
| **Name** | Brute Force Login Detection |
| **Severity** | High |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Data Source** | Windows Security Event Log |
| **Event ID** | 4625 — Failed Logon |

## Detection Logic
Triggers when 5 or more failed login attempts occur from the same 
account within a 5-minute window.

## Splunk Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name, Source_Network_Address
| where count >= 5
```

## Why This Matters
Brute force attacks are one of the most common initial access techniques.
Rapid sequential failures from one account indicate automated tooling.

## False Positive Considerations
- Legitimate users locking themselves out
- Service accounts with expired passwords
- Filter known-good accounts if needed
