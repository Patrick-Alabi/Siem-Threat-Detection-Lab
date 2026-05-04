# Incident Report — SIEM Lab
**Analyst:** Patrick Ekata Alabi  
**Date:** 2026-05-04  
**Environment:** Splunk Enterprise (Free) on Windows + Ubuntu VM  
**Tools Used:** Splunk, Sysmon, Windows Event Logs, Linux Auth Logs

---

## Incident 1 — Brute Force Login Attack

**Severity:** High  
**Status:** Detected & Closed  
**MITRE ATT&CK Technique:** T1110 — Brute Force

### Timeline
| Time | Event |
|---|---|
| 20:19 | First failed login attempt detected |
| 20:19 | 10 consecutive failures from `hacker_test_user` |
| 20:19 | Alert triggered — EventCode 4625 threshold exceeded |

### Findings
- **Source Account:** `hacker_test_user`
- **Source IP:** `::1` (localhost — simulated internal attacker)
- **Failed Attempts:** 10 within 60 seconds
- **Affected System:** DESKTOP-BHJAN1K

### Analysis
A series of rapid failed authentication attempts were detected originating 
from account `hacker_test_user`. The pattern is consistent with automated 
brute force tooling. The account does not exist in the directory, suggesting 
credential stuffing or username enumeration.

### Response Actions
- [x] Alert triggered in Splunk
- [x] Account confirmed non-existent (simulated attacker account)
- [x] No successful logins observed after failed attempts
- [x] Incident documented

### Detection Query Used
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name, Source_Network_Address
| where count >= 5
```

---

## Incident 2 — Suspicious PowerShell Execution

**Severity:** Critical  
**Status:** Detected & Closed  
**MITRE ATT&CK Technique:** T1059.001 — PowerShell

### Timeline
| Time | Event |
|---|---|
| 20:22 | PowerShell launched with `-EncodedCommand` flag |
| 20:22 | Sysmon EventCode 1 fired — process creation logged |
| 20:22 | Alert triggered in Splunk |

### Findings
- **Process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **User:** `DESKTOP-BHJAN1K\daddy`
- **Flag used:** `-EncodedCommand` (base64 encoded payload)
- **Decoded command:** `Invoke-WebRequest -Uri 'https://microsoft.com'`

### Analysis
PowerShell was executed with a base64 encoded command — a technique 
commonly used by malware and attackers to obfuscate their activity from 
basic log monitoring. Sysmon captured the full command line including the 
encoded payload. The decoded content pointed to an external web request, 
consistent with C2 beaconing or payload download behaviour.

### Response Actions
- [x] Process execution logged by Sysmon Event ID 1
- [x] Command decoded and analysed — benign in this simulation
- [x] Alert saved as real-time detection rule
- [x] Incident documented

---

## Incident 3 — Privilege Escalation via Admin Group Modification

**Severity:** Critical  
**Status:** Detected & Closed  
**MITRE ATT&CK Technique:** T1078 — Valid Accounts

### Timeline
| Time | Event |
|---|---|
| 20:25 | New user account `soclab_testuser` created |
| 20:25 | Account added to **Administrators** group |
| 20:25 | EventCode 4728 triggered — Splunk alert fired |

### Findings
- **Account Modified:** `daddy` (admin account that ran the command)
- **Group Affected:** `Administrators`
- **Event IDs:** 4728, 4732
- **System:** DESKTOP-BHJAN1K

### Analysis
A user account was added to the local Administrators group, granting full 
system privileges. This technique is used by attackers after gaining initial 
access to establish persistence and elevate privileges. The event was captured 
immediately by Windows Security auditing and flagged by the Splunk real-time alert.

### Response Actions
- [x] Alert triggered immediately on group modification
- [x] Test account removed after simulation confirmed
- [x] Real-time detection rule saved in Splunk
- [x] Incident documented

---

## Summary

| Incident | Severity | Detection Method | MITRE Technique |
|---|---|---|---|
| Brute Force Login | High | EventCode 4625 threshold | T1110 |
| PowerShell Misuse | Critical | Sysmon EventCode 1 | T1059.001 |
| Privilege Escalation | Critical | EventCode 4728/4732 | T1078 |

## Lab Conclusion
This lab demonstrated end-to-end SOC capabilities including log ingestion, 
attack simulation, detection engineering, and incident response documentation. 
All three attack scenarios were successfully detected using custom Splunk 
correlation rules aligned to MITRE ATT&CK framework techniques.