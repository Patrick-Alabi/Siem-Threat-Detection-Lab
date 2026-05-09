# ELK Detection Rules — KQL

## Rule 1: Brute Force Login
- **Platform:** ELK Stack (Kibana Rules)
- **Query:** `winlog.event_id : "4625"`
- **Threshold:** More than 4 events in 5 minutes
- **Index:** `soc-logs-*`
- **MITRE:** T1110 — Brute Force
- **Severity:** High

## Rule 2: Suspicious PowerShell Execution  
- **Platform:** ELK Stack (Kibana Rules)
- **Query:** `winlog.event_data.CommandLine : *EncodedCommand*`
- **Threshold:** Any match
- **Index:** `soc-logs-*`
- **MITRE:** T1059.001 — PowerShell
- **Severity:** Critical

## Rule 3: Privilege Escalation
- **Platform:** ELK Stack (Kibana Rules)
- **Query:** `winlog.event_id : "4728" or winlog.event_id : "4732"`
- **Threshold:** Any match
- **Index:** `soc-logs-*`
- **MITRE:** T1078 — Valid Accounts
- **Severity:** Critical

## Rule 4: Linux Authentication Failure
- **Platform:** ELK Stack (Kibana Rules)
- **Query:** `message : *authentication failure*`
- **Threshold:** Any match
- **Index:** `filebeat-*`
- **MITRE:** T1110 — Brute Force
- **Severity:** Medium

## Splunk vs ELK Field Mapping
| Event | Splunk Field | ELK Field |
|---|---|---|
| Failed login | `EventCode=4625` | `winlog.event_id : "4625"` |
| Process create | `EventCode=1` | `winlog.event_id : "1"` |
| Group change | `EventCode=4728` | `winlog.event_id : "4728"` |
| PowerShell | `CommandLine=*Encoded*` | `winlog.event_data.CommandLine : *EncodedCommand*` |
