# Detection Rule — Privilege Escalation via Admin Group

## Overview
| Field | Value |
|---|---|
| **Name** | Admin Group Modification |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1078 — Valid Accounts |
| **Data Source** | Windows Security Event Log |
| **Event ID** | 4728 / 4732 — Member Added to Group |

## Detection Logic
Triggers any time a user account is added to the local 
Administrators group.

## Splunk Query
```spl
index=main sourcetype="WinEventLog:Security" 
(EventCode=4728 OR EventCode=4732)
| search Group_Name="Administrators"
| table _time, Account_Name, Member_Security_ID, Group_Name
| sort -_time
```

## Why This Matters
Adding accounts to admin groups is a primary persistence and 
privilege escalation technique after initial compromise.

## False Positive Considerations
- Legitimate IT admin provisioning
- Correlate with business change requests
