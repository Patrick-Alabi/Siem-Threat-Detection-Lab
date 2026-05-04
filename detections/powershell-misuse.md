# Detection Rule — Suspicious PowerShell Execution

## Overview
| Field | Value |
|---|---|
| **Name** | Suspicious PowerShell Execution |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1059.001 — PowerShell |
| **Data Source** | Sysmon Event Log |
| **Event ID** | 1 — Process Creation |

## Detection Logic
Triggers when PowerShell is launched with encoded commands or 
download cradle techniques commonly used by malware.

## Splunk Query
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
EventCode=1
| search CommandLine="*EncodedCommand*" OR CommandLine="*Invoke-Expression*" 
OR CommandLine="*DownloadString*"
| table _time, Image, CommandLine, User, ParentImage
| sort -_time
```

## Why This Matters
Encoded PowerShell is a top malware delivery technique. Attackers use 
base64 encoding to bypass basic string-based detection.

## False Positive Considerations
- Some legitimate software uses encoded PS commands
- Correlate with parent process and network activity
