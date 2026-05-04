# 🔐 SIEM Threat Detection Lab

A hands-on Security Operations Center (SOC) lab built with **Splunk Enterprise** 
on Windows, using **Sysmon** and **Linux auth logs** to detect real-world attack 
patterns.

---

## 🧪 Lab Architecture

| Component | Role |
|---|---|
| Windows PC (Host) | Runs Splunk SIEM + Sysmon |
| Ubuntu Linux VM (VirtualBox) | Attack target + log source |
| Splunk Universal Forwarder | Ships Linux logs to Splunk |
| Sysmon (SwiftOnSecurity config) | Deep Windows telemetry |

---

## ⚔️ Attacks Simulated

| Attack | MITRE Technique | Event ID | Result |
|---|---|---|---|
| Brute Force Login | T1110 | 4625 | ✅ Detected |
| PowerShell Misuse | T1059.001 | Sysmon EID 1 | ✅ Detected |
| Privilege Escalation | T1078 | 4728/4732 | ✅ Detected |

---

## 📊 Dashboard

Built a real-time SOC monitoring dashboard in Splunk showing:
- Failed logins over time
- Top accounts with failed logins
- Suspicious PowerShell activity
- Privilege escalation events
- Total events by log source

![SOC Dashboard](screenshots/splunk-dashboard.png)

---

## 🚨 Detections

All detection rules are documented in the [`detections/`](./detections/) folder with:
- Splunk SPL queries
- MITRE ATT&CK mapping
- Severity ratings
- False positive considerations

---

## 📄 Incident Report

A full incident report covering all 3 detected attacks is available here:
[`incident-report.md`](./incident-report.md)

---

## 🔍 Key Findings

**Brute Force:** 10 failed login attempts from `hacker_test_user` detected 
within 60 seconds — consistent with automated credential stuffing tooling.

**PowerShell:** Base64 encoded command execution captured by Sysmon — 
technique matches real-world malware delivery patterns (T1059.001).

**Privilege Escalation:** Account addition to Administrators group detected 
in real-time via EventCode 4728 — zero detection delay.

---

## 🛠️ Tools Used

- Splunk Enterprise (Free License)
- Microsoft Sysmon + SwiftOnSecurity config
- VirtualBox + Ubuntu Server 22.04
- Splunk Universal Forwarder
- Windows Event Logs (Security, System, Application)

---

## 📚 What I Learned

- End-to-end SIEM deployment and configuration
- Log ingestion from Windows and Linux sources
- Detection engineering with correlation rules
- MITRE ATT&CK framework application
- Incident documentation and SOC workflow

---

## 🔗 References
- [MITRE ATT&CK](https://attack.mitre.org)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Documentation](https://docs.splunk.com)
