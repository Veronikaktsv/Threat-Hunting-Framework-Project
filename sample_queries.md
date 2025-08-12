# Sample Detection Queries

## 1. Suspicious PowerShell Execution
**MITRE Technique:** T1059.001 — PowerShell  
**Logic:**
- Detect execution of PowerShell with suspicious parameters (`-EncodedCommand`, `-NoProfile`, `-ExecutionPolicy Bypass`).
- Look for event ID 4104 (Script Block Logging) or Sysmon Event ID 1 (Process Creation).

**Example KQL Query:**
```kql
Event
| where EventID == 1 and ProcessName == "powershell.exe"
| where CommandLine contains "-EncodedCommand" or CommandLine contains "-ExecutionPolicy Bypass"
