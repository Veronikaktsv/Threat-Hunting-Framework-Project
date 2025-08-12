# Sample Detection Queries

## 1. Suspicious PowerShell Execution
**MITRE Technique:** T1059.001 — PowerShell  
**Logic:**
- Detect execution of PowerShell with suspicious parameters (`-EncodedCommand`, `-NoProfile`, `-ExecutionPolicy Bypass`).
- Look for event ID 4104 (Script Block Logging) or Sysmon Event ID 1 (Process Creation).

**Example KQL Query:**

    ```bash
    Event
    | where EventID == 1 and ProcessName == "powershell.exe"
    | where CommandLine contains "-EncodedCommand" or CommandLine contains "-ExecutionPolicy Bypass"

## 2. New Service Installation
**MITRE Technique:** T1543.003 — Windows Service
**Logic:**
- Detect creation of new services.
- Look for Sysmon Event ID 7045 or equivalent.

    ```bash
    Event
    | where EventID == 7045
    | project TimeGenerated, ServiceName, ServiceFileName

## 3. RDP Brute Force Attempt
**MITRE Technique:** T1110 — Brute Force
**Logic:**
- Detect repeated failed RDP login attempts from the same IP.
- Look for Windows Security Event ID 4625.

    ```bash
    SecurityEvent
    | where EventID == 4625 and LogonType == 10
    | summarize Attempts = count() by IpAddress
    | where Attempts > 10
