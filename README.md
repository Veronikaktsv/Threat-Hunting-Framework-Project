# Threat Hunting Framework with MITRE ATT&CK Integration

This project provides a Python-based threat hunting framework to automate detection of suspicious activities in Windows Sysmon event logs exported in XML format. The framework maps findings to MITRE ATT&CK techniques, prioritizes alerts, and visualizes results.

---

## Features

- Parses Sysmon event logs in XML format.
- Runs multiple detection rules for suspicious activity, including PowerShell obfuscation, LSASS access, suspicious service creation, and more.
- Maps findings to MITRE ATT&CK techniques using a JSON mapping file.
- Prioritizes alerts by severity scores.
- Pretty console output with colored tables (using `rich`).
- Saves detailed findings to a JSON file for further analysis.

---

## Requirements

- Python 3.7+
- Packages listed in `requirements.txt`

---

## Setup

1. Clone the repository:

    ```bash
    git clone https://github.com/Veronikaktsv/Sysmon-Event-Log-Analysis-Detection.git
    cd Sysmon-Event-Log-Analysis-Detection

2. Install dependencies:

   ```bash
    pip install -r requirements.txt

3. Add your Sysmon event log in XML format:
- Place your exported XML log inside the `sample_data/` folder named `Sysmon_sample.xml`.
- You can export from Windows Event Viewer:
  - Open Event Viewer (eventvwr.msc).
  - Navigate to: `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`
  - Right-click Operational → Save All Events As…
  - Choose XML format and save as sample_data/Sysmon_sample.xml

4. Verify or update the XML file path in the command line when running the hunt script.

## Usage 
1. Run the hunting framework:
    
    ```bash
    python hunt_framework.py --input sample_data/Sysmon_sample.xml --format xml --output findings.json

This will:
- Parse the XML log
- Run detection rules
- Map and prioritize findings with MITRE ATT&CK info
- Display findings in a colored console table
- Save detailed findings in `findings.json`

## Notes
- Detection rules are basic examples and meant for demonstration.
- Event ID 4672 (Privilege Escalation) usually appears in Windows Security logs, not Sysmon.
- Customize detection rules and MITRE mappings as needed.
- For production use, add error handling, log storage, and SIEM integration.

## Future Improvements
- Additional detection rules mapped to MITRE ATT&CK.
- Export alerts to logs or send notifications.
- Interactive web dashboard.
- Real-time log ingestion and alerting.

## License
This project is licensed under the [MIT License](LICENSE).

## References
- [Sysmon Documentation - Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
