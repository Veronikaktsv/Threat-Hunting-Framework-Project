# Threat Hunting Framework with MITRE ATT&CK Integration

A Python-based framework that automates key threat hunting steps using MITRE ATT&CK mappings.  
It parses logs (Sysmon XML), detects suspicious activity, maps it to ATT&CK techniques,  
and provides relevant detection queries for investigation.

---

## Features
- **MITRE ATT&CK Mapping** — Categorizes detections by technique & tactic.
- **Automated Hunting Queries** — Links to sample detection queries in `sample_queries.md`.
- **Extensible** — Add new detection rules, mappings, and queries easily.
- **Command Line Interface** — Simple CLI to run hunts on given Sysmon logs.

---

## Quick Start

1. **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/threat-hunting-framework.git
    cd threat-hunting-framework

2. Install dependencies
    ```bash
    pip install -r requirements.txt`

3. Run the framework
    ```bash
    python hunt_framework.py sample_data/Sysmon_sample.xml
