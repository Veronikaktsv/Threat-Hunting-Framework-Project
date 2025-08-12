import sys
import json
import pandas as pd
from tabulate import tabulate
import xml.etree.ElementTree as ET

# Load MITRE mappings
with open("mitre_mappings.json", "r") as f:
    MITRE_MAP = json.load(f)

def parse_sysmon(file_path):
    """Parse Sysmon XML log and return DataFrame."""
    tree = ET.parse(file_path)
    root = tree.getroot()

    data = []
    for event in root.findall(".//Event"):
        event_id = event.findtext("./System/EventID")
        process_name = event.findtext(".//Data[@Name='Image']")
        cmd_line = event.findtext(".//Data[@Name='CommandLine']")
        data.append({
            "EventID": event_id,
            "ProcessName": process_name,
            "CommandLine": cmd_line
        })
    return pd.DataFrame(data)

def detect_techniques(df):
    """Simple detection based on rules."""
    detections = []
    for _, row in df.iterrows():
        if row["ProcessName"] and "powershell.exe" in row["ProcessName"].lower():
            detections.append("T1059.001")
    return detections

def main():
    if len(sys.argv) != 2:
        print("Usage: python hunt_framework.py <sysmon_log.xml>")
        sys.exit(1)

    log_file = sys.argv[1]
    df = parse_sysmon(log_file)
    detected = detect_techniques(df)

    results = []
    for tech in detected:
        if tech in MITRE_MAP:
            mapping = MITRE_MAP[tech]
            results.append([
                tech,
                mapping["technique"],
                mapping["tactic"],
                mapping["description"],
                mapping["query_file"]
            ])

    print(tabulate(results, headers=["Technique ID", "Technique", "Tactic", "Description", "Query Link"]))

if __name__ == "__main__":
    main()
