#!/usr/bin/env python3
"""
Hunt framework: run a set of detection rules against Sysmon XML (or CSV) logs,
map findings to MITRE ATT&CK using mitre_mappings.json, prioritize, print and save results.

Usage:
  python hunt_framework.py --input sample_data/Sysmon_sample.xml --format xml --output findings.json
"""
import argparse
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET
import pandas as pd

# Try to use rich for pretty console output; fallback to tabulate
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    from tabulate import tabulate
    RICH_AVAILABLE = False
    console = None

MITRE_FILE = "mitre_mappings.json"
DEFAULT_OUTPUT = "findings.json"

# --- Parsing helpers -------------------------------------------------------
def parse_xml(xml_path: str) -> pd.DataFrame:
    """Parse Sysmon-exported XML (Event Viewer export) into a DataFrame."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Namespace handling if present
    ns = {'ns': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

    rows = []
    for event in root.findall('.//ns:Event' if ns else './/Event', ns):
        # find system info
        system = event.find('ns:System' if ns else 'System', ns)
        if system is None:
            continue
        eid_elem = system.find('ns:EventID' if ns else 'EventID', ns)
        time_elem = system.find('ns:TimeCreated' if ns else 'TimeCreated', ns)
        if eid_elem is None or time_elem is None:
            continue
        try:
            event_id = int(eid_elem.text)
        except Exception:
            event_id = None
        timestamp = time_elem.attrib.get('SystemTime', '')

        # collect EventData -> Data Name="..."
        eventdata = event.find('ns:EventData' if ns else 'EventData', ns)
        row = {"EventID": event_id, "TimeCreated": timestamp}
        if eventdata is not None:
            for d in eventdata.findall('ns:Data' if ns else 'Data', ns):
                key = d.attrib.get('Name') or ''
                row[key] = d.text
        rows.append(row)

    df = pd.DataFrame(rows)
    # Normalize common fields to expected column names
    # Some XMLs use "Image" for process path, others "ProcessName"
    if 'Image' in df.columns and 'ProcessName' not in df.columns:
        df.rename(columns={'Image': 'ProcessName'}, inplace=True)
    if 'TargetImage' in df.columns:
        df.rename(columns={'TargetImage': 'TargetImage'}, inplace=True)
    return df

def parse_csv(csv_path: str) -> pd.DataFrame:
    """Load a CSV into pandas (assumes columns similar to XML parser)."""
    return pd.read_csv(csv_path)

# --- Detection rules -------------------------------------------------------
def rule_powershell_encoded(df: pd.DataFrame):
    """Detect PowerShell with encoded or suspicious flags."""
    findings = []
    if 'CommandLine' not in df.columns and 'CommandLine' not in df.columns:
        return findings
    pattern_flags = re.compile(r'(-enc|-encodedcommand|-nop|-noninteractive|-windowstyle)', re.I)
    for _, r in df[df['CommandLine'].notna()].iterrows():
        cmd = r['CommandLine'] or ''
        pname = str((r.get('ProcessName') or '')).lower()
        if 'powershell' in pname or 'powershell' in cmd.lower():
            if pattern_flags.search(cmd):
                findings.append({
                    'rule': 'powershell_encoded',
                    'desc': 'PowerShell executed with encoded or suspicious flags',
                    'event_id': int(r.get('EventID') or 0),
                    'time': r.get('TimeCreated'),
                    'process': r.get('ProcessName'),
                    'commandline': cmd
                })
    return findings

def rule_cmd_unusual_parent(df: pd.DataFrame):
    """Detect cmd.exe spawned by unusual parent process."""
    findings = []
    if 'ProcessName' not in df.columns:
        return findings
    for _, r in df[df['ProcessName'].notna()].iterrows():
        pname = str(r['ProcessName'])
        if pname.lower().endswith('cmd.exe'):
            parent = str(r.get('ParentImage') or '').lower()
            # consider normal parents
            if parent and not any(x in parent for x in ['explorer.exe', 'cmd.exe', 'powershell.exe', 'services.exe']):
                findings.append({
                    'rule': 'cmd_unusual_parent',
                    'desc': 'cmd.exe spawned by unusual parent',
                    'event_id': int(r.get('EventID') or 0),
                    'time': r.get('TimeCreated'),
                    'process': r.get('ProcessName'),
                    'parent': r.get('ParentImage'),
                    'commandline': r.get('CommandLine')
                })
    return findings

def rule_lsass_access(df: pd.DataFrame):
    """Detect process access or connections to lsass (credential dumping attempts)."""
    findings = []
    # This can be EventID 10 (ProcessAccess) or TargetImage fields
    if 'TargetImage' in df.columns:
        ls = df[df['TargetImage'].str.lower().str.contains('lsass.exe', na=False)]
        for _, r in ls.iterrows():
            findings.append({
                'rule': 'lsass_access',
                'desc': 'Access to LSASS process detected',
                'event_id': int(r.get('EventID') or 0),
                'time': r.get('TimeCreated'),
                'process': r.get('ProcessName'),
                'target': r.get('TargetImage'),
                'commandline': r.get('CommandLine')
            })
    return findings

def rule_service_creation(df: pd.DataFrame):
    """Detect new service creation (Event ID 7045)."""
    findings = []
    svc = df[df['EventID'] == 7045] if 'EventID' in df.columns else pd.DataFrame()
    for _, r in svc.iterrows():
        findings.append({
            'rule': 'service_creation',
            'desc': 'New service installation detected',
            'event_id': int(r.get('EventID') or 7045),
            'time': r.get('TimeCreated'),
            'service_name': r.get('ServiceName') or r.get('TargetObject') or r.get('ServiceName'),
            'details': r.get('CommandLine') or r.get('ServiceFileName')
        })
    return findings

def rule_scheduled_task(df: pd.DataFrame):
    """Detect scheduled task creation (EventID 4698 or command schtasks.exe)."""
    findings = []
    if 'EventID' in df.columns:
        st = df[df['EventID'] == 4698]
        for _, r in st.iterrows():
            findings.append({
                'rule': 'scheduled_task',
                'desc': 'Scheduled task created',
                'event_id': int(r.get('EventID') or 4698),
                'time': r.get('TimeCreated'),
                'details': r.get('TaskName') or r.get('CommandLine')
            })
    # also check for schtasks.exe usage
    if 'ProcessName' in df.columns:
        sch = df[df['ProcessName'].str.lower().str.endswith('schtasks.exe', na=False)]
        for _, r in sch.iterrows():
            findings.append({
                'rule': 'scheduled_task_cmd',
                'desc': 'schtasks.exe executed',
                'event_id': int(r.get('EventID') or 0),
                'time': r.get('TimeCreated'),
                'process': r.get('ProcessName'),
                'commandline': r.get('CommandLine')
            })
    return findings

def rule_certutil(df: pd.DataFrame):
    """Detect certutil suspicious usage (likely used to download payloads)."""
    findings = []
    if 'ProcessName' in df.columns:
        cert = df[df['ProcessName'].str.lower().str.endswith('certutil.exe', na=False)]
        for _, r in cert.iterrows():
            cmd = r.get('CommandLine') or ''
            if any(k in (cmd or '').lower() for k in ['-urlcache', '-decode', '-encode']):
                findings.append({
                    'rule': 'certutil',
                    'desc': 'certutil used (possible file transfer or decoding)',
                    'event_id': int(r.get('EventID') or 0),
                    'time': r.get('TimeCreated'),
                    'process': r.get('ProcessName'),
                    'commandline': cmd
                })
    return findings

def rule_mimikatz(df: pd.DataFrame):
    """Detect mimikatz by name or suspicious args."""
    findings = []
    if 'CommandLine' in df.columns:
        mim = df[df['CommandLine'].str.contains('mimikatz', case=False, na=False)]
        for _, r in mim.iterrows():
            findings.append({
                'rule': 'mimikatz',
                'desc': 'Mimikatz detected in command line',
                'event_id': int(r.get('EventID') or 0),
                'time': r.get('TimeCreated'),
                'process': r.get('ProcessName'),
                'commandline': r.get('CommandLine')
            })
    return findings

# Add more rules as needed...

RULE_FUNCTIONS = [
    rule_powershell_encoded,
    rule_cmd_unusual_parent,
    rule_lsass_access,
    rule_service_creation,
    rule_scheduled_task,
    rule_certutil,
    rule_mimikatz,
]

# --- MITRE mapping loader & scoring ---------------------------------------
def load_mitre_map(path: str):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def enrich_with_mitre(findings: list, mitre_map: dict):
    """For each finding, if rule maps to a MITRE technique in the mapping file, append MITRE info."""
    enriched = []
    for f in findings:
        # Try to find mapping by rule or fallback to technique id in mapping
        # mapping file expected to be keyed by technique id (e.g., "T1059.001") or custom keys
        # We'll search values for a mapping that references our rule name in 'query_file' or 'rule' key
        # Simple approach: check known mapping fields "rule_name" or if mapping includes 'rules' list
        mapped = None
        # direct mapping by rule name key
        for k, v in mitre_map.items():
            # if mapping explicitly includes a 'rules' list -> check membership
            if isinstance(v, dict):
                if v.get('rules') and f['rule'] in v.get('rules'):
                    mapped = (k, v)
                    break
                # if f.rule matches technique id stored in mapping value keys (less likely)
            # fallback: if rule name equals key
            if k.lower() == f['rule'].lower():
                mapped = (k, v)
                break
        # fallback: try hardcoded mapping heuristics (rule -> technique)
        if not mapped:
            # common mappings
            if f['rule'].startswith('powershell'):
                mapped = ('T1059.001', mitre_map.get('T1059.001'))
            elif f['rule'].startswith('cmd'):
                mapped = ('T1059.003', mitre_map.get('T1059.003') or mitre_map.get('T1059'))
            elif f['rule'] == 'lsass_access' or f['rule'] == 'mimikatz':
                mapped = ('T1003', mitre_map.get('T1003') or mitre_map.get('T1003.001'))
            elif f['rule'] == 'service_creation':
                mapped = ('T1543.003', mitre_map.get('T1543.003'))
            elif f['rule'].startswith('scheduled_task'):
                mapped = ('T1053.005', mitre_map.get('T1053.005'))
            elif f['rule'] == 'certutil':
                mapped = ('T1105', mitre_map.get('T1105'))
        # build enriched dict
        if mapped and mapped[1]:
            tech_id = mapped[0]
            meta = mapped[1]
            score = meta.get('score', 5) if isinstance(meta, dict) else 5
            enriched.append({**f,
                             'mitre_id': tech_id,
                             'mitre_technique': meta.get('technique') if isinstance(meta, dict) else None,
                             'mitre_tactic': meta.get('tactic') if isinstance(meta, dict) else None,
                             'mitre_desc': meta.get('description') if isinstance(meta, dict) else None,
                             'score': score})
        else:
            # no mapping found
            enriched.append({**f, 'mitre_id': None, 'mitre_technique': None, 'mitre_tactic': None, 'mitre_desc': None, 'score': 1})
    return enriched

# --- Output helpers --------------------------------------------------------
def prioritize(findings: list):
    return sorted(findings, key=lambda x: x.get('score', 0), reverse=True)

def print_table(findings: list):
    if not findings:
        if RICH_AVAILABLE:
            console.print("[green]No findings detected.[/green]")
        else:
            print("No findings detected.")
        return

    if RICH_AVAILABLE:
        table = Table(title="Hunt Findings", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Score", style="bold red")
        table.add_column("Time")
        table.add_column("Rule")
        table.add_column("EventID")
        table.add_column("Technique")
        table.add_column("Tactic")
        table.add_column("Details")
        for f in findings:
            details = f.get('desc') or ''
            if f.get('commandline'):
                details += f"\nCmd: {f.get('commandline')[:140]}"
            table.add_row(str(f.get('score', '')), str(f.get('time','')), f.get('rule',''), str(f.get('event_id','')), str(f.get('mitre_id') or ''), str(f.get('mitre_tactic') or ''), details)
        console.print(table)
    else:
        rows = []
        for f in findings:
            details = f.get('desc') or ''
            if f.get('commandline'):
                details += f" | Cmd: {f.get('commandline')[:120]}"
            rows.append([f.get('score',''), f.get('time',''), f.get('rule',''), f.get('event_id',''), f.get('mitre_id',''), f.get('mitre_tactic',''), details])
        print(tabulate(rows, headers=['Score','Time','Rule','EventID','MITRE','Tactic','Details']))

def save_findings(findings: list, outpath: str):
    with open(outpath, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

# --- Main runner -----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Simple Threat Hunting Framework")
    parser.add_argument('--input', '-i', required=True, help='Input log file (XML or CSV)')
    parser.add_argument('--format', '-f', choices=['xml','csv'], default='xml', help='Input format')
    parser.add_argument('--mitre', '-m', default=MITRE_FILE, help='MITRE mapping JSON file')
    parser.add_argument('--output', '-o', default=DEFAULT_OUTPUT, help='Output findings JSON')
    args = parser.parse_args()

    mitre_map = load_mitre_map(args.mitre)

    # parse input
    if args.format == 'xml':
        df = parse_xml(args.input)
    else:
        df = parse_csv(args.input)

    # run rules and collect findings
    findings = []
    for rule_fn in RULE_FUNCTIONS:
        try:
            findings.extend(rule_fn(df))
        except Exception as e:
            # do not crash entire run for one rule
            print(f"Rule {rule_fn.__name__} error: {e}")

    # enrich with MITRE info & prioritize
    enriched = enrich_with_mitre(findings, mitre_map)
    prioritized = prioritize(enriched)

    # print and save
    print_table(prioritized)
    save_findings(prioritized, args.output)
    print(f"\nFindings saved to {args.output}")

if __name__ == "__main__":
    main()
