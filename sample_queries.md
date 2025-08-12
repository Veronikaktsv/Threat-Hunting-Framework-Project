# Sample Detection Queries and Logic

This file contains example detection rules and queries used by the hunting framework.

## Powershell Encoded Command Detection

- Look for ProcessName or CommandLine containing 'powershell' with flags such as:
  - -enc
  - -encodedcommand
  - -nop
  - -noninteractive
  - -windowstyle

## CMD with Unusual Parent

- Detect cmd.exe processes where the ParentImage is not explorer.exe, cmd.exe, powershell.exe, or services.exe

## LSASS Access

- Detect events where TargetImage or TargetProcess is lsass.exe (often EventID 10)

## Service Creation

- Detect Event ID 7045 indicating new service installation

## Scheduled Task Creation

- Detect Event ID 4698 or schtasks.exe execution

## Certutil Usage

- Detect certutil.exe usage with suspicious flags (-urlcache, -decode, -encode)

## Mimikatz Detection

- Detect any command line containing the string 'mimikatz'
