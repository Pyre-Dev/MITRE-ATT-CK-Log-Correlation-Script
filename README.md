# MITRE ATT&CK Log Correlation Script

This script parses Windows `.evtx` event logs and maps known security-relevant Event IDs to MITRE ATT&CK tactics and techniques.

## Features
- Maps log activity to MITRE ATT&CK
- Outputs findings in terminal
- Exports reports to CSV and JSON

## Usage
```bash
python detect_attack.py sample_logs/security.evtx