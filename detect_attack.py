import sys
import json
import csv
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from datetime import datetime

# Load MITRE mapping
with open("event_map.json") as f:
    mitre_map = json.load(f)

def parse_evtx(file_path):
    results = []
    print(f"\nAnalyzing log: {file_path}\n")

    with Evtx(file_path) as log:
        for record in log.records():
            try:
                xml = ET.fromstring(record.xml())
                event_id = xml.findtext(".//EventID")
                timestamp = xml.find(".//TimeCreated").attrib.get("SystemTime", "N/A")

                if event_id in mitre_map:
                    attack_info = mitre_map[event_id]
                    finding = {
                        "timestamp": timestamp,
                        "event_id": event_id,
                        "tactic": attack_info["tactic"],
                        "technique": attack_info["technique"],
                        "description": attack_info["description"]
                    }
                    results.append(finding)
                    print(f"[!] {timestamp} | Event ID: {event_id} | {attack_info['technique']} ({attack_info['tactic']}) - {attack_info['description']}")
            except Exception as e:
                continue
    return results

def export_csv(data, output_file):
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"\nCSV report saved to: {output_file}")

def export_json(data, output_file):
    with open(output_file, "w", encoding="utf-8") as jsonfile:
        json.dump(data, jsonfile, indent=4)
    print(f"JSON report saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_attack.py <log.evtx>")
        sys.exit(1)

    log_file = sys.argv[1]
    findings = parse_evtx(log_file)

    if findings:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_csv(findings, f"attack_report_{timestamp}.csv")
        export_json(findings, f"attack_report_{timestamp}.json")
    else:
        print("No suspicious activity found based on current MITRE mappings.")