import json
import re
from datetime import datetime
from typing import List, Dict
import requests


class SecurityLogAnalyzer:
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.api_url = "https://api.anthropic.com/v1/messages"

        self.mitre_mappings = {
            "failed_login": {
                "technique": "T1110 - Brute Force",
                "tactic": "Credential Access",
                "severity": "HIGH"
            },
            "privilege_escalation": {
                "technique": "T1078 - Valid Accounts",
                "tactic": "Privilege Escalation",
                "severity": "CRITICAL"
            },
            "new_user_created": {
                "technique": "T1136 - Create Account",
                "tactic": "Persistence",
                "severity": "HIGH"
            },
            "suspicious_process": {
                "technique": "T1059 - Command and Scripting Interpreter",
                "tactic": "Execution",
                "severity": "MEDIUM"
            },
            "lateral_movement": {
                "technique": "T1021 - Remote Services",
                "tactic": "Lateral Movement",
                "severity": "CRITICAL"
            },
            "data_exfiltration": {
                "technique": "T1048 - Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "severity": "CRITICAL"
            },
            "scheduled_task": {
                "technique": "T1053 - Scheduled Task/Job",
                "tactic": "Persistence",
                "severity": "MEDIUM"
            },
            "registry_modification": {
                "technique": "T1112 - Modify Registry",
                "tactic": "Defense Evasion",
                "severity": "MEDIUM"
            }
        }

        # Kill chain mapping
        self.kill_chain_mapping = {
            "failed_login": "Reconnaissance",
            "privilege_escalation": "Exploitation",
            "new_user_created": "Installation",
            "suspicious_process": "Execution",
            "lateral_movement": "Lateral Movement",
            "data_exfiltration": "Actions on Objectives",
            "scheduled_task": "Persistence",
            "registry_modification": "Installation"
        }

    def parse_windows_event_log(self, log_file: str) -> List[Dict]:
        events = []

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()

            log_entries = re.split(
                r'\n(?=Event ID:|Timestamp:|\d{4}-\d{2}-\d{2})',
                content
            )

            for entry in log_entries:
                if not entry.strip():
                    continue

                event = self._parse_single_event(entry)
                if event:
                    events.append(event)

        except Exception as e:
            print(f"Error parsing log file: {e}")

        return events

    def _parse_single_event(self, entry: str) -> Dict:
        event = {}

        timestamp_match = re.search(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            entry
        )
        if timestamp_match:
            event['timestamp'] = timestamp_match.group(1)

        event_id_match = re.search(
            r'Event ID[:\s]+(\d+)',
            entry,
            re.IGNORECASE
        )
        if event_id_match:
            event['event_id'] = event_id_match.group(1)

        source_match = re.search(
            r'(?:Source|Log Name)[:\s]+(.+?)(?:\n|$)',
            entry,
            re.IGNORECASE
        )
        if source_match:
            event['source'] = source_match.group(1).strip()

        desc_match = re.search(
            r'(?:Description|Message)[:\s]+(.+?)(?:\n\n|\n[A-Z]|$)',
            entry,
            re.IGNORECASE | re.DOTALL
        )
        if desc_match:
            event['description'] = desc_match.group(1).strip()

        user_match = re.search(
            r'(?:User|Account Name|Target User)[:\s]+(.+?)(?:\n|$)',
            entry,
            re.IGNORECASE
        )
        if user_match:
            event['user'] = user_match.group(1).strip()

        ip_match = re.search(
            r'(?:IP Address|Source IP|Client IP)[:\s]+(\d+\.\d+\.\d+\.\d+)',
            entry,
            re.IGNORECASE
        )
        if ip_match:
            event['ip_address'] = ip_match.group(1)

        event['raw'] = entry
        return event if event.get('event_id') else None

    def analyze_event_with_ai(self, event: Dict) -> Dict:
        return self._rule_based_analysis(event)

    def _rule_based_analysis(self, event: Dict) -> Dict:
        event_id = event.get('event_id', '')
        description = event.get('description', '').lower()

        suspicious_events = {
            '4625': ('failed_login', 'Failed login attempt detected'),
            '4672': ('privilege_escalation', 'Special privileges assigned to new logon'),
            '4720': ('new_user_created', 'New user account created'),
            '4688': ('suspicious_process', 'New process created'),
            '4648': ('lateral_movement', 'Logon attempt with explicit credentials'),
            '4698': ('scheduled_task', 'Scheduled task created'),
            '4657': ('registry_modification', 'Registry value modified'),
            '5140': ('data_exfiltration', 'Network share accessed'),
        }

        if event_id in suspicious_events:
            incident_type, explanation = suspicious_events[event_id]
            mitre_info = self.mitre_mappings.get(incident_type, {})

            return {
                "is_suspicious": True,
                "incident_type": incident_type,
                "mitre_technique": mitre_info.get('technique', 'Unknown'),
                "kill_chain_phase": self.kill_chain_mapping.get(incident_type, "Unknown"),
                "severity": mitre_info.get('severity', 'MEDIUM'),
                "explanation": explanation
            }

        return {
            "is_suspicious": False,
            "incident_type": "normal_activity",
            "mitre_technique": "N/A",
            "severity": "INFO",
            "explanation": "Normal system activity"
        }

    def generate_report(self, analyzed_events: List[Dict], output_file: str = None):
        report = {
    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "total_events": len(analyzed_events),
    "suspicious_events": len(
        [e for e in analyzed_events if e['analysis']['is_suspicious']]
    ),
    "severity_breakdown": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    },
    "incidents": []
}

        for event in analyzed_events:
            analysis = event['analysis']
            severity = analysis['severity']
            report['severity_breakdown'][severity] += 1

            if analysis['is_suspicious']:
                report['incidents'].append({
                    "timestamp": event.get('timestamp', 'Unknown'),
                    "event_id": event.get('event_id', 'Unknown'),
                    "user": event.get('user', 'Unknown'),
                    "ip_address": event.get('ip_address', 'N/A'),
                    "incident_type": analysis['incident_type'],
                    "mitre_technique": analysis['mitre_technique'],
                    "kill_chain_phase": analysis.get("kill_chain_phase", "Unknown"),
                    "severity": severity,
                    "explanation": analysis['explanation'],
                    "description": event.get('description', 'N/A')[:200]
                })

        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4
        }
        report['incidents'].sort(
            key=lambda x: severity_order.get(x['severity'], 5)
        )

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"\nReport saved to: {output_file}")

        return report

    def print_report(self, report: Dict):
        print("\n" + "=" * 80)
        print("SECURITY INCIDENT ANALYSIS REPORT")
        print("=" * 80)

        print(f"\nScan Time: {report['scan_time']}")
        print(f"Total Events Analyzed: {report['total_events']}")
        print(f"Suspicious Events Found: {report['suspicious_events']}")
        print("\n--- SEVERITY BREAKDOWN ---")
        for severity, count in report['severity_breakdown'].items():
            if count > 0:
                print(f"{severity}: {count}")

        if report['incidents']:
            print("\n--- INCIDENT DETAILS ---")
            for idx, incident in enumerate(report['incidents'], 1):
                print(f"\n[{idx}] {incident['severity']} - {incident['incident_type']}")
                print(f"    Time: {incident['timestamp']}")
                print(f"    User: {incident['user']}")
                print(f"    IP: {incident['ip_address']}")
                print(f"    Kill Chain: {incident['kill_chain_phase']}")
                print(f"    Event ID: {incident['event_id']}")
                print(f"    MITRE: {incident['mitre_technique']}")
                print(f"    Details: {incident['explanation']}")
        else:
            print("\nNo suspicious incidents detected.")

        print("\n" + "=" * 80)


def generate_html_report(report: Dict, output_file: str):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Incident Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .severity-bar-fill {{
            height: 30px;
            border-radius: 4px;
            display: flex;
            align-items: center;
            padding: 0 10px;
            color: white;
            font-weight: bold;
            margin: 10px 0;
        }}
        .CRITICAL {{ background-color: #e74c3c; }}
        .HIGH {{ background-color: #e67e22; }}
        .MEDIUM {{ background-color: #f39c12; }}
        .INFO {{ background-color: #95a5a6; }}
        .incident {{
            border-left: 4px solid #3498db;
            margin: 15px 0;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Incident Analysis Report</h1>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Events</h3>
                <p>{report['total_events']}</p>
            </div>
            <div class="summary-card">
                <h3>Suspicious Events</h3>
                <p>{report['suspicious_events']}</p>
            </div>
        </div>
"""

    for severity, count in report["severity_breakdown"].items():
        if count > 0:
            html += f"""
        <div class="severity-bar-fill {severity}">
            {severity}: {count}
        </div>
"""

    html += "<h2>Incident Details</h2>"

    for idx, incident in enumerate(report["incidents"], 1):
        html += f"""
        <div class="incident">
            <strong>#{idx} {incident['incident_type']}</strong><br>
            Severity: {incident['severity']}<br>
            MITRE: {incident['mitre_technique']}<br>
            Kill Chain: {incident['kill_chain_phase']}<br>
            User: {incident['user']}<br>
            Event ID: {incident['event_id']}<br>
            Details: {incident['explanation']}
        </div>
"""

    html += """
    </div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)



def main():
    print("AI-Powered Security Log Analyzer")
    print("=" * 50)

    analyzer = SecurityLogAnalyzer()
    log_file = "sample_security_logs.txt"

    print(f"\nParsing log file: {log_file}")
    events = analyzer.parse_windows_event_log(log_file)
    print(f"Found {len(events)} events")

    print("\nAnalyzing events...")
    analyzed_events = []

    for idx, event in enumerate(events, 1):
        print(f"Processing event {idx}/{len(events)}...", end='\r')
        event['analysis'] = analyzer.analyze_event_with_ai(event)
        analyzed_events.append(event)

    print("\nAnalysis complete!")

    report = analyzer.generate_report(
        analyzed_events,
        "security_report.json"
    )

    analyzer.print_report(report)

    generate_html_report(report, "security_report.html")
    print("\nHTML report generated: security_report.html")


if __name__ == "__main__":
    main()
