# """
# AI-Powered Security Log Analyzer
# Analyzes security logs and maps threats to MITRE ATT&CK framework
# """

# import json
# import re
# from datetime import datetime
# from typing import List, Dict
# import requests

# class SecurityLogAnalyzer:
#     def __init__(self, api_key: str = None):
#         """Initialize the analyzer with optional API key"""
#         self.api_key = api_key
#         self.api_url = "https://api.anthropic.com/v1/messages"
        
#         # MITRE ATT&CK technique mappings
#         self.mitre_mappings = {
#             "failed_login": {
#                 "technique": "T1110 - Brute Force",
#                 "tactic": "Credential Access",
#                 "severity": "HIGH"
#             },
#             "privilege_escalation": {
#                 "technique": "T1078 - Valid Accounts",
#                 "tactic": "Privilege Escalation",
#                 "severity": "CRITICAL"
#             },
#             "new_user_created": {
#                 "technique": "T1136 - Create Account",
#                 "tactic": "Persistence",
#                 "severity": "HIGH"
#             },
#             "suspicious_process": {
#                 "technique": "T1059 - Command and Scripting Interpreter",
#                 "tactic": "Execution",
#                 "severity": "MEDIUM"
#             },
#             "lateral_movement": {
#                 "technique": "T1021 - Remote Services",
#                 "tactic": "Lateral Movement",
#                 "severity": "CRITICAL"
#             },
#             "data_exfiltration": {
#                 "technique": "T1048 - Exfiltration Over Alternative Protocol",
#                 "tactic": "Exfiltration",
#                 "severity": "CRITICAL"
#             },
#             "scheduled_task": {
#                 "technique": "T1053 - Scheduled Task/Job",
#                 "tactic": "Persistence",
#                 "severity": "MEDIUM"
#             },
#             "registry_modification": {
#                 "technique": "T1112 - Modify Registry",
#                 "tactic": "Defense Evasion",
#                 "severity": "MEDIUM"
#             }
#         }
    
#     def parse_windows_event_log(self, log_file: str) -> List[Dict]:
#         """Parse Windows Event Log format"""
#         events = []
        
#         try:
#             with open(log_file, 'r', encoding='utf-8') as f:
#                 content = f.read()
                
#             # Split by event entries
#             log_entries = re.split(r'\n(?=Event ID:|Timestamp:|\d{4}-\d{2}-\d{2})', content)
            
#             for entry in log_entries:
#                 if not entry.strip():
#                     continue
                    
#                 event = self._parse_single_event(entry)
#                 if event:
#                     events.append(event)
                    
#         except Exception as e:
#             print(f"Error parsing log file: {e}")
            
#         return events
    
#     def _parse_single_event(self, entry: str) -> Dict:
#         """Parse a single log entry"""
#         event = {}
        
#         # Extract timestamp
#         timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', entry)
#         if timestamp_match:
#             event['timestamp'] = timestamp_match.group(1)
        
#         # Extract Event ID
#         event_id_match = re.search(r'Event ID[:\s]+(\d+)', entry, re.IGNORECASE)
#         if event_id_match:
#             event['event_id'] = event_id_match.group(1)
        
#         # Extract source/log name
#         source_match = re.search(r'(?:Source|Log Name)[:\s]+(.+?)(?:\n|$)', entry, re.IGNORECASE)
#         if source_match:
#             event['source'] = source_match.group(1).strip()
        
#         # Extract description/message
#         desc_match = re.search(r'(?:Description|Message)[:\s]+(.+?)(?:\n\n|\n[A-Z]|$)', entry, re.IGNORECASE | re.DOTALL)
#         if desc_match:
#             event['description'] = desc_match.group(1).strip()
        
#         # Extract username if present
#         user_match = re.search(r'(?:User|Account Name|Target User)[:\s]+(.+?)(?:\n|$)', entry, re.IGNORECASE)
#         if user_match:
#             event['user'] = user_match.group(1).strip()
        
#         # Extract IP if present
#         ip_match = re.search(r'(?:IP Address|Source IP|Client IP)[:\s]+(\d+\.\d+\.\d+\.\d+)', entry, re.IGNORECASE)
#         if ip_match:
#             event['ip_address'] = ip_match.group(1)
        
#         event['raw'] = entry
        
#         return event if event.get('event_id') else None
    
#     def analyze_event_with_ai(self, event: Dict) -> Dict:
#         """Analyze event using AI (Claude API)"""
#         if not self.api_key:
#             # Fallback to rule-based analysis if no API key
#             return self._rule_based_analysis(event)
        
#         try:
#             prompt = f"""Analyze this security event and determine:
# 1. Is it suspicious or malicious? (YES/NO)
# 2. What type of security incident is it?
# 3. MITRE ATT&CK technique (if applicable)
# 4. Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
# 5. Brief explanation

# Event Details:
# Event ID: {event.get('event_id', 'N/A')}
# Source: {event.get('source', 'N/A')}
# User: {event.get('user', 'N/A')}
# IP: {event.get('ip_address', 'N/A')}
# Description: {event.get('description', 'N/A')}

# Respond in JSON format:
# {{
#     "is_suspicious": true/false,
#     "incident_type": "type",
#     "mitre_technique": "T#### - Name",
#     "severity": "LEVEL",
#     "explanation": "brief explanation"
# }}"""

#             headers = {
#                 "Content-Type": "application/json",
#                 "x-api-key": self.api_key,
#                 "anthropic-version": "2023-06-01"
#             }
            
#             data = {
#                 "model": "claude-sonnet-4-20250514",
#                 "max_tokens": 1024,
#                 "messages": [
#                     {"role": "user", "content": prompt}
#                 ]
#             }
            
#             response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            
#             if response.status_code == 200:
#                 result = response.json()
#                 content = result['content'][0]['text']
                
#                 # Extract JSON from response
#                 json_match = re.search(r'\{.*\}', content, re.DOTALL)
#                 if json_match:
#                     analysis = json.loads(json_match.group())
#                     return analysis
            
#             # Fallback to rule-based if API fails
#             return self._rule_based_analysis(event)
            
#         except Exception as e:
#             print(f"AI analysis error: {e}")
#             return self._rule_based_analysis(event)
    
#     def _rule_based_analysis(self, event: Dict) -> Dict:
#         """Rule-based analysis as fallback"""
#         event_id = event.get('event_id', '')
#         description = event.get('description', '').lower()
        
#         # Windows Event ID mappings
#         suspicious_events = {
#             '4625': ('failed_login', 'Failed login attempt detected'),
#             '4672': ('privilege_escalation', 'Special privileges assigned to new logon'),
#             '4720': ('new_user_created', 'New user account created'),
#             '4688': ('suspicious_process', 'New process created'),
#             '4648': ('lateral_movement', 'Logon attempt with explicit credentials'),
#             '4698': ('scheduled_task', 'Scheduled task created'),
#             '4657': ('registry_modification', 'Registry value modified'),
#             '5140': ('data_exfiltration', 'Network share accessed'),
#         }
        
#         # Check for known suspicious event IDs
#         if event_id in suspicious_events:
#             incident_type, explanation = suspicious_events[event_id]
#             mitre_info = self.mitre_mappings.get(incident_type, {})
            
#             return {
#                 "is_suspicious": True,
#                 "incident_type": incident_type,
#                 "mitre_technique": mitre_info.get('technique', 'Unknown'),
#                 "severity": mitre_info.get('severity', 'MEDIUM'),
#                 "explanation": explanation
#             }
        
#         # Keyword-based detection
#         suspicious_keywords = [
#             ('failed', 'failed_login'),
#             ('brute force', 'failed_login'),
#             ('privilege', 'privilege_escalation'),
#             ('administrator', 'privilege_escalation'),
#             ('mimikatz', 'suspicious_process'),
#             ('powershell -enc', 'suspicious_process'),
#             ('remote desktop', 'lateral_movement'),
#             ('psexec', 'lateral_movement'),
#         ]
        
#         for keyword, incident_type in suspicious_keywords:
#             if keyword in description:
#                 mitre_info = self.mitre_mappings.get(incident_type, {})
#                 return {
#                     "is_suspicious": True,
#                     "incident_type": incident_type,
#                     "mitre_technique": mitre_info.get('technique', 'Unknown'),
#                     "severity": mitre_info.get('severity', 'MEDIUM'),
#                     "explanation": f"Suspicious keyword detected: {keyword}"
#                 }
        
#         return {
#             "is_suspicious": False,
#             "incident_type": "normal_activity",
#             "mitre_technique": "N/A",
#             "severity": "INFO",
#             "explanation": "Normal system activity"
#         }
    
#     def generate_report(self, analyzed_events: List[Dict], output_file: str = None):
#         """Generate security incident report"""
#         report = {
#             "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#             "total_events": len(analyzed_events),
#             "suspicious_events": len([e for e in analyzed_events if e['analysis']['is_suspicious']]),
#             "severity_breakdown": {
#                 "CRITICAL": 0,
#                 "HIGH": 0,
#                 "MEDIUM": 0,
#                 "LOW": 0,
#                 "INFO": 0
#             },
#             "incidents": []
#         }
        
#         for event in analyzed_events:
#             analysis = event['analysis']
#             severity = analysis['severity']
#             report['severity_breakdown'][severity] += 1
            
#             if analysis['is_suspicious']:
#                 incident = {
#                     "timestamp": event.get('timestamp', 'Unknown'),
#                     "event_id": event.get('event_id', 'Unknown'),
#                     "user": event.get('user', 'Unknown'),
#                     "ip_address": event.get('ip_address', 'N/A'),
#                     "incident_type": analysis['incident_type'],
#                     "mitre_technique": analysis['mitre_technique'],
#                     "severity": severity,
#                     "explanation": analysis['explanation'],
#                     "description": event.get('description', 'N/A')[:200]
#                 }
#                 report['incidents'].append(incident)
        
#         # Sort incidents by severity
#         severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
#         report['incidents'].sort(key=lambda x: severity_order.get(x['severity'], 5))
        
#         if output_file:
#             with open(output_file, 'w') as f:
#                 json.dump(report, f, indent=2)
#             print(f"\nReport saved to: {output_file}")
        
#         return report
    
#     def print_report(self, report: Dict):
#         """Print formatted report to console"""
#         print("\n" + "="*80)
#         print("SECURITY INCIDENT ANALYSIS REPORT")
#         print("="*80)
#         print(f"\nScan Time: {report['scan_time']}")
#         print(f"Total Events Analyzed: {report['total_events']}")
#         print(f"Suspicious Events Found: {report['suspicious_events']}")
        
#         print("\n--- SEVERITY BREAKDOWN ---")
#         for severity, count in report['severity_breakdown'].items():
#             if count > 0:
#                 print(f"{severity}: {count}")
        
#         if report['incidents']:
#             print("\n--- CRITICAL & HIGH SEVERITY INCIDENTS ---")
#             for idx, incident in enumerate(report['incidents'][:10], 1):  # Top 10
#                 if incident['severity'] in ['CRITICAL', 'HIGH']:
#                     print(f"\n[{idx}] {incident['severity']} - {incident['incident_type']}")
#                     print(f"    Time: {incident['timestamp']}")
#                     print(f"    User: {incident['user']}")
#                     print(f"    IP: {incident['ip_address']}")
#                     print(f"    MITRE: {incident['mitre_technique']}")
#                     print(f"    Details: {incident['explanation']}")
#         else:
#             print("\nNo suspicious incidents detected.")
        
#         print("\n" + "="*80)

# def main():
#     """Main execution function"""
#     print("AI-Powered Security Log Analyzer")
#     print("="*50)
    
#     # Option to use API key (can be None for demo)
#     api_key = None  # Set to your API key or use environment variable
    
#     # You can also get from environment
#     # import os
#     # api_key = os.getenv('ANTHROPIC_API_KEY')
    
#     analyzer = SecurityLogAnalyzer(api_key=api_key)
    
#     # Parse log file
#     log_file = "sample_security_logs.txt"
#     print(f"\nParsing log file: {log_file}")
#     events = analyzer.parse_windows_event_log(log_file)
#     print(f"Found {len(events)} events")
    
#     # Analyze each event
#     print("\nAnalyzing events...")
#     analyzed_events = []
#     for idx, event in enumerate(events, 1):
#         print(f"Processing event {idx}/{len(events)}...", end='\r')
#         analysis = analyzer.analyze_event_with_ai(event)
#         event['analysis'] = analysis
#         analyzed_events.append(event)
    
#     print("\nAnalysis complete!")
    
#     # Generate and display report
#     report = analyzer.generate_report(analyzed_events, "security_report.json")
#     analyzer.print_report(report)
    
#     # Generate HTML report
#     generate_html_report(report, "security_report.html")
#     print("\nHTML report generated: security_report.html")

# def generate_html_report(report: Dict, output_file: str):
#     """Generate HTML report"""
#     html = f"""<!DOCTYPE html>
# <html>
# <head>
#     <title>Security Incident Report</title>
#     <style>
#         body {{
#             font-family: Arial, sans-serif;
#             margin: 20px;
#             background-color: #f5f5f5;
#         }}
#         .container {{
#             max-width: 1200px;
#             margin: 0 auto;
#             background-color: white;
#             padding: 30px;
#             border-radius: 8px;
#             box-shadow: 0 2px 4px rgba(0,0,0,0.1);
#         }}
#         h1 {{
#             color: #2c3e50;
#             border-bottom: 3px solid #3498db;
#             padding-bottom: 10px;
#         }}
#         .summary {{
#             display: grid;
#             grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
#             gap: 15px;
#             margin: 20px 0;
#         }}
#         .summary-card {{
#             background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
#             color: white;
#             padding: 20px;
#             border-radius: 8px;
#             text-align: center;
#         }}
#         .summary-card h3 {{
#             margin: 0;
#             font-size: 14px;
#             opacity: 0.9;
#         }}
#         .summary-card p {{
#             margin: 10px 0 0 0;
#             font-size: 32px;
#             font-weight: bold;
#         }}
#         .severity-chart {{
#             margin: 20px 0;
#             padding: 20px;
#             background-color: #f8f9fa;
#             border-radius: 8px;
#         }}
#         .severity-bar {{
#             margin: 10px 0;
#         }}
#         .severity-bar-fill {{
#             height: 30px;
#             border-radius: 4px;
#             display: flex;
#             align-items: center;
#             padding: 0 10px;
#             color: white;
#             font-weight: bold;
#         }}
#         .CRITICAL {{ background-color: #e74c3c; }}
#         .HIGH {{ background-color: #e67e22; }}
#         .MEDIUM {{ background-color: #f39c12; }}
#         .LOW {{ background-color: #3498db; }}
#         .INFO {{ background-color: #95a5a6; }}
#         .incident {{
#             border-left: 4px solid #3498db;
#             margin: 15px 0;
#             padding: 15px;
#             background-color: #f8f9fa;
#             border-radius: 4px;
#         }}
#         .incident.CRITICAL {{
#             border-left-color: #e74c3c;
#             background-color: #fadbd8;
#         }}
#         .incident.HIGH {{
#             border-left-color: #e67e22;
#             background-color: #fae5d3;
#         }}
#         .incident-header {{
#             display: flex;
#             justify-content: space-between;
#             align-items: center;
#             margin-bottom: 10px;
#         }}
#         .incident-title {{
#             font-weight: bold;
#             font-size: 16px;
#         }}
#         .severity-badge {{
#             padding: 5px 15px;
#             border-radius: 20px;
#             color: white;
#             font-size: 12px;
#             font-weight: bold;
#         }}
#         .incident-details {{
#             font-size: 14px;
#             line-height: 1.6;
#         }}
#         .mitre-tag {{
#             display: inline-block;
#             background-color: #3498db;
#             color: white;
#             padding: 3px 10px;
#             border-radius: 3px;
#             font-size: 12px;
#             margin: 5px 5px 5px 0;
#         }}
#     </style>
# </head>
# <body>
#     <div class="container">
#         <h1>🛡️ Security Incident Analysis Report</h1>
        
#         <div class="summary">
#             <div class="summary-card">
#                 <h3>Scan Time</h3>
#                 <p style="font-size: 14px;">{report['scan_time']}</p>
#             </div>
#             <div class="summary-card">
#                 <h3>Total Events</h3>
#                 <p>{report['total_events']}</p>
#             </div>
#             <div class="summary-card">
#                 <h3>Suspicious Events</h3>
#                 <p>{report['suspicious_events']}</p>
#             </div>
#         </div>
        
#         <div class="severity-chart">
#             <h2>Severity Breakdown</h2>
# """
    
#     # Add severity bars
#     max_count = max(report['severity_breakdown'].values()) if report['severity_breakdown'].values() else 1
#     for severity, count in report['severity_breakdown'].items():
#         if count > 0:
#             width = (count / max_count * 100) if max_count > 0 else 0
#             html += f"""
#             <div class="severity-bar">
#                 <div class="severity-bar-fill {severity}" style="width: {width}%;">
#                     {severity}: {count}
#                 </div>
#             </div>
# """
    
#     html += """
#         </div>
        
#         <h2>Incident Details</h2>
# """
    
#     # Add incidents
#     if report['incidents']:
#         for idx, incident in enumerate(report['incidents'], 1):
#             html += f"""
#         <div class="incident {incident['severity']}">
#             <div class="incident-header">
#                 <div class="incident-title">#{idx} - {incident['incident_type'].replace('_', ' ').title()}</div>
#                 <span class="severity-badge {incident['severity']}">{incident['severity']}</span>
#             </div>
#             <div class="incident-details">
#                 <strong>Time:</strong> {incident['timestamp']}<br>
#                 <strong>User:</strong> {incident['user']}<br>
#                 <strong>IP Address:</strong> {incident['ip_address']}<br>
#                 <strong>Event ID:</strong> {incident['event_id']}<br>
#                 <span class="mitre-tag">🎯 {incident['mitre_technique']}</span><br>
#                 <strong>Explanation:</strong> {incident['explanation']}<br>
#                 <strong>Description:</strong> {incident['description']}
#             </div>
#         </div>
# """
#     else:
#         html += "<p>No suspicious incidents detected.</p>"
    
#         html += """
#     </div>
# </body>
# </html>
# """
    
#     with open(output_file, "w", encoding="utf-8") as f:
#         f.write(html)

# if __name__ == "__main__":
#     main()














"""
AI-Powered Security Log Analyzer
Analyzes security logs and maps threats to MITRE ATT&CK framework
"""

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
                print(f"    Event ID: {incident['event_id']}")
                print(f"    MITRE: {incident['mitre_technique']}")
                print(f"    Details: {incident['explanation']}")
        else:
            print("\nNo suspicious incidents detected.")

        print("\n" + "=" * 80)


# def generate_html_report(report: Dict, output_file: str):
#     html = f"""<!DOCTYPE html>
# <html>
# <head>
#     <meta charset="UTF-8">
#     <title>Security Incident Report</title>
# </head>
# <body>
#     <h1>🛡️ Security Incident Analysis Report</h1>
#     <p>Total Events: {report['total_events']}</p>
#     <p>Suspicious Events: {report['suspicious_events']}</p>
# </body>
# </html>
# """

#     with open(output_file, "w", encoding="utf-8") as f:
#         f.write(html)


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