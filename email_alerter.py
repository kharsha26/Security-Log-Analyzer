"""
Email Alert Module for Security Incidents
Sends email notifications for critical security events
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict
from datetime import datetime

class EmailAlerter:
    def __init__(self, smtp_server: str = "smtp.gmail.com", 
                 smtp_port: int = 587,
                 sender_email: str = None,
                 sender_password: str = None):
        """Initialize email alerter"""
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
    
    def send_alert(self, recipient_email: str, incidents: List[Dict]):
        """Send email alert for critical incidents"""
        if not self.sender_email or not self.sender_password:
            print("Email credentials not configured. Alert would be sent to:", recipient_email)
            self._print_alert(incidents)
            return
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f" SECURITY ALERT: {len(incidents)} Critical Incidents Detected"
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            
            # Create email body
            html_body = self._create_email_body(incidents)
            text_body = self._create_text_body(incidents)
            
            # Attach both plain text and HTML versions
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            print(f" Alert email sent to {recipient_email}")
            
        except Exception as e:
            print(f" Error sending email: {e}")
            print("Alert details printed below:")
            self._print_alert(incidents)
    
    def _create_email_body(self, incidents: List[Dict]) -> str:
        """Create HTML email body"""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #e74c3c; color: white; padding: 20px; text-align: center; }}
                .incident {{ border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; background-color: #f8f9fa; }}
                .critical {{ border-left-color: #e74c3c; }}
                .high {{ border-left-color: #e67e22; }}
                .timestamp {{ color: #7f8c8d; font-size: 12px; }}
                .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }}
                .severity.CRITICAL {{ background-color: #e74c3c; }}
                .severity.HIGH {{ background-color: #e67e22; }}
                .mitre {{ background-color: #3498db; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1> Security Alert</h1>
                <p>{len(incidents)} Critical/High Severity Incidents Detected</p>
                <p>Scan Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            <div style="padding: 20px;">
        """
        
        for idx, incident in enumerate(incidents, 1):
            severity_class = incident['severity'].lower()
            html += f"""
                <div class="incident {severity_class}">
                    <h3>Incident #{idx}: {incident['incident_type'].replace('_', ' ').title()}</h3>
                    <span class="severity {incident['severity']}">{incident['severity']}</span>
                    <span class="mitre">{incident['mitre_technique']}</span>
                    <p class="timestamp">⏰ {incident['timestamp']}</p>
                    <p><strong>User:</strong> {incident['user']}</p>
                    <p><strong>IP Address:</strong> {incident['ip_address']}</p>
                    <p><strong>Event ID:</strong> {incident['event_id']}</p>
                    <p><strong>Details:</strong> {incident['explanation']}</p>
                    <p><strong>Description:</strong> {incident['description']}</p>
                </div>
            """
        
        html += """
            </div>
            <div style="background-color: #ecf0f1; padding: 20px; text-align: center; margin-top: 20px;">
                <p><strong> Immediate Action Required</strong></p>
                <p>Please review these incidents and take appropriate security measures.</p>
                <p style="font-size: 12px; color: #7f8c8d;">
                    This is an automated alert from Security Log Analyzer
                </p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _create_text_body(self, incidents: List[Dict]) -> str:
        """Create plain text email body"""
        text = f"""
SECURITY ALERT
{'='*60}

{len(incidents)} Critical/High Severity Incidents Detected
Scan Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

INCIDENT DETAILS:
{'='*60}
"""
        
        for idx, incident in enumerate(incidents, 1):
            text += f"""
Incident #{idx}: {incident['incident_type'].replace('_', ' ').title()}
Severity: {incident['severity']}
MITRE ATT&CK: {incident['mitre_technique']}
Time: {incident['timestamp']}
User: {incident['user']}
IP Address: {incident['ip_address']}
Event ID: {incident['event_id']}
Details: {incident['explanation']}
Description: {incident['description']}
{'-'*60}
"""
        
        text += """
⚠️  IMMEDIATE ACTION REQUIRED
Please review these incidents and take appropriate security measures.

---
This is an automated alert from Security Log Analyzer
"""
        return text
    
    def _print_alert(self, incidents: List[Dict]):
        """Print alert to console when email is not configured"""
        print("\n" + "="*80)
        print("🚨 SECURITY ALERT - EMAIL NOTIFICATION")
        print("="*80)
        print(f"\nDetected {len(incidents)} Critical/High Severity Incidents")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        for idx, incident in enumerate(incidents, 1):
            print(f"[{idx}] {incident['severity']} - {incident['incident_type'].replace('_', ' ').title()}")
            print(f"    MITRE: {incident['mitre_technique']}")
            print(f"    User: {incident['user']} | IP: {incident['ip_address']}")
            print(f"    Time: {incident['timestamp']}")
            print(f"    Details: {incident['explanation']}\n")
        
        print("="*80)

# Example usage
if __name__ == "__main__":
    # Sample critical incidents
    sample_incidents = [
        {
            "timestamp": "2024-04-13 08:15:23",
            "event_id": "4625",
            "user": "Administrator",
            "ip_address": "192.168.1.105",
            "incident_type": "failed_login",
            "mitre_technique": "T1110 - Brute Force",
            "severity": "HIGH",
            "explanation": "Multiple failed login attempts detected",
            "description": "An account failed to log on - brute force attack suspected"
        }
    ]
    
    # Initialize alerter
    alerter = EmailAlerter()
    
    # Send alert (will print to console if email not configured)
    alerter.send_alert("security-team@company.com", sample_incidents)
