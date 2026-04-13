# AI-Powered Security Log Analyzer

## 🛡️ Project Overview

An intelligent security log analysis tool that automatically detects threats, maps incidents to the MITRE ATT&CK framework, and generates comprehensive security reports. This project demonstrates proficiency in security analysis, Python automation, AI integration, and incident response.

##  Key Features

- **Automated Threat Detection**: Parses Windows Event Logs and identifies suspicious activities
- **MITRE ATT&CK Mapping**: Automatically maps detected threats to MITRE ATT&CK techniques
- **AI-Powered Analysis**: Integrates with Claude AI API for intelligent threat classification (with rule-based fallback)
- **Severity Scoring**: Categorizes incidents as CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **Multi-Format Reports**: Generates JSON and HTML security reports
- **Email Alerts**: Sends automated notifications for critical security incidents

##  Technologies Used

- **Python 3.x**
- **Claude AI API** (Anthropic)
- **Windows Event Logs** (Security Event IDs)
- **MITRE ATT&CK Framework**
- **HTML/CSS** for reporting
- **SMTP** for email notifications

##  Detected Threat Types

| Threat Type | MITRE Technique | Event ID | Severity |
|------------|-----------------|----------|----------|
| Brute Force Attack | T1110 | 4625 | HIGH |
| Privilege Escalation | T1078 | 4672 | CRITICAL |
| Account Creation | T1136 | 4720 | HIGH |
| Suspicious Process | T1059 | 4688 | MEDIUM |
| Lateral Movement | T1021 | 4648 | CRITICAL |
| Data Exfiltration | T1048 | 5140 | CRITICAL |
| Scheduled Task | T1053 | 4698 | MEDIUM |
| Registry Modification | T1112 | 4657 | MEDIUM |

##  Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup Steps

1. **Clone/Download the project**
```bash
cd security_log_analyzer
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure API Key (Optional)**

For AI-powered analysis, set your Anthropic API key:
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

Or edit `log_analyzer.py` and set the `api_key` variable.

**Note**: The tool works without an API key using rule-based analysis.

##  Usage

### Basic Usage

```bash
python log_analyzer.py
```

This will:
1. Parse `sample_security_logs.txt`
2. Analyze all security events
3. Generate `security_report.json`
4. Generate `security_report.html`
5. Display summary in terminal

### Analyzing Your Own Logs

1. **Prepare your log file** in Windows Event Log format
2. **Update the log file path** in `log_analyzer.py`:
```python
log_file = "your_security_logs.txt"
```
3. **Run the analyzer**:
```bash
python log_analyzer.py
```

### Using Email Alerts

```python
from email_alerter import EmailAlerter

# Configure email settings
alerter = EmailAlerter(
    smtp_server="smtp.gmail.com",
    smtp_port=587,
    sender_email="your-email@gmail.com",
    sender_password="your-app-password"
)

# Send alerts for critical incidents
critical_incidents = [i for i in incidents if i['severity'] in ['CRITICAL', 'HIGH']]
alerter.send_alert("security-team@company.com", critical_incidents)
```

##  Output Examples

### Terminal Output
```
AI-Powered Security Log Analyzer
==================================================

Parsing log file: sample_security_logs.txt
Found 15 events

Analyzing events...
Analysis complete!

================================================================================
SECURITY INCIDENT ANALYSIS REPORT
================================================================================

Scan Time: 2024-04-13 18:30:45
Total Events Analyzed: 15
Suspicious Events Found: 12

--- SEVERITY BREAKDOWN ---
CRITICAL: 3
HIGH: 5
MEDIUM: 4

--- CRITICAL & HIGH SEVERITY INCIDENTS ---

[1] CRITICAL - privilege_escalation
    Time: 2024-04-13 08:45:30
    User: dbadmin
    IP: N/A
    MITRE: T1078 - Valid Accounts
    Details: Special privileges assigned to new logon
```

### JSON Report Structure
```json
{
  "scan_time": "2024-04-13 18:30:45",
  "total_events": 15,
  "suspicious_events": 12,
  "severity_breakdown": {
    "CRITICAL": 3,
    "HIGH": 5,
    "MEDIUM": 4,
    "LOW": 0,
    "INFO": 3
  },
  "incidents": [...]
}
```

### HTML Report
The HTML report includes:
- Visual severity breakdown with color-coded bars
- Interactive incident cards with full details
- MITRE ATT&CK technique tags
- Sortable incident list
- Professional styling

## 🔍 How It Works

### 1. Log Parsing
```python
# Extracts key fields from Windows Event Logs
- Event ID
- Timestamp
- User Account
- IP Address
- Description
- Source
```

### 2. Threat Analysis

**AI-Powered Mode** (with API key):
- Sends event details to Claude AI
- Gets intelligent threat classification
- Receives MITRE ATT&CK mapping
- Determines severity level

**Rule-Based Mode** (fallback):
- Matches Event IDs to known threats
- Keyword-based detection
- Predefined MITRE mappings
- Severity assignment

### 3. Report Generation
- Aggregates all incidents
- Sorts by severity
- Generates JSON for programmatic access
- Creates HTML for human review
- Triggers email alerts for critical events

##  Technical Skills Demonstrated

### Security Knowledge
-  Windows Event Log analysis
-  MITRE ATT&CK framework
-  Cyber Kill Chain concepts
-  Incident classification
-  Threat detection methodologies

### Programming & Automation
-  Python scripting
-  API integration (Claude AI)
-  Regular expressions for log parsing
-  JSON data handling
-  HTML report generation

### Cloud & AI Concepts
-  API usage and authentication
-  LLM integration
-  RESTful API calls
-  Error handling and fallbacks

### Security Operations
-  Automated alerting
-  Incident response workflows
-  Security reporting
-  SIEM-like functionality

##  Project Structure

```
security_log_analyzer/
├── log_analyzer.py              # Main analysis engine
├── email_alerter.py             # Email notification module
├── sample_security_logs.txt     # Sample Windows Event Logs
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── security_report.json         # Generated JSON report
└── security_report.html         # Generated HTML report
```

##  Security Best Practices

- Never commit API keys to version control
- Use environment variables for sensitive data
- Implement rate limiting for API calls
- Validate and sanitize all log inputs
- Use encrypted connections (SMTP TLS)
- Implement proper error handling

##  Future Enhancements

- [ ] Real-time log monitoring
- [ ] Integration with SIEM platforms
- [ ] Machine learning for anomaly detection
- [ ] Support for multiple log formats (Syslog, CEF, JSON)
- [ ] Dashboard with live statistics
- [ ] Threat intelligence feed integration
- [ ] Automated response actions
- [ ] Multi-tenant support

##  Use Cases

1. **Security Monitoring**: Continuous analysis of Windows security logs
2. **Incident Response**: Quick identification of security incidents
3. **Compliance Auditing**: Generate reports for compliance requirements
4. **Threat Hunting**: Proactive search for indicators of compromise
5. **Training**: Educational tool for learning security analysis

##  Interview Talking Points

When discussing this project in your Netenrich interview:

1. **Problem Statement**: Organizations generate massive amounts of security logs daily, making manual analysis impossible

2. **Your Solution**: Automated tool that intelligently analyzes logs, identifies threats, and provides actionable insights

3. **Technical Decisions**:
   - Why Python? (Industry standard for security automation)
   - Why MITRE ATT&CK? (Industry framework for threat categorization)
   - AI + Rule-based approach? (Best of both worlds - intelligent with reliable fallback)

4. **Real-World Application**:
   - Can be integrated into SOC workflows
   - Reduces MTTD (Mean Time To Detect)
   - Automates Tier 1 analyst tasks
   - Provides MITRE mapping for faster response

5. **Scalability**: 
   - Can process thousands of events
   - Modular design for easy extension
   - API-based for cloud deployment

##  Learning Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Python Security Tools](https://pypi.org/search/?q=security)




Created as a portfolio project demonstrating security analysis and automation skills.



**Note**: This is a demonstration project. For production use, additional features like input validation, comprehensive error handling, logging, and security hardening would be required.
