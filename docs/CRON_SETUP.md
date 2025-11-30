# Cron Source Configuration Guide

## Overview

The **cron source type** is designed for scheduled, automated log analysis. It's typically used to:
- Analyze logs periodically (e.g., every 5 minutes)
- Monitor security events continuously
- Generate regular reports without manual intervention

## Configuration

### Cron with Splunk Backend (Recommended)

This is the primary use case for cron source - querying Splunk every 5 minutes:

```json
{
  "source_type": "cron",
  "user_query": "Phân tích log định kỳ mỗi 5 phút",
  "log_source": {
    "type": "splunk",
    "index": "web_iis",
    "sourcetype": "modsec:dvwa",
    "earliest_time": "-5m",
    "latest_time": "now",
    "search_filter": ""
  }
}
```

**Parameters:**
- `index`: Splunk index to query (e.g., "web_iis")
- `sourcetype`: Log source type (e.g., "modsec:dvwa" for ModSecurity DVWA logs)
- `earliest_time`: Start of time range (e.g., "-5m" for last 5 minutes)
- `latest_time`: End of time range (typically "now")
- `search_filter`: Optional additional Splunk search filter

### Cron with File Backend (Alternative)

For testing or environments without Splunk:

```json
{
  "source_type": "cron",
  "user_query": "Phân tích log định kỳ từ file",
  "log_source": {
    "type": "file",
    "path": "/var/log/apache2/access.log",
    "max_lines": 1000
  }
}
```

## Scheduling with Cron

### Linux/Unix Cron Job

Create a cron job to run analysis every 5 minutes:

```bash
# Edit crontab
crontab -e

# Add this line (runs every 5 minutes)
*/5 * * * * /usr/bin/python3 /path/to/run_cron_analysis.py >> /var/log/v1-analyzer-cron.log 2>&1
```

### Example Cron Script

Create `run_cron_analysis.py`:

```python
#!/usr/bin/env python3
"""
Cron script for scheduled log analysis.
Runs every 5 minutes to analyze Splunk logs.
"""

import requests
import json
from datetime import datetime

API_URL = "http://127.0.0.1:8000/analyze"

def run_analysis():
    """Run scheduled analysis."""
    request = {
        "source_type": "cron",
        "user_query": "Scheduled security analysis - every 5 minutes",
        "log_source": {
            "type": "splunk",
            "index": "web_iis",
            "sourcetype": "modsec:dvwa",
            "earliest_time": "-5m",
            "latest_time": "now",
            "search_filter": ""
        }
    }
    
    print(f"[{datetime.now()}] Starting scheduled analysis...")
    
    try:
        response = requests.post(API_URL, json=request, timeout=300)
        
        if response.status_code == 200:
            data = response.json()
            findings = data["findings_summary"]
            
            print(f"✓ Analysis complete")
            print(f"  Total Events: {findings['total_events']}")
            print(f"  Attack Events: {findings['total_attack_events']}")
            print(f"  Severity: {findings['severity_level']}")
            
            if findings['has_attack']:
                print(f"  ⚠ ALERT: {findings['total_attack_events']} attacks detected!")
                # TODO: Send notification (email, Telegram, etc.)
            
            if data["attack_events_ref"]["csv_path"]:
                print(f"  Report: {data['attack_events_ref']['csv_path']}")
        else:
            print(f"✗ Analysis failed: {response.status_code}")
            print(f"  {response.text}")
    
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    run_analysis()
```

Make it executable:
```bash
chmod +x run_cron_analysis.py
```

### Windows Task Scheduler

For Windows environments:

1. Open Task Scheduler
2. Create Basic Task
3. Trigger: Repeat every 5 minutes
4. Action: Start a program
   - Program: `python`
   - Arguments: `C:\path\to\run_cron_analysis.py`
   - Start in: `C:\path\to\project`

## Differences Between Source Types

| Feature | file | splunk | cron |
|---------|------|--------|------|
| **Purpose** | Manual analysis | Manual Splunk query | Scheduled automated analysis |
| **Trigger** | User request | User request | Automated (cron job) |
| **Backend** | File only | Splunk only | File or Splunk |
| **Time Range** | All logs in file | User-specified | Typically last 5 minutes |
| **Use Case** | Ad-hoc analysis | Splunk investigation | Continuous monitoring |

## Best Practices

### 1. Time Range
- Use `-5m` to `-1m` for earliest_time (match your cron interval)
- Always use `"now"` for latest_time
- Avoid overlapping time ranges

### 2. Performance
- Limit results with appropriate time ranges
- Use Splunk search filters to reduce data volume
- Monitor API response times

### 3. Error Handling
- Log all cron job output
- Implement retry logic for transient failures
- Set up alerts for consecutive failures

### 4. Notifications
- Send alerts only for high severity findings
- Aggregate multiple low-severity events
- Use rate limiting to avoid alert fatigue

### 5. Storage
- Rotate CSV exports regularly
- Archive old reports
- Monitor disk space usage

## Example Cron Configurations

### Every 5 Minutes (High-Frequency Monitoring)
```bash
*/5 * * * * /usr/bin/python3 /path/to/run_cron_analysis.py
```

### Every 15 Minutes (Standard Monitoring)
```bash
*/15 * * * * /usr/bin/python3 /path/to/run_cron_analysis.py
```

### Every Hour (Low-Frequency Monitoring)
```bash
0 * * * * /usr/bin/python3 /path/to/run_cron_analysis.py
```

### Business Hours Only (9 AM - 6 PM, Weekdays)
```bash
*/5 9-18 * * 1-5 /usr/bin/python3 /path/to/run_cron_analysis.py
```

## Monitoring Cron Jobs

### Check Cron Logs
```bash
# Linux
tail -f /var/log/v1-analyzer-cron.log

# View recent runs
grep "Starting scheduled analysis" /var/log/v1-analyzer-cron.log | tail -20
```

### Check for Failures
```bash
grep "✗" /var/log/v1-analyzer-cron.log | tail -10
```

### Monitor Attack Detections
```bash
grep "ALERT" /var/log/v1-analyzer-cron.log | tail -20
```

## Troubleshooting

### Cron Job Not Running
1. Check cron service: `systemctl status cron`
2. Verify crontab: `crontab -l`
3. Check permissions: `ls -la /path/to/run_cron_analysis.py`
4. Test script manually: `python3 /path/to/run_cron_analysis.py`

### API Connection Failures
1. Verify backend is running: `curl http://127.0.0.1:8000/health`
2. Check network connectivity
3. Review backend logs for errors

### Splunk Connection Issues (V2)
1. Verify Splunk credentials in `.env`
2. Test Splunk connectivity
3. Check Splunk search permissions
4. Review MCP server logs

## V1 vs V2

**V1 (Current):**
- Splunk integration is stub (returns 0 events)
- Cron source works but requires manual Splunk setup
- File backend fully functional

**V2 (Future):**
- Full Splunk integration with splunklib
- Automatic Splunk authentication
- Real-time Splunk queries
- Advanced search capabilities

## Testing

Test cron source configuration:

```bash
# Test with Splunk backend (stub in V1)
python tests/test_all_sources.py

# Test with file backend
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "cron",
    "user_query": "Test cron analysis",
    "log_source": {
      "type": "file",
      "path": "tests/sample_logs.txt",
      "max_lines": 1000
    }
  }'
```

## Security Considerations

1. **Credentials**: Store Splunk credentials securely in `.env`
2. **API Access**: Restrict API access to localhost or trusted networks
3. **Log Rotation**: Implement log rotation to prevent disk fill
4. **Rate Limiting**: Prevent abuse with rate limiting
5. **Monitoring**: Monitor cron job execution and failures

---

For more information, see:
- `tests/test_all_sources.py` - Test examples
- `backend/analyzer.py` - Implementation details
- `.env.example` - Configuration template
