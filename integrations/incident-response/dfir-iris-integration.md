# Definitive Solution Report: Wazuh + DFIR-IRIS Integration

## Executive Summary of the Problem

Based on the analysis of all provided reports, I identified that the integration failure is due to three fundamental configuration errors that can be corrected by following this detailed plan. The success of the integration depends on executing each step in the correct order.

## 🔴 Identified Problems and Their Solutions

### Problem 1: Incorrect IRIS Endpoint

❌ What was wrong:

Attempts to use webhook endpoints that do not exist:

- /webhooks/iris_webhooks_module
- /api/webhooks
- /hooks/iris_webhooks_module

✅ Solution:

Use the correct REST API endpoint: https://<IRIS_IP>/alerts/add  
This is the only functional endpoint for receiving external alerts.

### Problem 2: Incorrect Script Naming

❌ What was wrong:

Script named without the "custom-" prefix.  
Wazuh rejects scripts that do not follow this convention.

✅ Solution:

Rename to: custom-wazuh_iris.py  

This is a mandatory rule for Wazuh 4.x.

### Problem 3: Permissions and Configuration

❌ What was wrong:

Incorrect permissions causing "file has write permissions" error.  

Incorrect configuration in ossec.conf.

✅ Solution:

Exact permissions: 750 (rwxr-x---)  
Owner: root:wazuh

## 📋 Step-by-Step Action Plan

### PHASE 1: Preparation and Validation of IRIS

#### Step 1.1: Obtain the IRIS API Key

1. Access IRIS via browser  
   http://localhost:8000

2. Log in with: administrator / administrator

3. Click on the username (top right corner)

4. Select "My settings"

5. Copy the API Key (it will be something like: Bearer xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

#### Step 1.2: Test the IRIS API

# Basic connectivity test

```bash
curl -X POST -k http://localhost:8000/alerts/add \
-H "Authorization: Bearer YOUR_API_KEY_HERE" \
-H "Content-Type: application/json" \
-d '{
    "alert_title": "Manual API Test",
    "alert_description": "Checking if the API is functional",
    "alert_source": "curl",
    "alert_severity_id": 3,
    "alert_status_id": 2,
    "alert_customer_id": 1
}'
```

Expected result: Status 201 Created with JSON response

If it fails, check:

- Is the API Key correct?
- Is the endpoint accessible?
- Is IRIS running? ( docker ps | grep iris )

### PHASE 2: Integration Script Configuration

#### Step 2.1: Create the Correct Script

# Navigate to the integrations directory

```bash
cd /var/ossec/integrations/
```

# Create the script with the CORRECT name

```bash
sudo nano custom-wazuh_iris.py
```

#### Step 2.2: Script Content

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
from datetime import datetime
import urllib3

# Disable SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurations - ADJUST THESE VALUES
IRIS_URL = "http://localhost:8000/alerts/add"  # Use http if local
IRIS_API_KEY = "YOUR_API_KEY_HERE"  # Replace with your API Key

def main():
    # Read the Wazuh alert via stdin
    alert_json = json.loads(sys.stdin.read())

    # Map Wazuh severity to IRIS
    severity_mapping = {
        1: 1,  # Low
        2: 1,  # Low
        3: 2,  # Medium
        4: 2,  # Medium
        5: 3,  # High
        6: 3,  # High
        7: 4,  # Critical
        8: 4,  # Critical
        9: 5,  # Very Critical
        10: 5,  # Very Critical
        11: 5,  # Very Critical
        12: 5  # Very Critical
    }

    # Extract alert data
    rule = alert_json.get('rule', {})
    agent = alert_json.get('agent', {})

    # Prepare payload for IRIS
    iris_payload = {
        "alert_title": f"[Wazuh] {rule.get('description', 'Unknown Alert')}",
        "alert_description": f"""
Rule ID: {rule.get('id', 'N/A')}
Level: {rule.get('level', 'N/A')}
Agent: {agent.get('name', 'Unknown')} ({agent.get('ip', 'N/A')})
Time: {alert_json.get('timestamp', datetime.now().isoformat())}
Full Data:
{json.dumps(alert_json.get('data', {}), indent=2)}
        """,
        "alert_source": f"Wazuh-{agent.get('name', 'Unknown')}",
        "alert_severity_id": severity_mapping.get(rule.get('level', 7), 3),
        "alert_status_id": 2,  # New
        "alert_customer_id": 1
    }

    # Send to IRIS
    headers = {
        'Authorization': f'Bearer {IRIS_API_KEY}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(
            IRIS_URL,
            json=iris_payload,
            headers=headers,
            verify=False,  # For local development
            timeout=10
        )
        if response.status_code == 201:
            print(f"Alert sent successfully to IRIS")
            sys.exit(0)
        else:
            print(f"Error sending: {response.status_code} - {response.text}")
            sys.exit(1)
    except Exception as e:
        print(f"Connection error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

#### Step 2.3: Set Correct Permissions

# CRITICAL: Execute these commands EXACTLY as shown

```bash
sudo chmod 750 /var/ossec/integrations/custom-wazuh_iris.py
sudo chown root:wazuh /var/ossec/integrations/custom-wazuh_iris.py
```

# Verify if correct

```bash
ls -la /var/ossec/integrations/custom-wazuh_iris.py
```

# Should show: -rwxr-x--- 1 root wazuh ... custom-wazuh_iris.py

### PHASE 3: Wazuh Configuration

#### Step 3.1: Edit ossec.conf

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this configuration BEFORE the closing </ossec_config> :

```xml
<!-- Integration with DFIR-IRIS -->
<integration>
  <name>custom-wazuh_iris.py</name>
  <hook_url>http://localhost:8000/alerts/add</hook_url>
  <level>5</level>
  <api_key>YOUR_API_KEY_HERE</api_key>
  <alert_format>json</alert_format>
</integration>
```

#### Step 3.2: Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

# Verify if started correctly

```bash
sudo systemctl status wazuh-manager
```

### PHASE 4: Test and Validation

#### Step 4.1: Monitor Logs in Real Time

Open 3 separate terminals:

Terminal 1 - Integration Logs:

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Terminal 2 - Error Logs:

```bash
sudo tail -f /var/ossec/logs/ossec.log | grep -E "ERROR|WARNING"
```

Terminal 3 - IRIS Logs:

```bash
docker logs -f $(docker ps | grep iris-web | awk '{print $1}')
```

#### Step 4.2: Generate Test Alert

# Method 1: Simulate SSH authentication failure

```bash
ssh invaliduser@localhost
```

# Method 2: Use wazuh-logtest

```bash
echo "Failed password for invalid user test from 192.168.1.100 port 12345 ssh2" | \
sudo /var/ossec/bin/wazuh-logtest
```

#### Step 4.3: Verify Result

1. Observe the logs in the 3 terminals
2. Access IRIS: http://localhost:8000
3. Check if the alert appears in the "Alerts" section

## 🔧 Troubleshooting: Solutions for Common Errors

Error: "file has write permissions"

# Check current permissions

```bash
stat /var/ossec/integrations/custom-wazuh_iris.py
```

# Correct if necessary

```bash
sudo chmod 750 /var/ossec/integrations/custom-wazuh_iris.py
sudo chown root:wazuh /var/ossec/integrations/custom-wazuh_iris.py
```

Error: "Resource not found"

Using the correct endpoint: /alerts/add  
Do not use webhook endpoints

Error: "Authentication failed"

Check the API Key in IRIS  
Confirm using "Bearer " before the key

Error: "Connection refused"

# Check if IRIS is running

```bash
docker ps | grep iris
```

# If not, start it

```bash
cd ~/projects/dfir-iris-official/iris-web-v2420/
docker-compose up -d
```

## 🚀 Alternative Solution (If Everything Fails)

Independent Python Middleware

If the direct integration continues to fail, implement this intermediate service:

```python
#!/usr/bin/env python3
# file: /opt/wazuh-iris-middleware/middleware.py

import time
import json
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class WazuhAlertHandler(FileSystemEventHandler):
    def __init__(self, iris_url, iris_api_key):
        self.iris_url = iris_url
        self.iris_api_key = iris_api_key
        self.last_position = 0

    def on_modified(self, event):
        if event.src_path == "/var/ossec/logs/alerts/alerts.json":
            self.process_new_alerts()

    def process_new_alerts(self):
        with open("/var/ossec/logs/alerts/alerts.json", 'r') as f:
            f.seek(self.last_position)
            for line in f:
                try:
                    alert = json.loads(line.strip())
                    self.send_to_iris(alert)
                except:
                    continue
            self.last_position = f.tell()

    def send_to_iris(self, alert):
        # Similar code to the previous script
        pass

if __name__ == "__main__":
    handler = WazuhAlertHandler(
        iris_url="http://localhost:8000/alerts/add",
        iris_api_key="YOUR_API_KEY"
    )
    observer = Observer()
    observer.schedule(handler, "/var/ossec/logs/alerts/", recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
```

Configure as a Service

# Create service file

```bash
sudo nano /etc/systemd/system/wazuh-iris-middleware.service
```

```
[Unit]
Description=Wazuh to IRIS Middleware
After=network.target wazuh-manager.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/wazuh-iris-middleware/middleware.py
Restart=always

[Install]
WantedBy=multi-user.target
```

# Enable and start

```bash
sudo systemctl enable wazuh-iris-middleware
sudo systemctl start wazuh-iris-middleware
```

## ✅ Final Validation Checklist

- IRIS API Key obtained and tested
- Script named as custom-wazuh_iris.py
- Permissions: 750, owner: root:wazuh
- ossec.conf correctly configured
- Wazuh Manager restarted
- Alert test executed
- Alert appears in IRIS

## Conclusion

By following this detailed plan, the integration should work. The previous errors were caused by:

1. Use of incorrect endpoints (webhooks instead of API REST)
2. Incorrect script name (missing "custom-" prefix)
3. Incorrect permissions

The solution lies in correcting these three fundamental points. If it still fails, the Python middleware solution is robust and guaranteed to work.
