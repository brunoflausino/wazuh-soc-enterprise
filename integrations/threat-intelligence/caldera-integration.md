# MITRE CALDERA Integration with Wazuh

## Overview
MITRE CALDERA is an adversary emulation framework that enables automated adversary emulation, red team operations, and threat hunting. This integration allows Wazuh to monitor CALDERA operations and detect simulated attacks.

## Requirements
- Wazuh Manager 4.13.1
- Ubuntu 24.04 LTS
- Python 3.12+
- 8GB RAM minimum

## Installation

### Step 1: Install CALDERA
```bash
cd ~
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Configure Wazuh Monitoring

Add to `/var/ossec/etc/ossec.conf`:
```xml
<!-- Caldera C2 Framework -->
<localfile>
  <log_format>json</log_format>
  <location>/home/brunoflausino/caldera/logs/caldera.log</location>
  <only-future-events>yes</only-future-events>
</localfile>
```

Restart Wazuh Manager:
```bash
sudo systemctl restart wazuh-manager
```

## Starting CALDERA
```bash
cd ~/caldera
source venv/bin/activate
python server.py --insecure
```

Access UI: http://127.0.0.1:8888/

## Verification

Test Wazuh integration:
```bash
TOKEN="TEST_$(date +%s)"
echo '{"event":"test","token":"'$TOKEN'"}' >> ~/caldera/logs/caldera.log
sleep 5
sudo grep -q "$TOKEN" /var/ossec/logs/archives/* && echo "✓ Working"
```

## Troubleshooting

**Issue**: "is not a JSON object" error  
**Fix**: Ensure CALDERA outputs valid JSON or change log_format to syslog

**Issue**: No events appearing  
**Check**: 
- CALDERA running: `curl -I http://127.0.0.1:8888/`
- Logs exist: `ls ~/caldera/logs/`
