# Caldera Integration with Wazuh

## Overview
**MITRE Caldera** is an open-source adversary emulation platform that automates ATT&CK-aligned behaviors.  
In this SOC environment, Caldera is used to generate realistic red-team activity, validate Wazuh detections, dashboards, and incident workflows.

This document details the full methodology used in the **Wazuh SOC Enterprise** lab, including installation, configuration, Wazuh ingestion, rules, and testing.

---

## 1) Requirements
| Component | Version | Purpose |
|------------|----------|----------|
| **Ubuntu** | 24.04 LTS | Host OS |
| **Wazuh Manager** | 4.13.x | SIEM / XDR |
| **Python** | 3.12+ | Caldera runtime |
| **Node.js** | 16+ | Caldera UI build |
| **Git** | Latest | Source retrieval |
| **Go** | ≥1.19 | Build Sandcat agent |
| **Docker (optional)** | Latest | Builder plugin |

---

## 2) Installation

### Step 1 — Create virtual environment
```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git nodejs npm
python3 -m venv ~/caldera-wazuh
source ~/caldera-wazuh/bin/activate
````

### Step 2 — Clone and install Caldera

```bash
git clone https://github.com/mitre/caldera.git --recursive --branch 5.3.0
cd ~/caldera
pip install -r requirements.txt
```

### Step 3 — First run (build interface)

```bash
python3 server.py --insecure --build
```

### Step 4 — Normal startup

```bash
python3 server.py --insecure
```

* UI: [http://127.0.0.1:8888/](http://127.0.0.1:8888/)
* Default credentials (demo only):
  **User:** red
  **Pass:** admin

---

## 3) Integration with Wazuh

### Step 3.1 — Configure Caldera log collection

Edit `/var/ossec/etc/ossec.conf` on the Wazuh Manager and add:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/home/brunoflausino/caldera/logs/caldera.log</location>
    <only-future-events>yes</only-future-events>
  </localfile>
</ossec_config>
```

Then:

```bash
sudo systemctl restart wazuh-manager
sudo chown -R wazuh:wazuh /home/brunoflausino/caldera/logs/
sudo chmod -R 640 /home/brunoflausino/caldera/logs/
```

---

## 4) Wazuh Rules for Caldera

Create `/var/ossec/etc/rules/caldera_rules.xml`:

```xml
<group name="caldera,red_team">
  <rule id="100001" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^caldera$</field>
    <field name="event_type">.+</field>
    <description>Caldera Red Team Event</description>
  </rule>

  <rule id="100002" level="5">
    <if_sid>100001</if_sid>
    <field name="event_type">^operation_start$</field>
    <description>Caldera Operation Started: $(operation_id)</description>
  </rule>

  <rule id="100003" level="7">
    <if_sid>100001</if_sid>
    <field name="event_type">^operation_complete$</field>
    <description>Caldera Operation Completed</description>
  </rule>

  <rule id="100004" level="6">
    <if_sid>100001</if_sid>
    <field name="event_type">^ability_executed$</field>
    <description>Caldera Ability Executed: $(ability_name)</description>
  </rule>
</group>
```

Permissions:

```bash
sudo chown wazuh:wazuh /var/ossec/etc/rules/caldera_rules.xml
sudo chmod 640 /var/ossec/etc/rules/caldera_rules.xml
sudo systemctl restart wazuh-manager
```

---

## 5) Testing Integration

### Step 5.1 — Create a test JSON event

```bash
echo '{"source":"caldera","event_type":"operation_start","operation_id":"demo-'$(date +%s)'","ts":"'$(date -Is)'"}' \
  >> /home/brunoflausino/caldera/logs/caldera.log
```

### Step 5.2 — Validate via Wazuh Logtest

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste the JSON and expect rule **100002** to match.

### Step 5.3 — Validate via archives

```bash
sudo grep -R --line-number -F '"event_type":"operation_start"' /var/ossec/logs/ 2>/dev/null | head
```

Expected output: lines showing rules **100001** and **100002** triggered.

---

## 6) Troubleshooting

| Issue                  | Cause                 | Solution                                                  |
| ---------------------- | --------------------- | --------------------------------------------------------- |
| “is not a JSON object” | Plain text log entry  | Ensure valid JSON per line                                |
| Rule conflict          | Duplicate IDs         | Use IDs >100000 or clear cache                            |
| No matches             | File permissions      | Ensure Wazuh can read `/home/brunoflausino/caldera/logs/` |
| Missing events         | Manager not restarted | `sudo systemctl restart wazuh-manager`                    |

---

## 7) Hardening and Operational Notes

* Replace `--insecure` with secure credentials in `conf/local.yml`.
* Configure SSL/TLS for Caldera if exposed externally.
* Regularly rotate `/home/brunoflausino/caldera/logs/caldera.log`.
* Keep Caldera updated:

  ```bash
  cd ~/caldera && git pull && pip install -r requirements.txt
  ```
* For advanced usage, integrate Caldera API to automate red-team campaigns and alert verification.

---

## 8) Summary

| Stage           | Description                                               |
| --------------- | --------------------------------------------------------- |
| **Setup**       | Created isolated Python environment and installed Caldera |
| **Integration** | Linked Caldera logs to Wazuh via JSON collector           |
| **Detection**   | Deployed four rules (IDs 100001–100004)                   |
| **Validation**  | Sent simulated event, confirmed in Wazuh dashboard        |
| **Hardened**    | Enabled restricted permissions and secure configs         |

---

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab — Threat Intelligence Stack*
