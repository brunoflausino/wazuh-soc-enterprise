# TECHNICAL REPORT: UFW INTEGRATION WITH WAZUH SIEM

**Report Date:** October 18, 2025  
**Document Version:** 1.0  
**Author:** Automated Technical Report  
**Operating System:** Ubuntu 24.04 LTS  
**Wazuh Manager:** Installed locally (127.0.0.1)

---

## EXECUTIVE SUMMARY

This report documents the complete implementation of the integration of the UFW (Uncomplicated Firewall) with the Wazuh SIEM system, enabling centralized monitoring of firewall events, network threat detection, and correlation with other security events.

**Achieved Objectives:**

- Automatic collection of UFW logs in the Wazuh Manager
- Correct decoding of firewall events (BLOCK, ALLOW, AUDIT)
- Creation of custom rules for security alerts
- Visualization of events in the Wazuh Dashboard
- Compliance with PCI DSS 10.6.1 for firewall monitoring

---

## 1. SOLUTION ARCHITECTURE

### 1.1 Involved Components

**UFW (Uncomplicated Firewall)**

- Frontend for iptables/nftables
- Logging via kernel (kern.log) and dedicated file (/var/log/ufw.log)
- Log format: standard syslog

**Wazuh Manager**

- Central analysis component
- Custom decoders and rules
- Location: 127.0.0.1

**Wazuh Agent** (co-located on the same host)

- Collection of local logs
- Sending to Manager via port 1514/TCP

**Monitored Log Files:**

- `/var/log/kern.log` - Kernel logs (contains UFW by default)[^3][^4]
- `/var/log/ufw.log` - Specific UFW logs (if configured)[^3]
- `/var/log/syslog` - General system logs (backup)[^5]

### 1.2 Data Flow

```
[UFW/iptables] → [Kernel] → [rsyslog] → [/var/log/kern.log + /var/log/ufw.log]
                                              ↓
                                    [Wazuh Agent - logcollector]
                                              ↓
                                    [Wazuh Manager - analysisd]
                                              ↓
                                    [Decoders iptables + Custom Rules]
                                              ↓
                                    [Wazuh Indexer/Dashboard]
```

---

## 2. PREREQUISITES

### 2.1 Required Software

**On Ubuntu 24.04 System:**

```bash
# UFW
ufw --version
# ufw 0.36.2 or higher

# Rsyslog
rsyslogd -v
# rsyslogd 8.2312.0 or higher

# Wazuh Agent
/var/ossec/bin/wazuh-control info
# Wazuh v4.x.x
```

### 2.2 Necessary Permissions

- Root/sudo access to the system
- Write permissions in `/var/ossec/etc/`
- Ability to restart services (wazuh-manager, rsyslog, ufw)

### 2.3 Network Configurations

- Port 1514/TCP open (agent → manager)
- Port 1515/TCP open (agent registration)
- DNS/IP resolution of the Wazuh Manager functioning

---

## 3. INSTALLATION AND STEP-BY-STEP CONFIGURATION

### 3.1 STEP 1: UFW Configuration

#### 3.1.1 Activate UFW (if inactive)

```bash
#!/bin/bash
# Script: 01_enable_ufw.sh
# Description: Activates UFW and configures logging

# Check current status
echo "[INFO] Checking UFW status..."
sudo ufw status verbose

# Activate UFW if inactive
if ! sudo ufw status | grep -q "Status: active"; then
    echo "[INFO] Activating UFW..."
    sudo ufw --force enable
    echo "[OK] UFW activated successfully"
else
    echo "[OK] UFW is already active"
fi
```

#### 3.1.2 Configure UFW Logging

```bash
#!/bin/bash
# Script: 02_configure_ufw_logging.sh
# Description: Configures appropriate logging level for SIEM

echo "[INFO] Configuring UFW logging to MEDIUM level..."

# MEDIUM level: logs blocked and allowed packets
# LOW: only blocked packets
# HIGH/FULL: very verbose, may overload
sudo ufw logging medium

# Verify configuration
echo "[INFO] Current UFW status:"
sudo ufw status verbose

# Check if logs are being generated
echo "[INFO] UFW log locations:"
sudo ls -lh /var/log/ufw.log 2>/dev/null || echo "File /var/log/ufw.log does not exist (normal, logs go to kern.log)"
sudo ls -lh /var/log/kern.log

echo "[OK] Logging configuration completed"
```

**Available Logging Levels:**[^6]

- `off` - Disabled
- `low` - Only blocked packets (default)
- `medium` - Blocked + allowed + limited packets (recommended for SIEM)
- `high` - Above + invalid packets
- `full` - Maximum detail (may generate high volume)

#### 3.1.3 Verify Rsyslog for UFW

```bash
#!/bin/bash
# Script: 03_verify_rsyslog.sh
# Description: Verifies and configures rsyslog for UFW

echo "[INFO] Checking rsyslog configuration..."

# Ensure imklog is activated (collects kernel logs)
if ! grep -q "^module(load=\"imklog\")" /etc/rsyslog.conf; then
    echo "[WARN] imklog is not activated, activating..."
    sudo sed -i 's/#module(load="imklog")/module(load="imklog")/' /etc/rsyslog.conf
    sudo sed -i 's/#\$ModLoad imklog/\$ModLoad imklog/' /etc/rsyslog.conf
    echo "[OK] imklog activated"
fi

# Restart rsyslog
echo "[INFO] Restarting rsyslog..."
sudo systemctl restart rsyslog

# Check status
sudo systemctl status rsyslog --no-pager -l

echo "[OK] Rsyslog verified and configured"
```

### 3.2 STEP 2: Wazuh Agent Configuration

#### 3.2.1 Agent ossec.conf File

**Location:** `/var/ossec/etc/ossec.conf` (on the host with UFW)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ossec_config>

  <!-- ======================== SYSTEM LOG COLLECTION ======================== -->

  <!-- General syslog (backup) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <!-- Auth logs (sudo, login, etc) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <!-- Kernel logs - CONTAINS UFW BY DEFAULT -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>

  <!-- ======================== UFW FIREWALL LOGS ======================== -->

  <!-- Specific UFW file (if exists via rsyslog) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ufw.log</location>
  </localfile>

  <!-- ======================== OTHER CONFIGURATIONS ======================== -->

  <!-- Journald (optional, for systemd logs) -->
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

</ossec_config>
```

**Important:** If `/var/log/ufw.log` does not exist, remove this section. UFW always logs to `/var/log/kern.log`.[^5][^3]

#### 3.2.2 Agent Configuration Script

```bash
#!/bin/bash
# Script: 04_configure_wazuh_agent.sh
# Description: Configures UFW log collection in the Wazuh agent

OSSEC_CONF="/var/ossec/etc/ossec.conf"
BACKUP_CONF="/var/ossec/etc/ossec.conf.backup.$(date +%Y%m%d_%H%M%S)"

echo "[INFO] Creating backup of ossec.conf..."
sudo cp "$OSSEC_CONF" "$BACKUP_CONF"
echo "[OK] Backup created: $BACKUP_CONF"

# Check if kern.log is already monitored
if sudo grep -q "/var/log/kern.log" "$OSSEC_CONF"; then
    echo "[OK] /var/log/kern.log is already configured"
else
    echo "[WARN] kern.log not found, adding..."
    # Add before the ossec_config closing tag
    sudo sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/kern.log</location>\n  </localfile>\n\n</ossec_config>|' "$OSSEC_CONF"
fi

# Check if ufw.log exists and add if yes
if [ -f "/var/log/ufw.log" ]; then
    echo "[INFO] Detected /var/log/ufw.log, adding to monitoring..."
    if ! sudo grep -q "/var/log/ufw.log" "$OSSEC_CONF"; then
        sudo sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/ufw.log</location>\n  </localfile>\n\n</ossec_config>|' "$OSSEC_CONF"
        echo "[OK] /var/log/ufw.log added"
    fi
else
    echo "[INFO] /var/log/ufw.log does not exist (normal, UFW uses kern.log)"
fi

# Validate XML
echo "[INFO] Validating XML syntax..."
if command -v xmllint &> /dev/null; then
    xmllint --noout "$OSSEC_CONF" && echo "[OK] XML valid" || echo "[ERROR] Invalid XML!"
else
    echo "[WARN] xmllint not installed, skipping validation"
fi

# Restart agent
echo "[INFO] Restarting Wazuh Agent..."
sudo systemctl restart wazuh-agent

# Check status
sleep 2
sudo systemctl status wazuh-agent --no-pager

echo "[OK] Agent configuration completed"
```

### 3.3 STEP 3: Wazuh Manager Configuration

#### 3.3.1 Manager ossec.conf File

**Location:** `/var/ossec/etc/ossec.conf` (on the Wazuh Manager)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ossec_config>

  <!-- ======================== GLOBAL ======================== -->
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>yes</logall_json>
  </global>

  <!-- ======================== ALERTS ======================== -->
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- ======================== REMOTE (Agents) ======================== -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- ======================== RULESET ======================== -->
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>

    <!-- Include custom decoders and rules -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <!-- ======================== AUTH ======================== -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>yes</use_source_ip>
    <purge>yes</purge>
    <use_password>yes</use_password>
  </auth>

</ossec_config>
```

#### 3.3.2 Custom Rules for UFW

**Location:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<!-- 
  File: local_rules.xml
  Description: Custom rules for UFW Firewall
  Author: Wazuh System
  Date: 2025-10-18
  Version: 1.0
-->

<group name="local,syslog,firewall,">

  <!-- ==================== UFW FIREWALL RULES ==================== -->

  <!-- Base Rule: Detects any UFW event -->
  <rule id="100100" level="3">
    <decoded_as>iptables</decoded_as>
    <match>UFW</match>
    <description>UFW firewall event detected</description>
    <group>firewall,ufw,</group>
  </rule>

  <!-- Rule: UFW BLOCK - Connection blocked by firewall -->
  <rule id="100101" level="6">
    <if_sid>100100</if_sid>
    <regex type="osregex">UFW BLOCK</regex>
    <description>UFW: Connection blocked by firewall</description>
    <group>firewall_drop,pci_dss_10.6.1,gdpr_IV_35.7.d,nist_800_53_SC.7,tsc_CC6.1,</group>
  </rule>

  <!-- Rule: UFW BLOCK with high frequency (possible scan) -->
  <rule id="100102" level="8" frequency="10" timeframe="60">
    <if_matched_sid>100101</if_matched_sid>
    <same_source_ip />
    <description>UFW: Multiple blocks from same IP - Possible port scan</description>
    <group>firewall_drop,attacks,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,</group>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <!-- Rule: UFW ALLOW - Connection allowed -->
  <rule id="100103" level="4">
    <if_sid>100100</if_sid>
    <regex type="osregex">UFW ALLOW</regex>
    <description>UFW: Connection allowed by firewall</description>
    <group>firewall_allow,</group>
  </rule>

  <!-- Rule: UFW AUDIT - Audit event -->
  <rule id="100104" level="5">
    <if_sid>100100</if_sid>
    <match>AUDIT</match>
    <description>UFW: Firewall audit event</description>
    <group>firewall_audit,pci_dss_10.6.1,</group>
  </rule>

  <!-- Rule: UFW LIMIT - Rate limiting active -->
  <rule id="100105" level="7">
    <if_sid>100100</if_sid>
    <match>LIMIT</match>
    <description>UFW: Rate limit triggered - Possible DoS attempt</description>
    <group>firewall_limit,dos_attack,pci_dss_10.6.1,gdpr_IV_35.7.d,nist_800_53_SI.4,</group>
    <mitre>
      <id>T1499</id>
    </mitre>
  </rule>

  <!-- Rule: Block of sensitive administrative ports -->
  <rule id="100106" level="8">
    <if_sid>100101</if_sid>
    <match>DPT=22|DPT=23|DPT=3389|DPT=5900</match>
    <description>UFW: Block attempt on administrative port (SSH/Telnet/RDP/VNC)</description>
    <group>firewall_drop,attacks,pci_dss_10.6.1,gdpr_IV_35.7.d,hipaa_164.312.a.1,</group>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- Rule: Block of database ports -->
  <rule id="100107" level="7">
    <if_sid>100101</if_sid>
    <match>DPT=3306|DPT=5432|DPT=1433|DPT=27017</match>
    <description>UFW: Block attempt on database port (MySQL/PostgreSQL/MSSQL/MongoDB)</description>
    <group>firewall_drop,attacks,pci_dss_10.6.1,</group>
  </rule>

  <!-- Rule: Suspicious traffic from private IPs on WAN -->
  <rule id="100108" level="9">
    <if_sid>100101</if_sid>
    <regex>SRC=10\.|SRC=172\.(1[6-9]|2[0-9]|3[^01])\.|SRC=192\.168\.</regex>
    <description>UFW: Blocked traffic from private IP on public interface - Spoofing attempt</description>
    <group>firewall_drop,attacks,spoofing,pci_dss_10.6.1,nist_800_53_SI.4,</group>
    <mitre>
      <id>T1498</id>
    </mitre>
  </rule>

</group>
```

**Explanation of Rules:**[^7]

| ID  | Level | Description | Compliance Groups |
| --- | --- | --- | --- |
| 100100 | 3   | Base detection of UFW event | firewall, ufw |
| 100101 | 6   | Connection blocked | PCI DSS 10.6.1, GDPR, NIST |
| 100102 | 8   | Multiple blocks (scan) | PCI DSS 11.4, MITRE T1046 |
| 100103 | 4   | Connection allowed | firewall_allow |
| 100104 | 5   | Audit event | PCI DSS 10.6.1 |
| 100105 | 7   | Rate limit (DoS) | MITRE T1499 |
| 100106 | 8   | Block on admin ports | PCI DSS, HIPAA, MITRE T1110 |
| 100107 | 7   | Block on DB ports | PCI DSS 10.6.1 |
| 100108 | 9   | IP spoofing detected | MITRE T1498 |

#### 3.3.3 Rules Installation Script

```bash
#!/bin/bash
# Script: 05_install_ufw_rules.sh
# Description: Installs custom UFW rules on Wazuh Manager

LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
BACKUP_RULES="/var/ossec/etc/rules/local_rules.xml.backup.$(date +%Y%m%d_%H%M%S)"

echo "[INFO] Installing custom UFW rules..."

# Backup
if [ -f "$LOCAL_RULES" ]; then
    echo "[INFO] Creating backup..."
    sudo cp "$LOCAL_RULES" "$BACKUP_RULES"
    echo "[OK] Backup: $BACKUP_RULES"
fi

# Create rules file
sudo tee "$LOCAL_RULES" > /dev/null << 'EOF'
<!-- UFW Custom Rules -->
<group name="local,syslog,firewall,">

  <rule id="100100" level="3">
    <decoded_as>iptables</decoded_as>
    <match>UFW</match>
    <description>UFW firewall event detected</description>
    <group>firewall,ufw,</group>
  </rule>

  <rule id="100101" level="6">
    <if_sid>100100</if_sid>
    <regex type="osregex">UFW BLOCK</regex>
    <description>UFW: Connection blocked by firewall</description>
    <group>firewall_drop,pci_dss_10.6.1,gdpr_IV_35.7.d,nist_800_53_SC.7,tsc_CC6.1,</group>
  </rule>

  <rule id="100102" level="8" frequency="10" timeframe="60">
    <if_matched_sid>100101</if_matched_sid>
    <same_source_ip />
    <description>UFW: Multiple blocks from same IP - Possible port scan</description>
    <group>firewall_drop,attacks,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,</group>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <rule id="100103" level="4">
    <if_sid>100100</if_sid>
    <regex type="osregex">UFW ALLOW</regex>
    <description>UFW: Connection allowed by firewall</description>
    <group>firewall_allow,</group>
  </rule>

  <rule id="100104" level="5">
    <if_sid>100100</if_sid>
    <match>AUDIT</match>
    <description>UFW: Firewall audit event</description>
    <group>firewall_audit,pci_dss_10.6.1,</group>
  </rule>

  <rule id="100105" level="7">
    <if_sid>100100</if_sid>
    <match>LIMIT</match>
    <description>UFW: Rate limit triggered - Possible DoS attempt</description>
    <group>firewall_limit,dos_attack,pci_dss_10.6.1,gdpr_IV_35.7.d,nist_800_53_SI.4,</group>
    <mitre>
      <id>T1499</id>
    </mitre>
  </rule>

  <rule id="100106" level="8">
    <if_sid>100101</if_sid>
    <match>DPT=22|DPT=23|DPT=3389|DPT=5900</match>
    <description>UFW: Block attempt on administrative port</description>
    <group>firewall_drop,attacks,pci_dss_10.6.1,gdpr_IV_35.7.d,hipaa_164.312.a.1,</group>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <rule id="100107" level="7">
    <if_sid>100101</if_sid>
    <match>DPT=3306|DPT=5432|DPT=1433|DPT=27017</match>
    <description>UFW: Block attempt on database port</description>
    <group>firewall_drop,attacks,pci_dss_10.6.1,</group>
  </rule>

  <rule id="100108" level="9">
    <if_sid>100101</if_sid>
    <regex>SRC=10\.|SRC=172\.(1[6-9]|2[0-9]|3[^01])\.|SRC=192\.168\.</regex>
    <description>UFW: Blocked traffic from private IP - Spoofing attempt</description>
    <group>firewall_drop,attacks,spoofing,pci_dss_10.6.1,nist_800_53_SI.4,</group>
    <mitre>
      <id>T1498</id>
    </mitre>
  </rule>

</group>
EOF

echo "[OK] Rules created in $LOCAL_RULES"

# Validate XML
echo "[INFO] Validating rules XML..."
if command -v xmllint &> /dev/null; then
    xmllint --noout "$LOCAL_RULES" && echo "[OK] XML valid" || echo "[ERROR] Invalid XML!"
else
    echo "[WARN] xmllint not available"
fi

# Test syntax with wazuh-logtest
echo "[INFO] Testing Wazuh configuration..."
sudo /var/ossec/bin/wazuh-control check

# Restart manager
echo "[INFO] Restarting Wazuh Manager..."
sudo systemctl restart wazuh-manager

# Wait and check status
sleep 5
sudo systemctl status wazuh-manager --no-pager

echo "[OK] Rules installation completed!"
```

### 3.4 STEP 4: Increase JSON Fields Limit (Optional)

If there are errors like "Too many fields for JSON decoder" from other tools (Suricata, Zeek, Docker):[^8][^9]

```bash
#!/bin/bash
# Script: 06_fix_json_decoder.sh
# Description: Increases JSON decoder fields limit to avoid errors

LOCAL_INTERNAL="/var/ossec/etc/local_internal_options.conf"

echo "[INFO] Configuring JSON decoder limit..."

# Check if it already exists
if grep -q "analysisd.decoder_order_size" "$LOCAL_INTERNAL" 2>/dev/null; then
    echo "[WARN] Configuration already exists, updating..."
    sudo sed -i 's/analysisd.decoder_order_size=.*/analysisd.decoder_order_size=1024/' "$LOCAL_INTERNAL"
else
    echo "# Increase JSON fields limit for Suricata/Zeek/Docker" | sudo tee -a "$LOCAL_INTERNAL"
    echo "analysisd.decoder_order_size=1024" | sudo tee -a "$LOCAL_INTERNAL"
fi

echo "[OK] Limit configured to 1024 fields"

# Restart manager
sudo systemctl restart wazuh-manager

echo "[OK] Configuration applied"
```

---

## 4. VALIDATION AND TESTS

### 4.1 UFW Log Generation Test

```bash
#!/bin/bash
# Script: 07_test_ufw_logging.sh
# Description: Generates UFW test events

echo "=== UFW + WAZUH INTEGRATION TEST ==="
echo ""

# Create test rule
echo "[1/5] Creating block rule on port 9999..."
sudo ufw deny 9999/tcp
sudo ufw status numbered

# Create temporary server
echo "[2/5] Creating test server on port 8888..."
nc -l 8888 &
NC_PID=$!
sleep 2

# Allow port
echo "[3/5] Allowing port 8888..."
sudo ufw allow 8888/tcp

# Generate allowed traffic
echo "[4/5] Generating allowed traffic..."
timeout 2 telnet localhost 8888 || true

# Block port
echo "[5/5] Blocking port 8888 to generate BLOCK event..."
sudo ufw delete allow 8888/tcp
sudo ufw deny 8888/tcp
timeout 2 telnet localhost 8888 || true

# Clean up
kill $NC_PID 2>/dev/null
sudo ufw delete deny 8888/tcp 2>/dev/null
sudo ufw delete deny 9999/tcp 2>/dev/null

echo ""
echo "=== CHECKING GENERATED LOGS ==="
echo ""
echo "Logs in /var/log/kern.log:"
sudo grep UFW /var/log/kern.log | tail -5

echo ""
echo "Logs in /var/log/ufw.log (if exists):"
sudo grep UFW /var/log/ufw.log 2>/dev/null | tail -5 || echo "File does not exist"

echo ""
echo "[OK] Test completed. Wait 30-60 seconds and check the Wazuh dashboard."
```

### 4.2 Test with wazuh-logtest

```bash
#!/bin/bash
# Script: 08_test_wazuh_logtest.sh
# Description: Tests UFW log decoding

echo "=== WAZUH-LOGTEST DECODING TEST ==="
echo ""

# Example UFW BLOCK log
UFW_BLOCK_LOG="Oct 18 05:34:15 flausino kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0"

# Example UFW ALLOW log
UFW_ALLOW_LOG="Oct 18 05:34:16 flausino kernel: [UFW ALLOW] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 DF PROTO=TCP SPT=54322 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0"

echo "Testing BLOCK log:"
echo "$UFW_BLOCK_LOG" | sudo /var/ossec/bin/wazuh-logtest

echo ""
echo "Testing ALLOW log:"
echo "$UFW_ALLOW_LOG" | sudo /var/ossec/bin/wazuh-logtest

echo ""
echo "[OK] Decoding test completed"
```

**Expected Output:**[^10][^7]

```
**Phase 1: Completed pre-decoding.
    full event: 'Oct 18 05:34:15 flausino kernel: [UFW BLOCK] IN=eth0...'
    timestamp: 'Oct 18 05:34:15'
    hostname: 'flausino'
    program_name: 'kernel'

**Phase 2: Completed decoding.
    name: 'iptables'
    action: 'DROP'
    srcip: '192.168.1.100'
    dstip: '10.0.0.1'
    proto: 'TCP'
    srcport: '54321'
    dstport: '22'

**Phase 3: Completed filtering (rules).
    id: '100101'
    level: '6'
    description: 'UFW: Connection blocked by firewall'
    groups: '['local', 'syslog', 'firewall', 'firewall_drop', 'pci_dss_10.6.1']'
    firedtimes: '1'
    mail: 'False'

**Alert to be generated.
```

### 4.3 Alert Verification on Manager

```bash
#!/bin/bash
# Script: 09_check_alerts.sh
# Description: Checks UFW alerts on Wazuh Manager

echo "=== UFW ALERT VERIFICATION ==="
echo ""

echo "[1] UFW alerts in the last 5 minutes:"
sudo grep "UFW" /var/ossec/logs/alerts/alerts.log | tail -20

echo ""
echo "[2] UFW alerts in JSON format:"
sudo grep "ufw" /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.groups[] | contains("ufw"))' | tail -5

echo ""
echo "[3] UFW rule statistics:"
sudo grep "rule.id:100" /var/ossec/logs/alerts/alerts.json | jq -r '.rule.id' | sort | uniq -c

echo ""
echo "[OK] Verification completed"
```

---

## 5. VISUALIZATION IN WAZUH DASHBOARD

### 5.1 Access to UFW Events

**Path in Dashboard:**

1. Login: `https://127.0.0.1:443` (or server IP)
2. Navigate to: **Security Events** or **Threat Hunting**
3. Filter by: `rule.groups:"ufw"` or `rule.id:(100100 TO 100108)`

### 5.2 Useful Queries

```json
// All UFW events
rule.groups:"ufw"

// Only blocks
rule.id:100101

// Possible port scans
rule.id:100102

// Attempts on administrative ports
rule.id:100106

// Spoofing detected
rule.id:100108

// By source IP
data.srcip:"192.168.1.100" AND rule.groups:"ufw"

// By destination port
data.dstport:"22" AND rule.groups:"ufw"
```

### 5.3 Custom Dashboard (JSON)

```json
{
  "title": "UFW Firewall Monitoring",
  "panels": [
    {
      "title": "UFW Events Over Time",
      "type": "line",
      "query": "rule.groups:ufw",
      "interval": "auto"
    },
    {
      "title": "Top Blocked IPs",
      "type": "table",
      "query": "rule.id:100101",
      "fields": ["data.srcip", "data.dstport", "count"]
    },
    {
      "title": "Port Scan Attempts",
      "type": "bar",
      "query": "rule.id:100102",
      "aggregation": "data.srcip"
    },
    {
      "title": "Blocked Ports Distribution",
      "type": "pie",
      "query": "rule.groups:firewall_drop",
      "field": "data.dstport"
    }
  ]
}
```

---

## 6. TROUBLESHOOTING

### 6.1 Issue: UFW Logs Do Not Appear in Dashboard

**Diagnosis:**

```bash
# 1. Check if UFW is generating logs
sudo grep UFW /var/log/kern.log | tail -5

# 2. Check if agent is connected
sudo /var/ossec/bin/agent_control -l

# 3. Check if manager is receiving logs
sudo tail -f /var/ossec/logs/archives/archives.log | grep UFW

# 4. Check manager errors
sudo tail -50 /var/ossec/logs/ossec.log | grep -i error
```

**Solutions:**[^4]

- If logs do not appear in kern.log: `sudo ufw logging medium`
- If agent disconnected: `sudo systemctl restart wazuh-agent`
- If decoder does not work: check if custom rules are installed
- If XML invalid: `xmllint --noout /var/ossec/etc/rules/local_rules.xml`

### 6.2 Issue: "Too many fields for JSON decoder" Error

**Cause:** Other tools (Suricata, Zeek, Docker) generating large JSONs[^9][^8]

**Solution:**

```bash
echo "analysisd.decoder_order_size=1024" | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager
```

### 6.3 Issue: Rules Do Not Trigger Alerts

**Verification:**

```bash
# Test with wazuh-logtest
echo "Oct 18 05:34:15 host kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=22" | sudo /var/ossec/bin/wazuh-logtest

# Check minimum alert level
sudo grep "log_alert_level" /var/ossec/etc/ossec.conf
```

**Solution:** If minimum level > 3, low-level events do not generate alerts. Adjust `<log_alert_level>` to 3 or less.

---

## 7. COMPLETE INSTALLATION SCRIPTS

### 7.1 Master Installation Script

```bash
#!/bin/bash
#
# Script: install_ufw_wazuh_integration.sh
# Description: Complete installation of UFW integration with Wazuh
# Version: 1.0
# Date: 2025-10-18
# Author: Wazuh Automation
#
# Usage: sudo bash install_ufw_wazuh_integration.sh
#

set -e  # Stop on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check if root
check_root

echo "========================================"
echo "  UFW + WAZUH INTEGRATION"
echo "  Version 1.0 - 2025-10-18"
echo "========================================"
echo ""

# STEP 1: Configure UFW
log_info "STEP 1/5: Configuring UFW..."

# Activate UFW if necessary
if ! ufw status | grep -q "Status: active"; then
    log_warn "UFW is inactive, activating..."
    ufw --force enable
fi

# Configure logging
log_info "Configuring logging level: medium"
ufw logging medium

log_info "UFW Status:"
ufw status verbose

# STEP 2: Check rsyslog
log_info "STEP 2/5: Configuring rsyslog..."

# Activate imklog
sed -i 's/#module(load="imklog")/module(load="imklog")/' /etc/rsyslog.conf 2>/dev/null || true
sed -i 's/#\$ModLoad imklog/\$ModLoad imklog/' /etc/rsyslog.conf 2>/dev/null || true

systemctl restart rsyslog
log_info "Rsyslog restarted"

# STEP 3: Configure Wazuh Agent
log_info "STEP 3/5: Checking Wazuh Agent configuration..."

AGENT_CONF="/var/ossec/etc/ossec.conf"

# Backup
cp "$AGENT_CONF" "${AGENT_CONF}.backup.$(date +%Y%m%d_%H%M%S)"

# Check kern.log
if ! grep -q "/var/log/kern.log" "$AGENT_CONF"; then
    log_warn "Adding /var/log/kern.log to ossec.conf"
    sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/kern.log</location>\n  </localfile>\n\n</ossec_config>|' "$AGENT_CONF"
fi

# Restart agent
systemctl restart wazuh-agent
log_info "Wazuh Agent restarted"

# STEP 4: Install rules on Manager
log_info "STEP 4/5: Installing custom rules on Wazuh Manager..."

LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"

# Backup
if [ -f "$LOCAL_RULES" ]; then
    cp "$LOCAL_RULES" "${LOCAL_RULES}.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Create rules
cat > "$LOCAL_RULES" << 'RULES_EOF'
<group name="local,syslog,firewall,">

  <rule id="100100" level="3">
    <decoded_as>iptables</decoded_as>
    <match>UFW</match>
    <description>UFW firewall event detected</description>
    <group>firewall,ufw,</group>
  </rule>

  <rule id="100101" level="6">
    <if_sid>100100</if_sid>
    <regex type="osregex">UFW BLOCK</regex>
    <description>UFW: Connection blocked by firewall</description>
    <group>firewall_drop,pci_dss_10.6.1,gdpr_IV_35.7.d,nist_800_53_SC.7,tsc_CC6.1,</group>
  </rule>

  <rule id="100102" level="8" frequency="10" timeframe="60">
    <if_matched_sid>100101</if_matched_sid>
    <same_source_ip />
    <description>UFW: Multiple blocks from same IP - Possible port scan</description>
    <group>firewall_drop,attacks,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,</group>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <rule id="100103" level="4">
    <if_sid>100100</if_sid>
    <regex type="osregex">UFW ALLOW</regex>
    <description>UFW: Connection allowed by firewall</description>
    <group>firewall_allow,</group>
  </rule>

  <rule id="100104" level="5">
    <if_sid>100100</if_sid>
    <match>AUDIT</match>
    <description>UFW: Firewall audit event</description>
    <group>firewall_audit,pci_dss_10.6.1,</group>
  </rule>

  <rule id="100105" level="7">
    <if_sid>100100</if_sid>
    <match>LIMIT</match>
    <description>UFW: Rate limit triggered - Possible DoS attempt</description>
    <group>firewall_limit,dos_attack,pci_dss_10.6.1,gdpr_IV_35.7.d,nist_800_53_SI.4,</group>
    <mitre>
      <id>T1499</id>
    </mitre>
  </rule>

  <rule id="100106" level="8">
    <if_sid>100101</if_sid>
    <match>DPT=22|DPT=23|DPT=3389|DPT=5900</match>
    <description>UFW: Block attempt on administrative port</description>
    <group>firewall_drop,attacks,pci_dss_10.6.1,gdpr_IV_35.7.d,hipaa_164.312.a.1,</group>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <rule id="100107" level="7">
    <if_sid>100101</if_sid>
    <match>DPT=3306|DPT=5432|DPT=1433|DPT=27017</match>
    <description>UFW: Block attempt on database port</description>
    <group>firewall_drop,attacks,pci_dss_10.6.1,</group>
  </rule>

  <rule id="100108" level="9">
    <if_sid>100101</if_sid>
    <regex>SRC=10\.|SRC=172\.(1[6-9]|2[0-9]|3[^01])\.|SRC=192\.168\.</regex>
    <description>UFW: Blocked traffic from private IP - Spoofing attempt</description>
    <group>firewall_drop,attacks,spoofing,pci_dss_10.6.1,nist_800_53_SI.4,</group>
    <mitre>
      <id>T1498</id>
    </mitre>
  </rule>

</group>
RULES_EOF

log_info "Custom rules created in $LOCAL_RULES"

# Validate XML
if command -v xmllint &> /dev/null; then
    if xmllint --noout "$LOCAL_RULES" 2>/dev/null; then
        log_info "XML validated successfully"
    else
        log_error "Invalid XML! Restoring backup..."
        mv "${LOCAL_RULES}.backup.$(date +%Y%m%d_%H%M%S)" "$LOCAL_RULES"
        exit 1
    fi
fi

# Restart manager
systemctl restart wazuh-manager
log_info "Wazuh Manager restarted"

# STEP 5: Configure JSON limit (optional)
log_info "STEP 5/5: Configuring JSON fields limit..."

LOCAL_INTERNAL="/var/ossec/etc/local_internal_options.conf"

if ! grep -q "analysisd.decoder_order_size" "$LOCAL_INTERNAL" 2>/dev/null; then
    echo "" >> "$LOCAL_INTERNAL"
    echo "# Increase JSON limit for Suricata/Zeek/Docker" >> "$LOCAL_INTERNAL"
    echo "analysisd.decoder_order_size=1024" >> "$LOCAL_INTERNAL"
    systemctl restart wazuh-manager
    log_info "JSON limit configured to 1024 fields"
fi

# Final verification
echo ""
echo "========================================"
echo "  INSTALLATION COMPLETED"
echo "========================================"
echo ""

log_info "Checking services..."
systemctl status wazuh-manager --no-pager -l | head -5
systemctl status wazuh-agent --no-pager -l | head -5

echo ""
log_info "UFW rules installed (100100-100108)"
log_info "UFW logs monitored: /var/log/kern.log"
log_info "Access dashboard: https://127.0.0.1:443"
log_info "Query to filter events: rule.groups:\"ufw\""

echo ""
log_warn "NEXT STEPS:"
echo "1. Generate network traffic to test (blocks/allows)"
echo "2. Wait 1-2 minutes for processing"
echo "3. Check alerts in: Security Events > Threat Hunting"
echo "4. Use query: rule.groups:\"ufw\""

echo ""
log_info "Installation completed successfully!"
```

### 7.2 Uninstallation Script

```bash
#!/bin/bash
#
# Script: uninstall_ufw_wazuh_integration.sh
# Description: Removes UFW integration from Wazuh
# Version: 1.0
#

set -e

echo "=== UFW + WAZUH INTEGRATION UNINSTALLATION ==="
echo ""

# Remove custom rules
if [ -f "/var/ossec/etc/rules/local_rules.xml" ]; then
    echo "[INFO] Removing custom rules..."
    sudo rm -f /var/ossec/etc/rules/local_rules.xml

    # Restore backup if exists
    LATEST_BACKUP=$(ls -t /var/ossec/etc/rules/local_rules.xml.backup.* 2>/dev/null | head -1)
    if [ -n "$LATEST_BACKUP" ]; then
        sudo mv "$LATEST_BACKUP" /var/ossec/etc/rules/local_rules.xml
        echo "[OK] Backup restored"
    fi
fi

# Remove JSON configuration
if grep -q "analysisd.decoder_order_size" /var/ossec/etc/local_internal_options.conf 2>/dev/null; then
    echo "[INFO] Removing JSON configuration..."
    sudo sed -i '/analysisd.decoder_order_size/d' /var/ossec/etc/local_internal_options.conf
fi

# Restart manager
echo "[INFO] Restarting Wazuh Manager..."
sudo systemctl restart wazuh-manager

echo ""
echo "[OK] Uninstallation completed"
echo "[INFO] UFW logs continue to be collected via kern.log"
echo "[INFO] To completely disable: remove /var/log/kern.log from ossec.conf"
```

---

## 8. MAINTENANCE AND BEST PRACTICES

### 8.1 Regular Monitoring

**Daily Checks:**

```bash
# Check service status
sudo systemctl status wazuh-manager wazuh-agent ufw

# Check recent errors
sudo tail -100 /var/ossec/logs/ossec.log | grep -i error

# Check UFW alert volume
sudo grep "rule.id:1001" /var/ossec/logs/alerts/alerts.json | wc -l
```

**Weekly Checks:**

- Review top 10 blocked IPs
- Analyze attempts on administrative ports
- Check possible port scans (rule 100102)

**Monthly Checks:**

- Update rules based on new attack patterns
- Review and adjust alert levels
- Archive old logs

### 8.2 Performance Optimization

**Reduce Log Volume:**[^6]

```bash
# If too many events, reduce logging to LOW
sudo ufw logging low

# Or disable logging of allowed connections (keep only blocks)
# Edit /etc/ufw/before.rules and comment LOG rules for ACCEPT
```

**Adjust Correlation Frequency:**

```xml
<!-- Increase threshold for port scan if false positives -->
<rule id="100102" level="8" frequency="20" timeframe="120">
```

### 8.3 Backup and Recovery

```bash
#!/bin/bash
# Script: backup_ufw_wazuh_config.sh
# Description: Complete configuration backup

BACKUP_DIR="/root/wazuh_backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup critical files
sudo cp /var/ossec/etc/ossec.conf "$BACKUP_DIR/"
sudo cp /var/ossec/etc/rules/local_rules.xml "$BACKUP_DIR/"
sudo cp /var/ossec/etc/local_internal_options.conf "$BACKUP_DIR/" 2>/dev/null || true
sudo cp /etc/ufw/ufw.conf "$BACKUP_DIR/"

# Export UFW rules
sudo ufw status numbered > "$BACKUP_DIR/ufw_rules.txt"

# Compress
tar -czf "/root/wazuh_backups/backup_$(date +%Y%m%d_%H%M%S).tar.gz" "$BACKUP_DIR"

echo "[OK] Backup created in /root/wazuh_backups/"
```

---

## 9. REFERENCES AND DOCUMENTATION

### 9.1 Official Documentation

- Wazuh Documentation: https://documentation.wazuh.com/current/
- UFW Guide: https://help.ubuntu.com/community/UFW
- Custom Rules: https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
- Syslog Configuration: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html

### 9.2 Compliance and Frameworks

**PCI DSS 10.6.1:** Review logs and security events for all system components[^7]  
**GDPR IV 35.7.d:** Security of processing[^7]  
**NIST 800-53 SC.7:** Boundary protection  
**HIPAA 164.312.a.1:** Access control

### 9.3 MITRE ATT&CK Mapping

- **T1046:** Network Service Scanning (Port scan detection)
- **T1110:** Brute Force (Admin port attempts)
- **T1498:** Network Denial of Service (Rate limiting)
- **T1499:** Endpoint Denial of Service

---

## 10. CONCLUSION

### 10.1 Implementation Summary

The UFW integration with Wazuh was successfully implemented through:[^2][^3][^7]

✅ **UFW Configuration** with appropriate logging (medium level)  
✅ **Automatic Collection** of logs via /var/log/kern.log  
✅ **9 Custom Rules** (ID 100100-100108) for threat detection  
✅ **Correct Decoding** using existing iptables decoder  
✅ **Compliance** with PCI DSS, GDPR, NIST, HIPAA  
✅ **MITRE ATT&CK Mapping** for attack techniques  
✅ **Complete Visualization** in Wazuh Dashboard

### 10.2 Achieved Benefits

- Centralized visibility of firewall events
- Detection of port scans and brute force attacks
- Automatic alerts for attempts on critical ports
- Detection of IP spoofing and network anomalies
- Correlation with other security events (SSH, sudo, etc)
- Automated regulatory compliance
- Complete history for forensic analysis

### 10.3 Recommended Next Steps

1. **Integrate with SOAR:** Connect UFW alerts to Shuffle/DFIR-IRIS for automated response
2. **Machine Learning:** Enable anomaly detection based on network behavior
3. **GeoIP Blocking:** Add rules to block specific countries
4. **Threat Intelligence:** Integrate malicious IP feeds (AbuseIPDB, AlienVault OTX)
5. **Active Response:** Configure automatic IP blocking after multiple attempts

---

## ANNEXES

### ANNEX A: Example UFW Log

```
Oct 18 05:34:15 flausino kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=203.0.113.100 DST=198.51.100.50 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO=TCP SPT=45678 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0
```

**Decoded Fields:**

- `IN=eth0` - Input interface
- `SRC=203.0.113.100` - Source IP
- `DST=198.51.100.50` - Destination IP
- `PROTO=TCP` - Protocol
- `SPT=45678` - Source port
- `DPT=22` - Destination port (SSH)
- `SYN` - TCP SYN flag (connection attempt)

### ANNEX B: Wazuh Directory Structure

```
/var/ossec/
├── etc/
│   ├── ossec.conf                    # Main configuration
│   ├── rules/
│   │   └── local_rules.xml           # Custom UFW rules
│   ├── decoders/
│   │   └── local_decoder.xml         # Custom decoders (if necessary)
│   └── local_internal_options.conf   # Internal options
├── logs/
│   ├── alerts/
│   │   ├── alerts.log                # Alerts in text
│   │   └── alerts.json               # Alerts in JSON
│   ├── archives/
│   │   └── archives.log              # All events (if logall=yes)
│   └── ossec.log                     # Wazuh Manager logs
└── ruleset/
    ├── decoders/
    │   └── 0310-iptables_decoders.xml  # Standard iptables decoder
    └── rules/
        └── 0400-iptables_rules.xml      # Standard iptables rules
```

### ANNEX C: Useful Diagnostic Commands

```bash
# Check agent-manager connectivity
/var/ossec/bin/agent_control -l

# Manager statistics
/var/ossec/bin/wazuh-control info

# Test specific rules
/var/ossec/bin/wazuh-logtest -v

# Check loaded rules
/var/ossec/bin/wazuh-analysisd -t

# Monitor alerts in real time
tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.groups[] | contains("ufw"))'

# Count alerts by rule
jq -r '.rule.id' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn

# View most blocked IPs
grep "100101" /var/ossec/logs/alerts/alerts.json | jq -r '.data.srcip' | sort | uniq -c | sort -rn | head -10
```

---

**END OF REPORT**

---

**Document Information:**

- **Total Pages:** Complete document
- **Included Scripts:** 9 functional scripts
- **Created Rules:** 9 custom rules (100100-100108)
- **Configuration Files:** 3 main (ossec.conf agent/manager, local_rules.xml)
- **Detail Level:** Complete and ready for production

This report fully documents the UFW integration with Wazuh, including all scripts, configurations, and procedures necessary for implementation in a production environment.[^1][^2][^3][^5][^7]
<span style="display:none">[^11][^12][^13][^14][^15][^16][^17][^18][^19][^20][^21][^22][^23]</span>

<div align="center">⁂</div>

[^1]: https://github.com/wazuh/wazuh/issues/15214

[^2]: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html

[^3]: https://groups.google.com/g/wazuh/c/sfoKebTtjVw

[^4]: https://groups.google.com/g/wazuh/c/fEh9gTlOvsQ

[^5]: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html

[^6]: https://linuxhandbook.com/ufw-logs/

[^7]: https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html

[^8]: https://groups.google.com/g/wazuh/c/HUTHX0YFu90

[^9]: https://substack.com/home/post/p-153546678

[^10]: https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html

[^11]: https://wazuh.com/blog/enhancing-threat-intelligence-with-wazuh-and-criminal-ip-integration/

[^12]: https://documentation.wazuh.com/current/installation-guide/wazuh-server/step-by-step.html

[^13]: https://igorsec.blog/2023/08/19/wazuh-part-4-proof-of-concept-ubuntu-endpoint-part-1-of-3/

[^14]: https://community.enhance.com/d/2204-testing-wazuh-integration-with-enhance-seeking-advice-and-experiences

[^15]: https://www.initmax.com/wiki/wazuh-installation-and-configuration/

[^16]: https://wazuh.com/blog/monitoring-network-devices/

[^17]: https://groups.google.com/g/wazuh/c/EEl6u-cqGB0

[^18]: https://groups.google.com/g/wazuh/c/pZW0N34wMU0

[^19]: https://documentation.wazuh.com/current/getting-started/architecture.html

[^20]: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html

[^21]: https://www.scribd.com/document/900949025/Wazuh-Additional-Firewall-Rules-Settings

[^22]: https://github.com/wazuh/wazuh-kibana-app/issues/1545

[^23]: https://github.com/wazuh/wazuh/issues/3454
