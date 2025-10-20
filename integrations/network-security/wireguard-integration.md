# Technical Report: Wazuh + WireGuard Integration

## Executive Summary

This report presents a complete solution for integrating WireGuard VPN monitoring with the Wazuh security platform. The implementation allows for full visibility into VPN connections, anomaly detection, access auditing, and automated incident response.

**Main benefits:**

- Real-time monitoring of VPN connections
- Detection of unauthorized access attempts
- Alerts about abnormal disconnections
- Performance and throughput metrics
- Complete access auditing
- Integration with corporate SIEM

---

## 1. Introduction

### 1.1 About WireGuard

WireGuard é um protocolo VPN moderno que oferece:

- **Superior performance**: 2-3x faster than OpenVPN
- **Simplicity**: ~4,000 lines of code vs ~100,000 for OpenVPN
- **Security**: State-of-the-art cryptography (Curve25519, ChaCha20, Poly1305)
- **Efficiency**: Runs in Linux kernel with low overhead

### 1.2 About Wazuh

Wazuh é uma plataforma open source para:

- SIEM (Security Information and Event Management)
- XDR (Extended Detection and Response)
- File integrity monitoring
- Vulnerability detection
- Regulatory compliance

### 1.3 Integration Objective

Centralizar logs e eventos do WireGuard no Wazuh para:

- Detection of suspicious accesses
- Correlation with other security events
- Automated alerts
- Unified dashboards
- Incident response

---

## 2. Solution Architecture

### 2.1 Components

WireGuard VPN Servidor → Logs via syslog → Wazuh Agent → ossec-agent → TLS encrypted → Wazuh Manager → Elasticsearch → Kibana

```
┌─────────────────┐
│  WireGuard VPN  │
│    (Servidor)   │
└────────┬────────┘
         │
         │ Logs via syslog
         │
┌────────▼────────┐
│  Wazuh Agent    │
│   (ossec-agent) │
└────────┬────────┘
         │
         │ TLS encrypted
         │
┌────────▼────────┐
│ Wazuh Manager   │
│  + Elasticsearch│
│  + Kibana       │
└─────────────────┘
```

### 2.2 Data Flow

1. WireGuard generates connection/disconnection logs
2. systemd/syslog captures the logs
3. Custom script collects metrics from `wg show`
4. Wazuh Agent processes and sends to Manager
5. Manager applies detection rules
6. Alerts are generated and visualized in Kibana

---

## 3. WireGuard Configuration

### 3.1 Installation (Ubuntu/Debian)

```bash
# Update repositories
sudo apt update

# Install WireGuard
sudo apt install wireguard wireguard-tools

# Verify installation
wg --version
```

### 3.2 Key Generation

```bash
# Create configuration directory
sudo mkdir -p /etc/wireguard
cd /etc/wireguard

# Generate server private key
wg genkey | sudo tee serverprivate.key

# Generate server public key
sudo cat serverprivate.key | wg pubkey | sudo tee serverpublic.key

# Set secure permissions
sudo chmod 600 serverprivate.key
```

### 3.3 Server Configuration

Create file `/etc/wireguard/wg0.conf`:

```ini
[Interface]
# Server private key
PrivateKey = [CONTENT OF serverprivate.key]
# VPN interface IP address
Address = 10.8.0.1/24
# Listening port
ListenPort = 51820
# Enable packet forwarding
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
# Logging important for Wazuh
SaveConfig = false

# Client 1
[Peer]
PublicKey = CLIENT_PUBLIC_KEY_1
AllowedIPs = 10.8.0.2/32
PersistentKeepalive = 25

# Client 2
[Peer]
PublicKey = CLIENT_PUBLIC_KEY_2
AllowedIPs = 10.8.0.3/32
PersistentKeepalive = 25
```

### 3.4 Enable Service

```bash
# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Enable and start service
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Verify status
sudo systemctl status wg-quick@wg0
sudo wg show
```

### 3.5 Client Configuration

Create file `client1.conf`:

```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.8.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = SERVER_PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0, ::
PersistentKeepalive = 25
```

---

## 4. Wazuh Agent Configuration

### 4.1 Agent Installation

```bash
# Download and install Wazuh Agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-agent

# Configure Manager
echo "WAZUH_MANAGER_IP" > /var/ossec/etc/client.keys
# Or edit /var/ossec/etc/ossec.conf.d/manager.conf

# Start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### 4.2 ossec.conf Configuration

Edit `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <!-- Collect logs from syslog (WireGuard logs here) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <!-- Collect logs from systemd journal for WireGuard -->
  <localfile>
    <log_format>command</log_format>
    <command>journalctl -u wg-quick@wg0 -n 100 --no-pager</command>
    <frequency>60</frequency>
  </localfile>

  <!-- Execute custom monitoring script -->
  <localfile>
    <log_format>json</log_format>
    <command>/var/ossec/wodles/wireguard-monitor.sh</command>
    <frequency>60</frequency>
  </localfile>

  <!-- Monitor configuration file -->
  <syscheck>
    <directories check_all="yes" realtime="yes">/etc/wireguard</directories>
  </syscheck>
</ossec_config>
```

### 4.3 Custom Monitoring Script

Create `/var/ossec/wodles/wireguard-monitor.sh`:

```bash
#!/bin/bash
# WireGuard monitoring script for Wazuh
# Collects metrics and status of peers

# Check if WireGuard is running
if ! systemctl is-active --quiet wg-quick@wg0; then
    echo "{\"wireguard\": {\"status\": \"down\"}, \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"}"
    exit 0
fi

# Get peer information
wg show wg0 dump | tail -n +2 | while IFS= read -r publickey presharedkey endpoint allowedips latesthandshake transferrx transfertx persistentkeepalive; do
    # Calculate time since last handshake
    if [ "$latesthandshake" != "0" ]; then
        currenttime=$(date +%s)
        timesincehandshake=$((currenttime - latesthandshake))
    else
        timesincehandshake=-1
    fi

    # Determine connection status
    if [ $timesincehandshake -lt 180 ] && [ $timesincehandshake -ge 0 ]; then
        connectionstatus="active"
    elif [ $timesincehandshake -eq -1 ]; then
        connectionstatus="neverconnected"
    else
        connectionstatus="stale"
    fi

    # Convert bytes to human readable format
    rxmb=$(echo "scale=2; $transferrx / 1048576" | bc -l)
    txmb=$(echo "scale=2; $transfertx / 1048576" | bc -l)

    # Output in JSON format for Wazuh
    cat << EOF
{
  "wireguard": {
    "interface": "wg0",
    "peer": {
      "publickey": "${publickey:0:16}...${publickey: -6}",
      "publickeyfull": "$publickey",
      "endpoint": "$endpoint",
      "allowedips": "$allowedips",
      "connectionstatus": "$connectionstatus",
      "timesincehandshakeseconds": $timesincehandshake,
      "transfer": {
        "receivedbytes": $transferrx,
        "receivedmb": $rxmb,
        "transmittedbytes": $transfertx,
        "transmittedmb": $txmb
      },
      "persistentkeepalive": "$persistentkeepalive"
    }
  },
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF
done

# Interface general information
interfaceinfo=$(ip -j addr show wg0 2>/dev/null | jq -c '.[^0]')
if [ -n "$interfaceinfo" ]; then
    echo "{\"wireguard\": {\"interfaceinfo\": $interfaceinfo}, \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"}"
fi
```

Make script executable:

```bash
sudo chmod +x /var/ossec/wodles/wireguard-monitor.sh
sudo chown root:ossec /var/ossec/wodles/wireguard-monitor.sh
```

---

## 5. Wazuh Manager Configuration

### 5.1 Custom Rules

Create `/var/ossec/etc/rules/local_rules.xml`:

```xml
<!-- Custom rules for WireGuard - Author: Security Team - Date: 2025 -->
<group name="wireguard,vpn,">
  <!-- Detection of WireGuard events in syslog -->
  <rule id="100200" level="3">
    <decoded_as>wg-decoded</decoded_as>
    <description>WireGuard Event detected</description>
  </rule>

  <!-- Peer connected -->
  <rule id="100201" level="3">
    <if_sid>100200</if_sid>
    <match>Peer.*connected.*handshake</match>
    <description>WireGuard Peer connection established</description>
  </rule>

  <!-- Peer disconnected -->
  <rule id="100202" level="5">
    <if_sid>100200</if_sid>
    <match>Peer.*disconnected.*removed.*timeout</match>
    <description>WireGuard Peer disconnected</description>
  </rule>

  <!-- JSON rules from custom script -->
  <rule id="100210" level="3">
    <decoded_as>json</decoded_as>
    <field name="wireguard.field">.*</field>
    <description>WireGuard Metrics collected</description>
  </rule>

  <!-- Active connection detected -->
  <rule id="100211" level="3">
    <if_sid>100210</if_sid>
    <field name="wireguard.peer.connectionstatus">active</field>
    <description>WireGuard Peer connection is active</description>
  </rule>

  <!-- Stale connection - possible problem -->
  <rule id="100212" level="7">
    <if_sid>100210</if_sid>
    <field name="wireguard.peer.connectionstatus">stale</field>
    <description>WireGuard Peer connection is stale - no recent handshake</description>
  </rule>

  <!-- Peer never connected -->
  <rule id="100213" level="5">
    <if_sid>100210</if_sid>
    <field name="wireguard.peer.connectionstatus">neverconnected</field>
    <description>WireGuard Peer has never established connection</description>
  </rule>

  <!-- WireGuard service down -->
  <rule id="100214" level="10">
    <if_sid>100210</if_sid>
    <field name="wireguard.status">down</field>
    <description>WireGuard Service is down!</description>
  </rule>

  <!-- High data transfer detected (adjustable threshold) -->
  <rule id="100215" level="5">
    <if_sid>100211</if_sid>
    <field name="wireguard.peer.transfer.receivedmb" type="pcre2">[4-9][0-9]{3,}|[1-9][0-9]{4,}</field>
    <description>WireGuard High data transfer detected: $wireguard.peer.transfer.receivedmb MB received</description>
  </rule>

  <!-- Configuration file changed -->
  <rule id="100220" level="8">
    <if_sid>550</if_sid>
    <match>/etc/wireguard</match>
    <description>WireGuard Configuration file modified</description>
  </rule>

  <!-- Multiple disconnections in short period -->
  <rule id="100221" level="10">
    <frequency>3</frequency>
    <timeframe>300</timeframe>
    <if_matched_sid>100212</if_matched_sid>
    <same_field>wireguard.peer.publickeyfull</same_field>
    <description>WireGuard Multiple stale connections from same peer - possible network issue or attack</description>
  </rule>

  <!-- Unauthorized connection attempt -->
  <rule id="100222" level="12">
    <if_sid>100200</if_sid>
    <match>Invalid.*unauthorized.*not allowed.*rejected</match>
    <description>WireGuard Unauthorized connection attempt detected</description>
  </rule>
</group>
```

### 5.2 Custom Decoders

Create `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<!-- Custom decoders for WireGuard -->
<decoder name="wireguard-syslog">
  <prematch>^.*wg-.*WireGuard.*</prematch>
</decoder>

<decoder name="wireguard-peer">
  <parent>wireguard-syslog</parent>
  <regex>^.*Peer (.*):</regex>
  <order>peerkey</order>
</decoder>

<decoder name="wireguard-endpoint">
  <parent>wireguard-syslog</parent>
  <regex>^.*endpoint (.*):.*</regex>
  <order>endpoint</order>
</decoder>

<!-- JSON decoder for custom script already exists natively in Wazuh -->
```

### 5.3 Restart Wazuh Manager

```bash
# Verify syntax
/var/ossec/bin/wazuh-logtest

# Restart manager
systemctl restart wazuh-manager

# Verify logs
tail -f /var/ossec/logs/ossec.log
```

---

## 6. Dashboards and Visualizations

### 6.1 Create Index Pattern in Kibana

1. Access Kibana: https://WAZUH_MANAGER:443
2. Go to Stack Management → Index Patterns
3. Create pattern: wazuh-alerts-*
4. Select timestamp field

### 6.2 WireGuard VPN Dashboard

Create visualizations in Kibana:

A. **Gauge: Service Status**

- Type: Metric
- Query: `rule.group:wireguard AND wireguard.status`
- Metric: Count
- Color ranges: green (up), red (down)

B. **Line Chart: Active Connections Over Time**

- Type: Line
- X-axis: timestamp (interval 5m)
- Y-axis: Count of `wireguard.peer.connectionstatus:active`

C. **Data Table: Connected Peers**

- Columns:
  - `wireguard.peer.publickey`
  - `wireguard.peer.endpoint`
  - `wireguard.peer.connectionstatus`
  - `wireguard.peer.timesincehandshakeseconds`
  - `timestamp`

D. **Pie Chart: Status Distribution**

- Slices: `wireguard.peer.connectionstatus`
- Metric: Count

E. **Heat Map: Data Traffic**

- X-axis: timestamp
- Y-axis: `wireguard.peer.publickey`
- Colors: `wireguard.peer.transfer.receivedmb`

F. **Bar Chart: Top Peers by Traffic**

- X-axis: `wireguard.peer.publickey`
- Y-axis: Sum of `wireguard.peer.transfer.receivedmb`
- Order: Descending
- Limit: 10

### 6.3 Important Alerts

Configure visualizations for:

- Peers with stale connections (last 24h)
- Configuration file changes
- Unauthorized connection attempts
- WireGuard service down
- Multiple disconnections from same peer

---

## 7. Use Cases and Alerts

### 7.1 Intrusion Detection

Cenário: Tentativa de conexão com chave pública não autorizada

- Detection: Rule 100222 (level 12)
- Logs with "unauthorized" or "rejected" messages
- Response: Immediate alert to security team
- Block source IP (active response)
- Investigate public key origin

### 7.2 Availability Monitoring

Cenário: Serviço WireGuard parou inesperadamente

- Detection: Rule 100214 (level 10)
- "down" status in JSON
- Response: Critical alert
- Automatic restart attempt
- Escalate to infrastructure team

### 7.3 Anomaly Analysis

Cenário: Peer com padrão anormal de desconexões

- Detection: Rule 100221 (frequency rule)
- 3 stale connections in 5 minutes
- Response: Investigate network issues
- Check client configuration
- Possible DoS attack

### 7.4 Compliance Auditing

<span style="display:none">[^1][^10][^2][^3][^4][^5][^6][^7][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://w3cybersec.com/wazuh-siem/documentation

[^2]: https://www.reddit.com/r/Wazuh/comments/1fsb6mr/wazuh_on_vps/

[^3]: https://w3cybersec.com/wazuh-siem/documentation/integrations

[^4]: https://www.youtube.com/watch?v=mgU_q1rJveg

[^5]: https://avidadesuporte.wordpress.com/2025/06/29/hacking-wazuh-introducao-e-instalacao/

[^6]: https://cloud.google.com/chronicle/docs/ingestion/default-parsers/wazuh?hl=pt-br

[^7]: https://my.minivps.com.br/knowledgebase/7/Instrucoes-de-uso-do-Wireguard.html?language=portuguese-pt

[^8]: https://documentation.wazuh.com/current/index.html

[^9]: https://www.youtube.com/watch?v=AOyHDz308bs

[^10]: https://www.youtube.com/watch?v=1oSYqg3DotE
