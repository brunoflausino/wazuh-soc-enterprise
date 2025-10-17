# Conpot Integration with Wazuh

## Overview
**Conpot** is an open-source industrial control systems (ICS) honeypot used to emulate ICS devices and protocols for threat intelligence, research and SOC validation.  
This document describes the deployment and Wazuh integration methodology used in the Wazuh SOC Enterprise lab (deployment performed on Ubuntu using Docker), including deployment artifacts, testing, Wazuh ingestion validation, recommended rules and operational notes.

**Environment (validated)**  
- Host OS: Ubuntu (x86_64)  
- Conpot image: `ghcr.io/telekom-security/conpot:24.04.1` (reported Conpot app version 0.6.0)  
- Container IP example: `172.21.0.2` (Docker bridge)  
- Host-exposed ports: `80/tcp`, `102/tcp`, `502/tcp`, `161/udp`  
- Additional container services (internal): FTP(21), TFTP(69), ENIP(44818), BACnet(47808), IPMI(623)

---

## 1) Requirements
- Docker & Docker Compose (recent stable)  
- Wazuh Manager with Docker JSON log collection enabled (see ossec.conf)  
- `curl`, `nc` (netcat), `logger` for tests  
- Sufficient privileges to write to `/opt/honeypots/` and control containers

---

## 2) Deployment (Docker)

### 2.1 Recommended directory
```

/opt/honeypots/conpot/
├── docker-compose.yml
└── quick_deploy_conpot.sh

````

### 2.2 Example `docker-compose.yml`
Create `/opt/honeypots/conpot/docker-compose.yml`:

```yaml
version: "3.8"
services:
  conpot:
    image: ghcr.io/telekom-security/conpot:24.04.1
    container_name: conpot
    command: ["conpot", "-f", "--template", "default"]
    ports:
      - "80:80"       # HTTP
      - "502:502"     # Modbus/TCP
      - "102:102"     # S7Comm (Siemens)
      - "161:161/udp" # SNMP
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
````

**Design notes**

* `restart: unless-stopped` ensures automatic recovery after reboots.
* Docker `json-file` driver + log rotation integrates with Wazuh's existing Docker collector and prevents disk exhaustion.

### 2.3 Quick automated deploy script (`quick_deploy_conpot.sh`)

Create and run this script to generate the compose file and start the service:

```bash
#!/bin/bash
# quick_deploy_conpot.sh - Automated Conpot deployment
set -e
BASE_DIR="/opt/honeypots/conpot"
sudo mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

sudo tee docker-compose.yml > /dev/null <<'EOF'
version: "3.8"
services:
  conpot:
    image: ghcr.io/telekom-security/conpot:24.04.1
    container_name: conpot
    command: ["conpot", "-f", "--template", "default"]
    ports:
      - "80:80"
      - "502:502"
      - "102:102"
      - "161:161/udp"
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF

# Start container
sudo docker compose up -d

# Wait a few seconds
sleep 5

# Show status and a basic HTTP probe
sudo docker ps --filter name=conpot --format "table {{.ID}}\t{{.Image}}\t{{.Status}}"
echo "HTTP probe:"
curl -sI http://127.0.0.1/ | head -1
echo "Latest logs:"
sudo docker logs conpot --tail 5 || true
```

Run:

```bash
sudo chmod +x quick_deploy_conpot.sh
sudo ./quick_deploy_conpot.sh
```

---

## 3) Integration with Wazuh

### 3.1 Wazuh existing Docker collection (no change required)

In this environment Wazuh already collects Docker logs via `ossec.conf`:

```xml
<!-- Example excerpt from /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/docker/containers/*/*-json.log</location>
  <only-future-events>no</only-future-events>
</localfile>
```

This wildcard collects container JSON logs (Conpot stdout/stderr), so Conpot events are ingested without additional Manager config.

### 3.2 Ensure permissions & start

* Confirm Docker is running and container started.
* Wazuh Manager must have access to Docker log path (default managed by Wazuh when installed as root).

Restart Wazuh if you change collection configuration:

```bash
sudo systemctl restart wazuh-manager
```

---

## 4) Testing & Validation

### 4.1 Quick test script (`test_integration.sh`)

Use this to generate connection events and validate ingestion:

```bash
#!/bin/bash
# test_integration.sh - Verify Conpot-Wazuh integration
set -e
echo "=== Testing Conpot Integration ==="

# HTTP test
echo "HTTP test:"
curl -sI http://127.0.0.1/ | head -1

# Modbus (502)
echo "Modbus test:"
timeout 2 nc -vz 127.0.0.1 502 || true

# S7 (102)
echo "S7 test:"
timeout 2 nc -vz 127.0.0.1 102 || true

# Syslog token for Wazuh archives verification
TOKEN="TEST_$(date +%Y%m%d_%H%M%S)"
echo "Sending syslog token: $TOKEN"
logger -n 127.0.0.1 -T -P 514 "$TOKEN" || true

sleep 3
ARCH="/var/ossec/logs/archives/archives.json" 
echo "Looking for token in archives:"
sudo grep -a "$TOKEN" "$ARCH" | head -1 || echo "Token not found yet"
echo "Counting Conpot events:"
sudo grep -E "New http session|New Modbus connection|New S7 connection" -c "$ARCH" || echo "0"
echo "=== Test complete ==="
```

Run:

```bash
sudo chmod +x test_integration.sh
sudo ./test_integration.sh
```

### 4.2 Verify archives & sample event

Check Wazuh archives for Conpot logs:

```bash
sudo tail -n 50 /var/ossec/logs/archives/archives.json | grep -i conpot | sed -n '1,6p'
```

A sample archives entry contains:

* `data.log` with lines such as: `New http session from 172.21.0.1 (...)`
* `decoder.name`: `json`
* `location`: path to the container json log

---

## 5) Recommended Wazuh Rules (optional)

If you want active alerts for Conpot interactions, add rules under `/var/ossec/etc/rules/local_rules.xml` (example IDs start at `100100`):

```xml
<group name="conpot,ics,honeypot,scada">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="data.log">^[0-9-]+ [0-9:,]+ </field>
    <match>New.*session|New.*connection</match>
    <description>Conpot ICS honeypot: Protocol interaction detected</description>
  </rule>

  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <field name="data.log">New http session</field>
    <description>Conpot: HTTP session detected</description>
    <group>conpot,web,http</group>
  </rule>

  <rule id="100102" level="7">
    <if_sid>100100</if_sid>
    <field name="data.log">New Modbus connection</field>
    <description>Conpot: Modbus/TCP connection detected</description>
    <group>conpot,scada,modbus</group>
  </rule>

  <rule id="100103" level="7">
    <if_sid>100100</if_sid>
    <field name="data.log">New S7 connection</field>
    <description>Conpot: S7Comm (Siemens) connection detected</description>
    <group>conpot,scada,siemens,s7</group>
  </rule>

  <rule id="100104" level="5">
    <if_sid>100100</if_sid>
    <field name="data.log">snmp</field>
    <description>Conpot: SNMP interaction detected</description>
    <group>conpot,snmp</group>
  </rule>

  <rule id="100110" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100100</if_matched_sid>
    <description>Conpot: Multiple ICS protocol interactions in 60s - possible automated scan</description>
    <group>conpot,attack,reconnaissance</group>
  </rule>
</group>
```

After editing:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

---

## 6) Event Fields & Decoding

Wazuh's built-in JSON decoder extracts:

* `data.log` — the Conpot log message (e.g., "New Modbus connection from x.x.x.x")
* `data.stream` — stdout/stderr
* `data.time` — Docker timestamp
* `location` — container json log path
* `timestamp`, `agent.name`, `agent.id`

Use these fields in rules (e.g., `<field name="data.log">New Modbus connection</field>`).

---

## 7) Operational Management & Utilities

### 7.1 Manual commands

```bash
# Start/Stop/Restart
sudo docker start conpot
sudo docker stop conpot
sudo docker restart conpot

# Status and logs
sudo docker ps | grep conpot
sudo docker logs -f conpot
sudo docker logs --tail 50 conpot

# Inspect container IP
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' conpot
```

### 7.2 Aliases (optional)

Add to `~/.bashrc`:

```bash
echo "alias conpot-start='sudo docker start conpot'" >> ~/.bashrc
echo "alias conpot-stop='sudo docker stop conpot'" >> ~/.bashrc
echo "alias conpot-logs='sudo docker logs -f conpot'" >> ~/.bashrc
echo "alias conpot-status='sudo docker ps | grep conpot'" >> ~/.bashrc
source ~/.bashrc
```

### 7.3 Unified management script (optional)

Create `/usr/local/bin/conpot`:

```bash
#!/bin/bash
case "$1" in
  start) docker start conpot ;;
  stop) docker stop conpot ;;
  restart) docker restart conpot ;;
  logs) docker logs -f conpot ;;
  status) docker ps | grep conpot ;;
  *) echo "Use: conpot {start|stop|restart|logs|status}" ;;
esac
```

Make executable:

```bash
sudo chmod +x /usr/local/bin/conpot
```

---

## 8) Troubleshooting

**Container won't start**

```bash
sudo systemctl status docker
sudo docker logs conpot
cd /opt/honeypots/conpot && sudo docker compose down && sudo docker compose up -d
```

**Events not appearing in Wazuh**

```bash
sudo systemctl status wazuh-manager
sudo docker inspect conpot | grep LogPath
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

**Port conflicts**

```bash
sudo lsof -i :80
# If conflict, change host mapping in docker-compose (e.g., 8080:80)
```

**Log parsing issues**

* If you see `is not a JSON object` in Wazuh logs, confirm Docker json logs are intact and use `<log_format>json</log_format>`.

---

## 9) Performance & Observed Metrics (from lab)

* Container startup time: ~5s
* Event ingestion latency: <1s
* Docker log rotation: 10MB, 3 files (per compose config)
* Memory footprint (Conpot): ~200MB (varies)

---

## 10) Security Considerations

* Run Conpot on an isolated host or network segment (DMZ) to avoid lateral risk.
* Restrict firewall rules to limit external access to honeypot ports (if public exposure is not desired).
* Use network rate limiting to mitigate DoS/scan noise.
* Keep Conpot images updated and monitor upstream changes.
* Treat captured data as potential evidence; maintain chain-of-custody if used for investigations.

---

## 11) Summary & Recommendations

* Zero-configuration integration achieved when Wazuh already collects Docker JSON logs.
* Enable the recommended custom rules if you want active alerting on ICS interactions (IDs 100100–100110 used as examples).
* Use the provided `quick_deploy_conpot.sh` and `test_integration.sh` to deploy and validate reproducibly.
* For production alerting, tailor rules and thresholds to reduce false positives and forward high-severity alerts to SOAR/IR (e.g., Shuffle, DFIR-IRIS).

---

## References

* Telekom Security — Conpot container: `ghcr.io/telekom-security/conpot`
* Wazuh Documentation — Container Security / JSON logs
* Docker Documentation — Logging drivers & compose spec

---

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab — Threat Intelligence Stack*
