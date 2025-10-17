# SpiderFoot Integration with Wazuh

## Overview
**SpiderFoot** is an open-source OSINT/automation tool that can produce structured JSONL event output.  
This document describes the full methodology used in the Wazuh SOC Enterprise lab to integrate SpiderFoot with a single-node Wazuh Manager via local JSON ingestion, validate the pipeline, and add minimal rules to surface baseline events and credential exposure. It includes reproducible scripts used in the lab.

**Goal:** ingest SpiderFoot JSONL events into Wazuh, decode them as JSON, apply alerting rules, and validate via Wazuh archives/alerts.

---

## 1) Environment & Assumptions
- SpiderFoot HTTP UI (service) listening on `127.0.0.1:5002` (Digest auth).  
- SpiderFoot event file: `/var/log/spiderfoot/events.jsonl` (one JSON object per line).  
- Wazuh Manager runs on same host and reads files from `/var/log/spiderfoot/events.jsonl`.  
- Wazuh writes archives to `/var/ossec/logs/archives/archives.json` and alerts to `/var/ossec/logs/alerts/alerts.json`.  
- Filebeat may be present but **is not** part of the SpiderFoot→Wazuh ingestion path in this design.

---

## 2) Prerequisites
```text
- Wazuh Manager installed and running (manager must have read access to /var/log/spiderfoot/events.jsonl)
- SpiderFoot installed and running (service user: spiderfoot)
- curl, jq, logger, filebeat (optional), bash, sudo
- root/sudo access for configuration and restarts
````

---

## 3) Configure Wazuh to collect SpiderFoot JSONL

Add (or confirm) this `<localfile>` entry in `/var/ossec/etc/ossec.conf` on the manager:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/spiderfoot/events.jsonl</location>
  <only-future-events>yes</only-future-events>
  <label key="@source">spiderfoot</label>
  <label key="spiderfoot.profile">passive</label>
</localfile>
```

Then restart Wazuh manager:

```bash
sudo systemctl restart wazuh-manager
```

Ensure permissions:

```bash
sudo mkdir -p /var/log/spiderfoot
sudo chown spiderfoot:wazuh /var/log/spiderfoot
sudo chmod 750 /var/log/spiderfoot
# file itself:
sudo touch /var/log/spiderfoot/events.jsonl
sudo chown spiderfoot:wazuh /var/log/spiderfoot/events.jsonl
sudo chmod 640 /var/log/spiderfoot/events.jsonl
```

---

## 4) Wazuh Rules (baseline + credential exposure)

Place this rule block (single authoritative source) inside `/var/ossec/etc/rules/local_rules.xml` (or a single dedicated file, but avoid duplicates):

```xml
<group name="spiderfoot,local,">
  <!-- Base: any JSON line from SpiderFoot file -->
  <rule id="100600" level="3">
    <location type="pcre2">/var/log/spiderfoot/events\.jsonl</location>
    <decoded_as>json</decoded_as>
    <field name="msg">.+</field>
    <description>SpiderFoot: event collected</description>
    <group>spiderfoot,</group>
  </rule>

  <!-- Elevated: possible credential/secret exposure -->
  <rule id="100601" level="8">
    <if_sid>100600</if_sid>
    <match>password|credential|creds|apikey|token|leak|exposed|pwned</match>
    <description>SpiderFoot: possible credential/secret exposure</description>
    <group>spiderfoot,threatintel,</group>
  </rule>
</group>
```

After editing, test rule syntax and restart analysisd:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

**Important:** avoid duplicating these rules in multiple files — keep one authoritative block to prevent `duplicate rule ID` warnings.

---

## 5) Log rotation (keep Wazuh reading)

Create `/etc/logrotate.d/spiderfoot`:

```text
/var/log/spiderfoot/events.jsonl {
  daily
  rotate 7
  compress
  missingok
  notifempty
  su spiderfoot wazuh
  create 0640 spiderfoot wazuh
  copytruncate
}
```

`copytruncate` lets SpiderFoot keep writing while Wazuh reads rotated files.

---

## 6) SpiderFoot credential file (Digest auth)

SpiderFoot requires a credentials file for Digest authentication. Recent SpiderFoot builds expect it under the spiderfoot user home:

* Path example: `/opt/spiderfoot/.spiderfoot/passwd` **or** `~/.spiderfoot/passwd` for the spiderfoot system user.

Create the passwd file (avoid `!` expansion issues — see script S5 below):

```bash
# run as root or via sudo; this example writes sfadmin:StrongP@ssw0rd!
set +H || true   # disable history expansion to avoid '!' issues
sudo -u spiderfoot sh -c 'mkdir -p ~/.spiderfoot && printf "%s\n" "sfadmin:SpiderFoot!2025" > ~/.spiderfoot/passwd'
sudo chown -R spiderfoot:wazuh /opt/spiderfoot/.spiderfoot ~/.spiderfoot 2>/dev/null || true
sudo chmod 750 /opt/spiderfoot/.spiderfoot ~/.spiderfoot 2>/dev/null || true
sudo chmod 640 /opt/spiderfoot/.spiderfoot/passwd ~/.spiderfoot/passwd 2>/dev/null || true
# Remove legacy location if present
sudo rm -f /opt/spiderfoot/passwd || true
# Restart SpiderFoot service afterwards
sudo systemctl restart spiderfoot
```

Validate Digest auth:

```bash
curl --digest -u 'sfadmin:SpiderFoot!2025' -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5002/
# expect 200
```

---

## 7) Reproducible scripts (publication-ready)

Below are the lab scripts (S1–S6) used to reproduce the integration. You can place them under `/usr/local/bin/` or `~/scripts/` and run as needed.

### S1 — Neutralize & recover Filebeat (if present)

```bash
#!/usr/bin/env bash
# S1: Reset & neutralize Filebeat (do not touch SpiderFoot logs)
set -euo pipefail

sudo systemctl stop filebeat || true
sudo cp -a /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

sudo bash -c 'cat > /etc/filebeat/filebeat.yml << "EOF"
filebeat.modules: []
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/dpkg.log
    ignore_older: 24h
output.file:
  path: /var/log/filebeat-out
  filename: filebeat
  rotate_every_kb: 10240
  number_of_files: 2
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 3
  rotateeverybytes: 10485760
EOF'

sudo install -d -m 0755 /var/log/filebeat-out
TS=$(date +%Y%m%d_%H%M%S)
sudo install -d -m 0750 /var/lib/filebeat/backup-registry-$TS
[ -e /var/lib/filebeat/registry ] && sudo mv /var/lib/filebeat/registry /var/lib/filebeat/backup-registry-$TS/ || true
[ -e /var/lib/filebeat/registry.old ] && sudo mv /var/lib/filebeat/registry.old /var/lib/filebeat/backup-registry-$TS/ || true
sudo chown -R root:root /var/lib/filebeat /var/log/filebeat-out || true
sudo chmod 0750 /var/lib/filebeat || true

sudo filebeat test config -c /etc/filebeat/filebeat.yml || true
sudo systemctl daemon-reload || true
sudo systemctl restart filebeat || true
sleep 1
systemctl --no-pager --full status filebeat | sed -n '1,12p' || true
echo "S1 complete"
```

### S2 — Insert SpiderFoot rules (idempotent)

```bash
#!/usr/bin/env bash
# S2: Ensure SpiderFoot rules are present in local_rules.xml (idempotent)
set -euo pipefail
RULE_FILE="/var/ossec/etc/rules/local_rules.xml"
TMP="/tmp/local_rules.xml.$$"

# If the ruleset already contains 100600, skip adding.
if sudo grep -q "100600" "$RULE_FILE" 2>/dev/null; then
  echo "SpiderFoot rules already present in $RULE_FILE (skipping)"
  exit 0
fi

sudo awk 'BEGIN{added=0}
  /<rules>/ && added==0 {
    print;
    print "<group name=\"spiderfoot,local,\">"
    print "  <rule id=\"100600\" level=\"3\">"
    print "    <location type=\"pcre2\">/var/log/spiderfoot/events\\.jsonl</location>"
    print "    <decoded_as>json</decoded_as>"
    print "    <field name=\"msg\">.+</field>"
    print "    <description>SpiderFoot: event collected</description>"
    print "    <group>spiderfoot,</group>"
    print "  </rule>"
    print "  <rule id=\"100601\" level=\"8\">"
    print "    <if_sid>100600</if_sid>"
    print "    <match>password|credential|creds|apikey|token|leak|exposed|pwned</match>"
    print "    <description>SpiderFoot: possible credential/secret exposure</description>"
    print "    <group>spiderfoot,threatintel,</group>"
    print "  </rule>"
    print "</group>"
    added=1
    next
  } {print}
  END{ if(added==0) {
    print \"<group name=\\\"spiderfoot,local,\\\">... (rules not inserted) </group>\"
  }}' "$RULE_FILE" | sudo tee "$TMP" > /dev/null
sudo mv "$TMP" "$RULE_FILE"
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
echo "S2 complete"
```

### S3 — Silence noisy packs (if needed)

```bash
#!/usr/bin/env bash
# S3: Add rule_exclude entries (idempotent, targeted)
set -euo pipefail
CONF="/var/ossec/etc/ossec.conf"
sudo grep -q "0350-amazon_rules.xml" "$CONF" || sudo sed -i '/<ruleset>/,/<\/ruleset>/ s|</ruleset>|<rule_exclude>0350-amazon_rules.xml</rule_exclude>\n</ruleset>|' "$CONF" || true
sudo grep -q "0365-auditd_rules.xml" "$CONF" || sudo sed -i '/<ruleset>/,/<\/ruleset>/ s|</ruleset>|<rule_exclude>0365-auditd_rules.xml</rule_exclude>\n</ruleset>|' "$CONF" || true
sudo systemctl restart wazuh-manager || true
sleep 2
sudo tail -n 80 /var/ossec/logs/ossec.log | egrep -i 'WARNING|error|rules|analysisd' || true
echo "S3 complete"
```

### S4 — Logrotate policy for SpiderFoot

```bash
#!/usr/bin/env bash
# S4: Write logrotate policy
sudo tee /etc/logrotate.d/spiderfoot >/dev/null <<'EOF'
/var/log/spiderfoot/events.jsonl {
  daily
  rotate 7
  compress
  missingok
  notifempty
  su spiderfoot wazuh
  create 0640 spiderfoot wazuh
  copytruncate
}
EOF
echo "S4 complete"
```

### S5 — SpiderFoot credentials and service health

```bash
#!/usr/bin/env bash
# S5: Create SpiderFoot credentials file and restart service
set -euo pipefail
# Avoid bash history expansion issues with "!" in passwords
set +H 2>/dev/null || true

# Example credential: sfadmin:SpiderFoot!2025
# Replace with secure password in production.
sudo -u spiderfoot sh -c 'mkdir -p ~/.spiderfoot && printf "%s\n" "sfadmin:SpiderFoot!2025" > ~/.spiderfoot/passwd'
# ensure ownership & perms
sudo chown -R spiderfoot:wazuh /opt/spiderfoot/.spiderfoot ~/.spiderfoot 2>/dev/null || true
sudo chmod 750 /opt/spiderfoot/.spiderfoot ~/.spiderfoot 2>/dev/null || true
sudo chmod 640 /opt/spiderfoot/.spiderfoot/passwd ~/.spiderfoot/passwd 2>/dev/null || true
# remove legacy
sudo rm -f /opt/spiderfoot/passwd || true

sudo systemctl daemon-reload || true
sudo systemctl restart spiderfoot || true
systemctl --no-pager --full status spiderfoot | sed -n '1,20p' || true

# Validate digest auth (expect HTTP 200)
curl --digest -u 'sfadmin:SpiderFoot!2025' -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5002/ || true

echo "S5 complete"
```

### S6 — Ingestion sanity & rule verification

```bash
#!/usr/bin/env bash
# S6: Inject test SpiderFoot events and verify archives/alerts
set -euo pipefail

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sudo tee -a /var/log/spiderfoot/events.jsonl > /dev/null <<EOF
{"@timestamp":"$TS","@source":"spiderfoot","msg":"integration-doublecheck-ok"}
EOF

TS2="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sudo tee -a /var/log/spiderfoot/events.jsonl > /dev/null <<EOF
{"@timestamp":"$TS2","@source":"spiderfoot","msg":"password token leaked for example.com"}
EOF

sleep 5

echo "---- archives.json (matching lines) ----"
sudo egrep -n '"integration-doublecheck-ok"|"password token leaked for example.com"' /var/ossec/logs/archives/archives.json | tail -n 10 || echo "no archives matches yet"

echo "---- alerts.json (rule matches) ----"
sudo jq -c 'select(.rule.id==100600 or .rule.id==100601) | {ts:.timestamp, rule:.rule.id, desc:.rule.description, msg:(.data.msg // .full_log // "")}' /var/ossec/logs/alerts/alerts.json | tail -n 10 || echo "no alerts matches yet"

echo "S6 complete"
```

---

## 8) Quick manual validation (one-liners)

* Check SpiderFoot UI:

```bash
curl --digest -u 'sfadmin:SpiderFoot!2025' -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5002/
```

* Inject a test event manually and check Wazuh:

```bash
printf '{"@timestamp":"%s","@source":"spiderfoot","msg":"integration-ok-after-passwd-move"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee -a /var/log/spiderfoot/events.jsonl
sleep 3
sudo egrep -n '"integration-ok-after-passwd-move"' /var/ossec/logs/archives/archives.json | tail -n 5 || true
sudo jq -c 'select(.rule.id==100600 or .rule.id==100601) | {ts:.timestamp, rule:.rule.id, desc:.rule.description, msg:(.data.msg // .full_log // "")}' /var/ossec/logs/alerts/alerts.json | tail -n 5 || true
```

---

## 9) Troubleshooting (common issues)

* **Wazuh not seeing events** — check file path and permissions; check `ossec.log` for parsing errors (e.g., `is not a JSON object`).
* **Duplicate rule IDs** — search rules directories for 100600/100601; keep a single authoritative block (avoid duplicates).
* **SpiderFoot 401/Crash loop** — move password file to the new supported location (see S5), ensure perms, restart service.
* **Filebeat interfering** — neutralize as in S1, or exclude SpiderFoot logs from Filebeat config.
* **Bash “event not found” when using `!`** — disable history expansion (`set +H`) or quote correctly when creating passwd.

---

## 10) Hardening & Operational Notes

* Bind SpiderFoot to `127.0.0.1` and place behind a reverse proxy with TLS if remote access is required. Add IP allow-lists and rate limits.
* Rotate credentials regularly and store secrets in a secure vault (do **not** hardcode).
* Tighten permissions: `chmod 640` on events file, `chown spiderfoot:wazuh`.
* Expand the 100601 match to include structured fields or module names to reduce false positives.
* For enterprise: route high-severity alerts into SOAR/IR and centralize logs.

---

## 11) Summary & next steps

* Added Wazuh collection for `/var/log/spiderfoot/events.jsonl`.
* Implemented rules 100600 (baseline) and 100601 (credential exposure).
* Provided scripts S1–S6 to neutralize Filebeat, add rules, write logrotate, place credentials, and validate ingestion.
* Recommended copying these scripts into a `scripts/spiderfoot/` repo folder and committing them for reproducibility.

---

## References

* Wazuh documentation — archives/alerts paths, rule syntax, JSON decoding
* SpiderFoot project docs (service/credentials)
* Elastic/Filebeat docs (registry, test config)
* Docker/logrotate manpages for rotation semantics

---

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab — Threat Intelligence Stack*
