# SpiderFoot Integration with Wazuh

## Overview
**SpiderFoot** is an automated OSINT reconnaissance tool that can produce JSON-line events suitable for ingestion by Wazuh.
This document records the methodology used in the Wazuh SOC Enterprise lab to integrate SpiderFoot → Wazuh (local JSON ingestion), validate the pipeline, apply protective log rotation and neutralize interfering Filebeat configurations. It includes the exact Wazuh rules used (IDs 100600 / 100601), operational scripts, test steps and hardening notes.

**Validated environment (lab)**
- SpiderFoot service: HTTP server on `127.0.0.1:5002` (Digest auth)
- SpiderFoot events file: `/var/log/spiderfoot/events.jsonl` (one JSON object per line)
- Wazuh Manager: single node, normal installation (paths: `/var/ossec/...`)
- Filebeat installed on same host but intentionally neutralized for SpiderFoot logs

---

## 1. Requirements
- Python/SpiderFoot installed (system package or container)
- Wazuh Manager with localfile collection enabled for SpiderFoot events (JSON)
- `curl`, `jq`, `logger`, `grep`, `filebeat` (for neutralization workflow)
- Privileges to edit `/var/ossec/etc/ossec.conf`, `/var/ossec/etc/rules/local_rules.xml` and to write `/var/log/spiderfoot/`

---

## 2. SpiderFoot: general deployment & auth
- Run SpiderFoot bound to `127.0.0.1` (do not expose publicly).
- Digest auth credentials file **must** be placed under the SpiderFoot user's home: `~/.spiderfoot/passwd` (one line `username:password`).
- If you use a package or systemd service, ensure the service user is `spiderfoot` (or adapt paths).

**Important notes**
- If your password contains `!` or other special characters, disable Bash history expansion for that command (`set +H`) or quote properly.
- Example credential file creation (replace placeholder with your secret — do not commit secrets):

```bash
# as root or with sudo
sudo -u spiderfoot mkdir -p /home/spiderfoot/.spiderfoot
sudo -u spiderfoot bash -c 'printf "%s\n" "sfadmin:REPLACE_WITH_STRONG_PASSWORD" > /home/spiderfoot/.spiderfoot/passwd'
sudo chown -R spiderfoot:wazuh /home/spiderfoot/.spiderfoot
sudo chmod 750 /home/spiderfoot/.spiderfoot
sudo chmod 640 /home/spiderfoot/.spiderfoot/passwd
````

Validate Digest auth:

```bash
curl --digest -u 'sfadmin:REPLACE_WITH_STRONG_PASSWORD' -s -o /dev/null -w '%{http_code}\n' [http://127.0.0.1:5002/](http://127.0.0.1:5002/)
# Expect 200
```

-----

## 3\. Wazuh integration (local JSON file ingestion)

### 3.1 ossec.conf snippet

Add a localfile entry on the Wazuh Manager to collect SpiderFoot events (JSONL):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/spiderfoot/events.jsonl</location>
  <only-future-events>yes</only-future-events>
  <label key="@source">spiderfoot</label>
  <label key="spiderfoot.profile">passive</label>
</localfile>
```

Then reload/restart the manager:

```bash
sudo /var/ossec/bin/wazuh-control restart  # or systemctl restart wazuh-manager
```

### 3.2 Log rotation (logrotate)

Create `/etc/logrotate.d/spiderfoot` to rotate `events.jsonl` safely:

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

`copytruncate` keeps Wazuh reading the file while rotated.

-----

## 4\. Wazuh rules (example)

Place this authoritative block in `/var/ossec/etc/rules/local_rules.xml` (avoid duplicates):

```xml
<group name="spiderfoot,local,">

  <rule id="100600" level="3">
    <location type="pcre2">/var/log/spiderfoot/events\.jsonl</location>
    <decoded_as>json</decoded_as>
    <field name="msg">.+</field>
    <description>SpiderFoot: evento coletado</description>
    <group>spiderfoot,</group>
  </rule>

  <rule id="100601" level="8">
    <if_sid>100600</if_sid>
    <match>password|credential|creds|apikey|token|leak|exposed|pwned</match>
    <description>SpiderFoot: possível vazamento/credenciais expostas</description>
    <group>spiderfoot,threatintel,</group>
  </rule>

</group>
```

After editing:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

**Avoid duplicating rule IDs** — keep one canonical rules file to prevent analysisd warnings.

-----

## 5\. Filebeat neutralization (when Filebeat interferes)

If Filebeat was previously configured to read `events.jsonl`, neutralize it (we prefer Wazuh localfile for ingestion). Example steps used in the lab:

**Neutral minimal Filebeat config (no SpiderFoot):**

```bash
# Backup existing Filebeat config with timestamp
sudo cp -a /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak.$(date +%Y%m%d_%H%M%S)

# Write minimal neutral Filebeat configuration (no SpiderFoot)
sudo tee /etc/filebeat/filebeat.yml > /dev/null <<'EOF'
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
EOF
```

```bash
# Prepare directories and backup Filebeat registry files
sudo install -d -m 0755 /var/log/filebeat-out

TS=$(date +%Y%m%d_%H%M%S)
sudo install -d -m 0750 /var/lib/filebeat/backup-registry-$TS

[ -e /var/lib/filebeat/registry ] && sudo mv /var/lib/filebeat/registry /var/lib/filebeat/backup-registry-$TS/ || true
[ -e /var/lib/filebeat/registry.old ] && sudo mv /var/lib/filebeat/registry.old /var/lib/filebeat/backup-registry-$TS/ || true

# Fix ownership of Filebeat directories
sudo chown -R root:root /var/lib/filebeat /var/log/filebeat-out || true

# Test Filebeat config and restart service
sudo filebeat test config -c /etc/filebeat/filebeat.yml || true
sudo systemctl daemon-reload
sudo systemctl restart filebeat
```

This recovers Filebeat while ensuring it does not consume SpiderFoot logs. These two blocks can be used as-is in a shell script or copy-pasted sequentially into the terminal for minimal neutral Filebeat setup without SpiderFoot integration.
The first block backs up the current configuration and writes the minimal config to track /var/log/dpkg.log with local rotating file output.The second block ensures logging output directories exist, backs up the registry files, corrects permissions, tests the config, reloads systemd and restarts Filebeat.

-----

## 6\. Tests & validation (end-to-end)

### 6.1 Inject baseline and sensitive events

Append two JSONL test events:

```bash
sudo bash -c 'printf "{\"@timestamp\":\"%s\",\"@source\":\"spiderfoot\",\"msg\":\"integration-doublecheck-ok\"}\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> /var/log/spiderfoot/events.jsonl'
sudo bash -c 'printf "{\"@timestamp\":\"%s\",\"@source\":\"spiderfoot\",\"msg\":\"password token leaked for example.com\"}\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> /var/log/spiderfoot/events.jsonl'
```

Wait a few seconds for Wazuh to ingest.

### 6.2 Confirm in archives (raw events)

```bash
sudo egrep -n '"integration-doublecheck-ok"|"password token leaked"' /var/ossec/logs/archives/archives.json | tail -n 5
```

### 6.3 Confirm alerts (rules 100600 / 100601)

```bash
sudo jq -c 'select((.rule.id|tostring)=="100600" or (.rule.id|tostring)=="100601") | {ts:.timestamp, rule:.rule.id, desc:.rule.description, msg:(.data.msg // .full_log // "")}' /var/ossec/logs/alerts/alerts.json | tail -n 10
```

Expected: an alert with rule `100600` for the baseline event and `100601` for the sensitive/credential event.

-----

## 7\. Scripts (S1–S6) — reproducible artifacts

Below are the scripts used in the lab. Save each as indicated (executable) or copy them into a `scripts/spiderfoot/` directory in the repo.

### S1 — Filebeat reset & neutralize

```bash
#!/bin/bash
# S1: Reset & neutralize Filebeat (keep SpiderFoot out of Filebeat)
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
sudo systemctl daemon-reload
sudo systemctl restart filebeat
sleep 1
systemctl --no-pager --full status filebeat || true
```

### S2 — Ensure SpiderFoot rules in Wazuh (idempotent insert)

```bash
#!/bin/bash
# S2: Ensure SpiderFoot rule block in local_rules.xml (avoid duplicates)
set -euo pipefail
RULE_BLOCK=$(cat <<'XML'
<group name="spiderfoot,local,">
  <rule id="100600" level="3">
    <location type="pcre2">/var/log/spiderfoot/events\.jsonl</location>
    <decoded_as>json</decoded_as>
    <field name="msg">.+</field>
    <description>SpiderFoot: evento coletado</description>
    <group>spiderfoot,</group>
  </rule>
  <rule id="100601" level="8">
    <if_sid>100600</if_sid>
    <match>password|credential|creds|apikey|token|leak|exposed|pwned</match>
    <description>SpiderFoot: possível vazamento/credenciais expostas</description>
    <group>spiderfoot,threatintel,</group>
  </rule>
</group>
XML
)

LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
if ! grep -q "spiderfoot,local" "$LOCAL_RULES"; then
  sudo sed -i '/<\/rules>/i\'"$RULE_BLOCK" "$LOCAL_RULES" || true
  sudo /var/ossec/bin/wazuh-analysisd -t
  sudo systemctl restart wazuh-manager
else
  echo "[i] SpiderFoot rules already present in $LOCAL_RULES"
fi
```

### S3 — Silence noisy AWS/Auditd packs (example)

```bash
#!/bin/bash
# S3: Add rule_exclude lines for problematic packs in ossec.conf
set -euo pipefail
CONF="/var/ossec/etc/ossec.conf"
sudo sed -i '/<ruleset>/,/<\/ruleset>/ {
  /<rule_exclude>0350-amazon_rules.xml<\/rule_exclude>/! s|</ruleset>|<rule_exclude>0350-amazon_rules.xml</rule_exclude>\n</ruleset>|
}' "$CONF" || true
sudo sed -i '/<ruleset>/,/<\/ruleset>/ {
  /<rule_exclude>0365-auditd_rules.xml<\/rule_exclude>/! s|</ruleset>|<rule_exclude>0365-auditd_rules.xml</rule_exclude>\n</ruleset>|
}' "$CONF" || true
sudo systemctl restart wazuh-manager || true
sleep 2
sudo tail -n 80 /var/ossec/logs/ossec.log | egrep -i 'WARNING|error|rules|analysisd' || true
```

### S4 — Logrotate policy writer for SpiderFoot

```bash
#!/bin/bash
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
```

### S5 — SpiderFoot credentials migration & restart (handle `!` in password)

```bash
#!/bin/bash
# S5: Create credentials file for SpiderFoot under user home and restart
set +H 2>/dev/null || set +o histexpand  # disable history expansion (for "!" in passwords)
set -euo pipefail

SF_USER="spiderfoot"
SF_HOME="/home/$SF_USER"
SF_PASS_FILE="$SF_HOME/.spiderfoot/passwd"
SF_CRED="sfadmin:REPLACE_WITH_STRONG_PASSWORD"   # <-- change here, do not commit

sudo -u "$SF_USER" mkdir -p "$SF_HOME/.spiderfoot"
sudo -u "$SF_USER" bash -c "printf '%s\n' \"$SF_CRED\" > '$SF_PASS_FILE'"
sudo chown -R "$SF_USER":wazuh "$SF_HOME/.spiderfoot"
sudo chmod 750 "$SF_HOME/.spiderfoot"
sudo chmod 640 "$SF_PASS_FILE"
sudo rm -f /opt/spiderfoot/passwd || true
sudo systemctl daemon-reload || true
sudo systemctl restart spiderfoot || true
sudo systemctl --no-pager --full status spiderfoot | sed -n '1,20p' || true
# validate digest
curl --digest -u 'sfadmin:REPLACE_WITH_STRONG_PASSWORD' -s -o /dev/null -w '%{http_code}\n' [http://127.0.0.1:5002/](http://127.0.0.1:5002/) || true
```

### S6 — Ingestion sanity & rule verification

```bash
#!/bin/bash
# S6: Inject test events and verify archives/alerts
set -euo pipefail
printf '{"@timestamp":"%s","@source":"spiderfoot","msg":"integration-doublecheck-ok"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee -a /var/log/spiderfoot/events.jsonl >/dev/null
printf '{"@timestamp":"%s","@source":"spiderfoot","msg":"password token leaked for example.com"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee -a /var/log/spiderfoot/events.jsonl >/dev/null
sleep 5
sudo egrep -n '"integration-doublecheck-ok"|"password token leaked"' /var/ossec/logs/archives/archives.json | tail -n 5 || true
sudo jq -c 'select((.rule.id|tostring)=="100600" or (.rule.id|tostring)=="100601") | {ts:.timestamp, rule:.rule.id, desc:.rule.description, msg:(.data.msg // .full_log // "")}' /var/ossec/logs/alerts/alerts.json | tail -n 10 || true
```

-----

## 8\. Troubleshooting (common issues)

  * **Filebeat crashes / no inputs** — rotate registry and apply neutral config (S1). Validate with `filebeat test config`.
  * **Duplicate rule IDs** — ensure only one authoritative SpiderFoot rule block exists (S2). Remove/disable any extra spiderfoot rule files.
  * **401 or crash loop** — SpiderFoot no longer supports `appdir/passwd`; move to `~/.spiderfoot/passwd` for the service user and restart (S5). Remember `set +H` when writing password with `!`.
  * **“is not a JSON object”** in Wazuh logs — ensure `events.jsonl` contains one well-formed JSON object per line and `ossec.conf` `<log_format>json</log_format>` is set for that file.
  * **No events in alerts** — check `sudo tail /var/ossec/logs/ossec.log` and `sudo /var/ossec/bin/wazuh-analysisd -t` for rule syntax errors.

-----

## 9\. Hardening & production notes

  * Keep SpiderFoot bound to `127.0.0.1` and place behind a TLS-terminating reverse proxy if remote access is required. Restrict access with IP allow-lists or VPN.
  * Do **not** commit credentials; use vaults or environment-based secrets. Use `~/.spiderfoot/passwd` with strict perms.
  * Tailor rule `100601` to specific SpiderFoot module fields to reduce false positives (match structured keys rather than free text if possible).
  * Centralize alerts to SOAR/IR (e.g., Shuffle, DFIR-IRIS) and add Mitre/priority fields to rule outputs for triage.

-----

## 10\. References

  * SpiderFoot — [https://www.spiderfoot.net/](https://www.spiderfoot.net/)
  * Wazuh docs — log collection, rules syntax, archives/alerts paths
  * Elastic/Filebeat docs — registry, test config, neutral output.file
  * System `logrotate(8)` manpage

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab — Threat Intelligence Stack*
