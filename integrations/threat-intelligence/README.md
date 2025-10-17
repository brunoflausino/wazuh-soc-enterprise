# Threat Intelligence & Hunting Integrations

## Tools Integrated

### MITRE CALDERA
- **Status**: ✅ Integrated
- **Documentation**: [caldera-integration.md](caldera-integration.md)
- **Port**: 8888/tcp
- **Purpose**: Adversary emulation and red team automation

### SpiderFoot OSINT
- **Status**: ✅ Integrated
- **Documentation**: [spiderfoot-integration.md](spiderfoot-integration.md)
- **Port**: 5001/tcp
- **Purpose**: Open Source Intelligence gathering

### Conpot ICS/SCADA Honeypot
- **Status**: ✅ Integrated
- **Documentation**: [conpot-integration.md](conpot-integration.md)
- **Ports**: 80, 102, 502, 161 (multiple protocols)
- **Purpose**: Industrial Control System honeypot

---

## Embedded operational scripts for SpiderFoot

> The following scripts are embedded here for convenience. If you want to run them on the host, extract them using the extraction command shown below (it will create the files with the paths indicated and `chmod +x`).

<!-- BEGIN_SCRIPT: scripts/spiderfoot/S1-neutralize-filebeat.sh -->
```bash
#!/usr/bin/env bash
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
sudo systemctl restart filebeat || true
sleep 1
systemctl --no-pager --full status filebeat || true
````

<!-- END_SCRIPT -->

<!-- BEGIN_SCRIPT: scripts/spiderfoot/S2-ensure-wazuh-rules.sh -->

```bash
#!/usr/bin/env bash
# S2: Ensure SpiderFoot rule block in local_rules.xml (avoid duplicates)
set -euo pipefail
RULE_BLOCK=$(cat <<'XML'
<group name="spiderfoot,local,">
  <rule id="100600" level="3">
    <location type="pcre2">/var/log/spiderfoot/events\.jsonl</location>
    <decoded_as>json</decoded_as>
    <field name="msg">.+</field>
    <description>SpiderFoot: event collected</description>
    <group>spiderfoot,</group>
  </rule>
  <rule id="100601" level="8">
    <if_sid>100600</if_sid>
    <match>password|credential|creds|apikey|token|leak|exposed|pwned</match>
    <description>SpiderFoot: possible leak/credentials exposed</description>
    <group>spiderfoot,threatintel,</group>
  </rule>
</group>
XML
)

LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
if ! sudo grep -q "spiderfoot,local" "$LOCAL_RULES"; then
  if sudo grep -q "</rules>" "$LOCAL_RULES"; then
    sudo sed -i '/<\/rules>/i\'"$RULE_BLOCK" "$LOCAL_RULES" || true
  else
    echo "$RULE_BLOCK" | sudo tee -a "$LOCAL_RULES" >/dev/null
  fi
  sudo /var/ossec/bin/wazuh-analysisd -t || true
  sudo systemctl restart wazuh-manager || true
else
  echo "[i] SpiderFoot rules already present in $LOCAL_RULES"
fi
```

<!-- END_SCRIPT -->

<!-- BEGIN_SCRIPT: scripts/spiderfoot/S3-silence-noisy-packs.sh -->

```bash
#!/usr/bin/env bash
# S3: Add rule_exclude lines for example noisy packs in ossec.conf
set -euo pipefail
CONF="/var/ossec/etc/ossec.conf"
sudo grep -q "0350-amazon_rules.xml" "$CONF" || sudo sed -i '/<\/ruleset>/i <rule_exclude>0350-amazon_rules.xml</rule_exclude>' "$CONF" || true
sudo grep -q "0365-auditd_rules.xml" "$CONF" || sudo sed -i '/<\/ruleset>/i <rule_exclude>0365-auditd_rules.xml</rule_exclude>' "$CONF" || true
sudo systemctl restart wazuh-manager || true
sleep 1
sudo tail -n 80 /var/ossec/logs/ossec.log | egrep -i 'WARNING|error|rules|analysisd' || true
```

<!-- END_SCRIPT -->

<!-- BEGIN_SCRIPT: scripts/spiderfoot/S4-logrotate-spiderfoot.sh -->

```bash
#!/usr/bin/env bash
# S4: Write /etc/logrotate.d/spiderfoot policy
set -euo pipefail
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
echo "[i] /etc/logrotate.d/spiderfoot written"
```

<!-- END_SCRIPT -->

<!-- BEGIN_SCRIPT: scripts/spiderfoot/S5-spiderfoot-creds.sh -->

```bash
#!/usr/bin/env bash
# S5: Create credentials file for SpiderFoot under user home and restart
set +H 2>/dev/null || set +o histexpand  # disable history expansion (for "!" in passwords)
set -euo pipefail

SF_USER="spiderfoot"
SF_HOME="/home/$SF_USER"
SF_PASS_FILE="$SF_HOME/.spiderfoot/passwd"
# NOTE: replace the placeholder 'REPLACE_WITH_STRONG_PASSWORD' locally AFTER copying.
SF_CRED="sfadmin:REPLACE_WITH_STRONG_PASSWORD"

sudo -u "$SF_USER" mkdir -p "$SF_HOME/.spiderfoot"
sudo -u "$SF_USER" bash -c "printf '%s\n' \"$SF_CRED\" > '$SF_PASS_FILE'"
sudo chown -R "$SF_USER":wazuh "$SF_HOME/.spiderfoot" || true
sudo chmod 750 "$SF_HOME/.spiderfoot" || true
sudo chmod 640 "$SF_PASS_FILE" || true
sudo systemctl daemon-reload || true
sudo systemctl restart spiderfoot || true
echo "[i] Credentials file created at $SF_PASS_FILE (remember to replace placeholder password)"
curl --digest -u "sfadmin:REPLACE_WITH_STRONG_PASSWORD" -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5002/ || true
```

<!-- END_SCRIPT -->

<!-- BEGIN_SCRIPT: scripts/spiderfoot/S6-ingest-and-verify.sh -->

```bash
#!/usr/bin/env bash
# S6: Inject test events and verify archives/alerts
set -euo pipefail

printf '{"@timestamp":"%s","@source":"spiderfoot","msg":"integration-doublecheck-ok"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee -a /var/log/spiderfoot/events.jsonl >/dev/null
printf '{"@timestamp":"%s","@source":"spiderfoot","msg":"password token leaked for example.com"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee -a /var/log/spiderfoot/events.jsonl >/dev/null
sleep 5
echo "[i] Searching archives for injected tokens:"
sudo egrep -n '"integration-doublecheck-ok"|"password token leaked"' /var/ossec/logs/archives/archives.json | tail -n 5 || true
echo "[i] Checking alerts for rule IDs 100600/100601:"
sudo jq -c 'select((.rule.id|tostring)=="100600" or (.rule.id|tostring)=="100601") | {ts:.timestamp, rule:.rule.id, desc:.rule.description, msg:(.data.msg // .full_log // "")}' /var/ossec/logs/alerts/alerts.json | tail -n 10 || true
```

<!-- END_SCRIPT -->

---

## How to extract embedded scripts into files (and make them executable)

Run this exact command **once** from the repository root (it reads the current `integrations/threat-intelligence/README.md` and writes the files to the paths embedded above):

````bash
awk '
  match($0,/^<!-- BEGIN_SCRIPT: ([^ ]+) -->/,a){fname=a[1]; in=1; started=0; next}
  in && $0 ~ /^```/ && started==0 {started=1; next}
  in && $0 ~ /^```/ && started==1 {in=0; started=0; close(fname); next}
  in && started==1 { print > fname }
' integrations/threat-intelligence/README.md
# make executable (if scripts were created)
chmod +x scripts/spiderfoot/*.sh || true
ls -l scripts/spiderfoot/
````

> Nota: se colou o README para outra localização (ex.: `scripts/spiderfoot/README.md`), ajuste o caminho `integrations/threat-intelligence/README.md` acima para o ficheiro correto.

---

## Recomendações

* **Se for usar os scripts operacionalmente**, prefira extrair e manter como ficheiros separados (`scripts/spiderfoot/…`) e comitar esses ficheiros no repositório (para histórico).
* Se preferir manter tudo embutido no README, a extração acima funciona sempre que precisar executar os scripts.

---

````

---

## 2) O comando de extração (resumido)
Depois de colar e salvar o README, cole e execute **apenas** este bloco no terminal (estando na raiz do repo):

```bash
awk '
  match($0,/^<!-- BEGIN_SCRIPT: ([^ ]+) -->/,a){fname=a[1]; in=1; started=0; next}
  in && $0 ~ /^```/ && started==0 {started=1; next}
  in && $0 ~ /^```/ && started==1 {in=0; started=0; close(fname); next}
  in && started==1 { print > fname }
' integrations/threat-intelligence/README.md
chmod +x scripts/spiderfoot/*.sh || true
ls -l scripts/spiderfoot/
