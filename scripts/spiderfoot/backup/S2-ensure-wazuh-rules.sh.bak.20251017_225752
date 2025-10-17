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
