#!/usr/bin/env bash
# S3: Add rule_exclude lines for example noisy packs in ossec.conf
set -euo pipefail
CONF="/var/ossec/etc/ossec.conf"
sudo grep -q "0350-amazon_rules.xml" "$CONF" || sudo sed -i '/<\/ruleset>/i <rule_exclude>0350-amazon_rules.xml</rule_exclude>' "$CONF" || true
sudo grep -q "0365-auditd_rules.xml" "$CONF" || sudo sed -i '/<\/ruleset>/i <rule_exclude>0365-auditd_rules.xml</rule_exclude>' "$CONF" || true
sudo systemctl restart wazuh-manager || true
sleep 1
sudo tail -n 80 /var/ossec/logs/ossec.log | egrep -i 'WARNING|error|rules|analysisd' || true
