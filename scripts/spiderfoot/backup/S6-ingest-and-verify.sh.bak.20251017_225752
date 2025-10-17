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
