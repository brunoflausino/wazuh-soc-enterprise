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


