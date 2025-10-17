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
