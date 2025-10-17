#!/usr/bin/env bash
# S5: Create credentials file for SpiderFoot under service user home and restart service
# Usage:
#  - interactively: sudo ./S5-spiderfoot-creds.sh
#  - non-interactive: export SF_PASSWORD='MySecret!' && sudo SF_PASSWORD=... ./S5-spiderfoot-creds.sh
#
# Security note: do NOT commit the resulting file to git. Prefer using .gitignore or git skip-worktree.
set -euo pipefail

# Configuration
SF_USER="spiderfoot"
SF_HOME="/home/${SF_USER}"
SF_PASS_DIR="${SF_HOME}/.spiderfoot"
SF_PASS_FILE="${SF_PASS_DIR}/passwd"
SF_USER_GROUP="wazuh"   # group to own the file (adjust if different)

# Obtain password securely: prefer environment variable, else prompt (no echo)
if [[ -n "${SF_PASSWORD:-}" ]]; then
  # Use SF_PASSWORD from environment (preferred for automation)
  SF_PLAIN="${SF_PASSWORD}"
else
  # Prompt securely
  printf 'Enter password for SpiderFoot user "sfadmin": '
  # -s silent, -r raw
  IFS= read -r -s SF_PLAIN || true
  printf '\n'
  if [[ -z "$SF_PLAIN" ]]; then
    echo "[ERROR] No password entered. Aborting." >&2
    exit 3
  fi
fi

# Build credential line (username:password)
SF_CRED="sfadmin:${SF_PLAIN}"

# Create directory as the service user (if it exists) and write file atomically
echo "[*] Creating directory ${SF_PASS_DIR} (as ${SF_USER})..."
sudo -u "$SF_USER" mkdir -p "$SF_PASS_DIR"
# Ensure ownership and perms for the directory (best-effort)
sudo chown -R "$SF_USER":"$SF_USER_GROUP" "$SF_PASS_DIR" 2>/dev/null || true
sudo chmod 750 "$SF_PASS_DIR" 2>/dev/null || true

# Write credential line to the target file using a pipe to sudo tee (avoids exposing as argv)
printf '%s\n' "$SF_CRED" | sudo tee "$SF_PASS_FILE" >/dev/null

# Correct ownership and permissions
sudo chown "$SF_USER":"$SF_USER_GROUP" "$SF_PASS_FILE" 2>/dev/null || true
sudo chmod 640 "$SF_PASS_FILE" 2>/dev/null || true

# Reload systemd and restart spiderfoot service if present (best-effort)
echo "[*] Attempting to reload systemd and restart spiderfoot service (if present)..."
sudo systemctl daemon-reload 2>/dev/null || true
# Try common service names; ignore failures
sudo systemctl restart spiderfoot.service 2>/dev/null || sudo systemctl restart spiderfoot 2>/dev/null || true

echo
echo "[OK] Credentials file created at: ${SF_PASS_FILE}"
echo "      Owner: ${SF_USER}:${SF_USER_GROUP}   Permissions: $(stat -c '%a' "$SF_PASS_FILE" 2>/dev/null || echo 'n/a')"
echo
cat <<'ADVICE'
Important next steps & safety advice:
- Do NOT add the credentials file to git. Add the template path to .gitignore:
    echo "scripts/spiderfoot/S5-spiderfoot-creds.sh" >> .gitignore
  or better, ignore the actual /home/.../passwd path in your repo workflow.
- If you want a repository template for S5, keep only a placeholder in the repo (do NOT include real passwords).
- To verify SpiderFoot web access manually (run this locally, it will prompt for password if not using SF_PASSWORD):
    curl --digest -u "sfadmin:YOUR_PASSWORD" -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5002/
  (Replace YOUR_PASSWORD; note this command will include the password in the process arguments while running.)
- To avoid accidentally committing local changes to S5, consider marking it skip-worktree after committing a template:
    git update-index --skip-worktree scripts/spiderfoot/S5-spiderfoot-creds.sh
ADVICE

# For safety, clear sensitive vars in this shell (best-effort)
SF_PLAIN=""
SF_CRED=""
unset SF_PASSWORD || true
