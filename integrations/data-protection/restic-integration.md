# Restic Backup Integration with Wazuh (Agentless)

This document provides a complete, reproducible methodology for installing Restic, configuring automated backups via Systemd, and monitoring the backup job logs directly from the Wazuh manager using the `localfile` capability (agentless monitoring).

This integration is designed for a setup where Restic and the Wazuh Manager are running on the same host (e.g., the SIEM server backing itself up).

## 1. Prerequisites

* [cite_start]**OS:** Ubuntu 24.04 LTS [cite: 1158]
* [cite_start]**Wazuh:** A Wazuh Manager (v4.x or later) must be installed and running on the host. [cite: 1161]
* **Access:** Sudo/root privileges are required.

---

## 2. Part 1: Restic Installation

### 2.1 Install Dependencies

Update the system and install necessary tools for downloading and verifying Restic.
```bash
sudo apt-get update -y
sudo apt-get install -y curl wget jq bzip2 coreutils ca-certificates
````

[cite\_start][cite: 1169, 1170]

### 2.2 Download and Install Restic

This method downloads the latest stable release, verifies its checksum, and installs the binary.

```bash
# Get the latest stable version tag (e.g., 0.18.0)
LATEST_TAG=$(curl -fsSL [https://api.github.com/repos/restic/restic/releases/latest](https://api.github.com/repos/restic/restic/releases/latest) \
  | jq -r '.tag_name' | sed 's/^v//')

# Set download variables
BASE="[https://github.com/restic/restic/releases/download/v$](https://github.com/restic/restic/releases/download/v$){LATEST_TAG}"
BIN="restic_${LATEST_TAG}_linux_amd64.bz2"
SUMS="SHA256SUMS"
TMPD=$(mktemp -d)

cd "$TMPD"

# Download the binary and checksums
wget -q "${BASE}/${BIN}" "${BASE}/${SUMS}"

# Verify the checksum
grep "${BIN}$" "${SUMS}" | sha256sum -c

# Decompress the binary
bzip2 -d "${BIN}"

# Install the binary
sudo install -m 0755 -o root -g root "restic_${LATEST_TAG}_linux_amd64" /usr/local/bin/restic

# Verify installation
echo "Installed: $(restic version)"
```

[cite\_start][cite: 1172-1185]

-----

## 3\. Part 2: Restic Repository Configuration

### 3.1 Create Directory Structure

Create the necessary directories for the repository, configuration, logs, and cache.

```bash
sudo mkdir -p /backup/restic /etc/restic /var/log/restic /var/cache/restic
```

[cite\_start][cite: 1191]

### 3.2 Set Permissions

Secure the directories appropriately.

```bash
sudo chown root:root /backup/restic /etc/restic /var/log/restic /var/cache/restic
sudo chmod 755 /backup/restic /var/log/restic
sudo chmod 750 /etc/restic
sudo chmod 700 /var/cache/restic
```

[cite\_start][cite: 1192-1195]

### 3.3 Create Repository Password

Create a file to store the repository encryption password.

```bash
sudo tee /etc/restic/password >/dev/null <<'EOF'
change-this-secure-password-123
EOF

sudo chmod 600 /etc/restic/password
```

[cite\_start][cite: 1197-1200]

### 3.4 Create Environment File

Create a file to store Restic's environment variables for automation.

```bash
sudo tee /etc/restic/env >/dev/null <<'EOF'
RESTIC_REPOSITORY=/backup/restic
RESTIC_PASSWORD_FILE=/etc/restic/password
RESTIC_CACHE_DIR=/var/cache/restic
RESTIC_COMPRESSION=auto
EOF

sudo chmod 644 /etc/restic/env
```

[cite\_start][cite: 1202-1208]

### 3.5 Initialize Restic Repository

Source the environment file and initialize the repository *if* it doesn't already exist.

```bash
set -a; source /etc/restic/env; set +a
if ! restic cat config >/dev/null 2>&1; then
  restic init
fi
```

[cite\_start][cite: 1210-1213]

-----

## 4\. Part 3: Systemd Backup Automation

### 4.1 Create the Backup Script

This script sources the environment variables and runs the backup, logging all output to `/var/log/restic/backup.log`.

```bash
sudo tee /usr/local/bin/restic-backup.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/var/log/restic"
LOG_FILE="${LOG_DIR}/backup.log"
ENV_FILE="/etc/restic/env"

# Ensure log directory and file exist
mkdir -p "$LOG_DIR"; touch "$LOG_FILE"
chmod 640 "$LOG_FILE"; chown root:root "$LOG_FILE"

# Source environment variables
set -a; source "$ENV_FILE"; set +a

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Pipe all output to the log file
{
  echo "[$TS] START backup"
  restic version
  
  # Run the backup (e.g., for /etc/ and /home/)
  restic backup \
    --one-file-system \
    --exclude-caches \
    --exclude-if-present .nobackup \
    /etc/ /home/

  echo "[$TS] SNAPSHOT created"

  # Prune old snapshots (keep 7 daily, 4 weekly, 6 monthly)
  restic forget \
    --prune \
    --keep-daily 7 \
    --keep-weekly 4 \
    --keep-monthly 6

  echo "[$TS] Pruning complete"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] FINISH backup OK"
  
} >> "$LOG_FILE" 2>&1
EOF

# Make the script executable
sudo chmod +x /usr/local/bin/restic-backup.sh
```

[cite\_start][cite: 1216-1234]

### 4.2 Create Systemd Service File

Create a service file to execute the backup script.

```bash
sudo tee /etc/systemd/system/restic-backup.service >/dev/null <<'EOF'
[Unit]
Description=Restic backup job
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Nice=10
ExecStart=/usr/local/bin/restic-backup.sh
User=root
Group=root
EOF
```

[cite\_start][cite: 1237-1244]

### 4.3 Create Systemd Timer File

Create a timer to run the service daily at 02:30 AM, with a randomized delay.

```bash
sudo tee /etc/systemd/system/restic-backup.timer >/dev/null <<'EOF'
[Unit]
Description=Run restic backup daily at 02:30

[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
EOF
```

[cite\_start][cite: 1246-1252]

### 4.4 Enable the Timer

Reload the systemd daemon and enable the timer.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now restic-backup.timer
```

[cite\_start][cite: 1253, 1254]

-----

## 5\. Part 4: Wazuh Manager Integration (Agentless)

This procedure configures the Wazuh Manager (on the *same* host) to monitor the Restic log file.

### 5.1 Configure `ossec.conf`

1.  Edit the Wazuh Manager's configuration file:

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

2.  Add the following `<localfile>` block inside the `<ossec_config>` section. This tells the manager's *own* logcollector to monitor the `backup.log` file.

    ```xml
    <localfile>
      <location>/var/log/restic/backup.log</location>
      <log_format>syslog</log_format>
    </localfile>
    ```

    [cite\_start][cite: 1287, 1218]

3.  *(Optional - From Report)* The methodology also included a step to fix badly formatted `<label>` tags (e.g., from Zeek logs) that may have been in the configuration.

    ```bash
    sudo sed -i 's#<label>\([^ ]\+\)</label>#<label key="program_name">\1</label>#g' /var/ossec/etc/ossec.conf
    ```

    [cite\_start][cite: 1290]

### 5.2 Restart Wazuh Manager

Apply the configuration changes by restarting the manager.

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status --no-pager wazuh-manager
```

[cite\_start][cite: 1294, 1295]

-----

## 6\. Part 5: Validation

### 6.1 Trigger a Manual Backup

Start the backup service manually to generate logs.

```bash
sudo systemctl start restic-backup.service
```

[cite\_start][cite: 1298]

### 6.2 Check Restic Log

First, confirm the log file was written correctly.

```bash
sudo tail -f /var/log/restic/backup.log
```

(Look for the "FINISH backup OK" message)

### 6.3 Check Wazuh Archives

Finally, verify that the Wazuh Manager ingested the log.

```bash
# Search the JSON archives for the success message
sudo grep "FINISH backup OK" /var/ossec/logs/archives/archives.json
```

[cite\_start][cite: 1299]

You should see a JSON object confirming the ingestion, similar to:

```json
{
  "timestamp": "2025-09-11T22:50:39.608+0200",
  "agent": {
    "id": "000",
    "name": "flausino"
  },
  "full_log": "[2025-09-11T20:50:37Z] FINISH backup OK",
  ...
}
```

[cite\_start][cite: 1301-1306]

This confirms the log was successfully collected by the Wazuh manager. You can now build custom rules based on the log content (e.g., alert on "START backup" and "FINISH backup OK").
