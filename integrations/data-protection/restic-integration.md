# **Restic Backup Integration with Wazuh (Agentless)**

## **1. Overview**

This guide provides a complete, step-by-step methodology for installing **Restic**, configuring automated backups via **Systemd**, and monitoring the backup job logs directly from the **Wazuh Manager** using its `localfile` capability. This setup assumes Restic and the Wazuh Manager are running on the same host (agentless monitoring).

The primary objective is to create a reliable backup process and ensure its execution (success or failure) is logged and visible within the Wazuh SIEM for auditing and alerting purposes.

## **2. System Environment**

  * **Operating System:** Ubuntu 24.04 LTS
  * **Wazuh:** Wazuh Manager (v4.x) installed and running on the host.
  * **Privileges:** All commands require `sudo`.
  * **Internet Access:** Required for downloading Restic from GitHub.

-----

## **3. Part 1: Restic Installation**

This section covers downloading the official Restic binary, verifying its integrity, and installing it.

### **3.1 Install Dependencies**

Update the system and install necessary tools (`curl`, `wget`, `jq`, `bzip2`).

```bash
sudo apt-get update -y
sudo apt-get install -y curl wget jq bzip2 coreutils ca-certificates
```

### **3.2 Download and Install Restic**

These commands fetch the latest stable release directly from GitHub, verify the download using SHA256 checksums, and install the binary to `/usr/local/bin/restic`.

1.  **Determine Latest Version and Architecture:**

    ```bash
    # Get the latest stable version tag (e.g., 0.18.0)
    LATEST_TAG=$(curl -fsSL https://api.github.com/repos/restic/restic/releases/latest \
      | jq -r '.tag_name' | sed 's/^v//')

    # Detect architecture (amd64 or arm64)
    ARCH="amd64"
    case "$(uname -m)" in
      x86_64|amd64) ARCH="amd64" ;;
      aarch64|arm64) ARCH="arm64" ;;
      *) echo "ERROR: Unsupported architecture $(uname -m)"; exit 1 ;;
    esac

    echo "Latest Restic version: $LATEST_TAG"
    echo "Detected architecture: $ARCH"
    ```

2.  **Download Binary and Checksums:**

    ```bash
    # Set download variables
    BASE="https://github.com/restic/restic/releases/download/v${LATEST_TAG}"
    BIN="restic_${LATEST_TAG}_linux_${ARCH}.bz2"
    SUMS="SHA256SUMS"
    SUMS_SIG="SHA256SUMS.asc" # GPG signature (optional verification)
    TMPD=$(mktemp -d) # Create a temporary directory

    cd "$TMPD"

    # Download the binary and checksum files
    echo "Downloading Restic binary and checksums..."
    wget -q "${BASE}/${BIN}" "${BASE}/${SUMS}" "${BASE}/${SUMS_SIG}"
    ```

3.  **Verify Checksum:**

    ```bash
    echo "Verifying checksum..."
    # Check the downloaded binary against the official checksum list
    if grep " ${BIN}$" "${SUMS}" | sha256sum -c --strict --quiet -; then
      echo "Checksum verification successful."
    else
      echo "ERROR: Checksum verification failed!"
      cd ~
      rm -rf "$TMPD"
      exit 1
    fi
    ```

4.  **Decompress and Install:**

    ```bash
    echo "Decompressing and installing Restic..."
    # Decompress the binary
    bzip2 -d "${BIN}"

    # Install the binary to /usr/local/bin
    sudo install -m 0755 -o root -g root "restic_${LATEST_TAG}_linux_${ARCH}" /usr/local/bin/restic
    ```

5.  **Verify Installation and Cleanup:**

    ```bash
    # Verify Restic is executable and print version
    if command -v restic >/dev/null; then
      echo "Restic installed successfully: $(restic version)"
    else
      echo "ERROR: Restic installation failed."
      cd ~
      rm -rf "$TMPD"
      exit 1
    fi

    # Cleanup temporary directory
    cd ~
    rm -rf "$TMPD"
    ```

-----

## **4. Part 2: Restic Repository Configuration**

This section sets up the local directory structure, creates the repository password file, configures environment variables, and initializes the Restic repository.

### **4.1 Create Directory Structure and Set Permissions**

Create directories for the repository, configuration, logs, and cache, setting appropriate permissions.

```bash
# Create directories
sudo mkdir -p /backup/restic /etc/restic /var/log/restic /var/cache/restic

# Set ownership and permissions
sudo chown root:root /backup/restic /etc/restic /var/log/restic /var/cache/restic
sudo chmod 755 /backup/restic /var/log/restic  # World-readable repo/log dirs
sudo chmod 750 /etc/restic                     # Config readable only by root/group
sudo chmod 700 /var/cache/restic               # Cache accessible only by root
```

### **4.2 Create Repository Password File**

Store the repository encryption password in a secure file. **Replace `change-this-secure-password-123` with a strong, unique password.**

```bash
# Create the password file
sudo tee /etc/restic/password >/dev/null <<'EOF'
change-this-secure-password-123
EOF

# Set strict permissions (readable only by root)
sudo chmod 600 /etc/restic/password
```

### **4.3 Create Environment File**

Create a file (`/etc/restic/env`) to store environment variables used by Restic for automated runs.

```bash
sudo tee /etc/restic/env >/dev/null <<'EOF'
# Restic environment variables for backup script
RESTIC_REPOSITORY=/backup/restic
RESTIC_PASSWORD_FILE=/etc/restic/password
RESTIC_CACHE_DIR=/var/cache/restic
RESTIC_COMPRESSION=auto
EOF

# Set permissions (readable by root)
sudo chmod 644 /etc/restic/env
```

### **4.4 Initialize Restic Repository**

Source the environment file and run `restic init` *only if* the repository hasn't been initialized yet.

```bash
# Load environment variables into the current shell temporarily
set -a; source /etc/restic/env; set +a

# Check if repository exists by trying to read its config
if ! restic cat config >/dev/null 2>&1; then
  echo "Initializing Restic repository at $RESTIC_REPOSITORY..."
  restic init
  echo "Repository initialized successfully."
else
  echo "Restic repository already initialized."
fi
```

-----

## **5. Part 3: Systemd Backup Automation**

This section creates a script to perform the backup and configures Systemd Service and Timer units to run it automatically.

### **5.1 Create the Backup Script**

This script sources the Restic environment variables, runs the backup command (backing up `/etc` and `/home` in this example), applies a retention policy (`forget --prune`), and logs all output to `/var/log/restic/backup.log`.

```bash
sudo tee /usr/local/bin/restic-backup.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
# Script to perform Restic backup and log output

# Fail on error, undefined variable, or pipe failure
set -euo pipefail

# Configuration
LOG_DIR="/var/log/restic"
LOG_FILE="${LOG_DIR}/backup.log"
ENV_FILE="/etc/restic/env"

# --- Script Execution ---

# Ensure log directory and file exist with correct permissions
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"
chown root:root "$LOG_FILE" # Ensure root owns the log

# Source Restic environment variables
# 'set -a' exports them, 'set +a' stops exporting
set -a; source "$ENV_FILE"; set +a

# Timestamp for logging
TS=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

# Group commands to redirect all stdout/stderr to the log file
{
  echo "[$TS] START backup job"
  echo "Restic version: $(restic version)"
  
  # --- Restic Backup Command ---
  # Backup specified paths
  # --one-file-system: Stay within the initial filesystem (e.g., don't cross mount points)
  # --exclude-caches: Exclude common cache directories
  # --exclude-if-present .nobackup: Skip directories containing a .nobackup file
  echo "Starting backup for /etc /home ..." # Add/remove paths as needed
  restic backup \
    --one-file-system \
    --exclude-caches \
    --exclude-if-present .nobackup \
    /etc \
    /home
  
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] Backup command finished. SNAPSHOT created."

  # --- Restic Pruning Command ---
  # Apply retention policy and remove old data
  # --keep-daily 7: Keep the last 7 daily snapshots
  # --keep-weekly 4: Keep the last 4 weekly snapshots (one per week)
  # --keep-monthly 6: Keep the last 6 monthly snapshots (one per month)
  # --prune: Remove data no longer referenced by kept snapshots
  echo "Starting pruning process..."
  restic forget \
    --prune \
    --keep-daily 7 \
    --keep-weekly 4 \
    --keep-monthly 6
  
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] Pruning process finished."
  
  # Final success message
  echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] FINISH backup job OK"

} >> "$LOG_FILE" 2>&1 # Redirect stdout and stderr to the log file

EOF

# Make the script executable
sudo chmod +x /usr/local/bin/restic-backup.sh
echo "Backup script created at /usr/local/bin/restic-backup.sh"
```

### **5.2 Create Systemd Service File**

This defines a `oneshot` service unit that runs the backup script.

```bash
sudo tee /etc/systemd/system/restic-backup.service >/dev/null <<'EOF'
[Unit]
Description=Restic Backup Job Service
# Ensure network is available if backing up to remote target (adjust if local only)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# Run with lower priority
Nice=10
# Execute the backup script
ExecStart=/usr/local/bin/restic-backup.sh
# Run as root
User=root
Group=root

[Install]
# This service is typically started by the timer, not enabled directly
# WantedBy=multi-user.target
EOF

echo "Systemd service file created at /etc/systemd/system/restic-backup.service"
```

### **5.3 Create Systemd Timer File**

This defines a timer unit to trigger the `restic-backup.service` daily at 02:30 AM, with a random delay up to 10 minutes (600 seconds) to avoid thundering herd issues.

```bash
sudo tee /etc/systemd/system/restic-backup.timer >/dev/null <<'EOF'
[Unit]
Description=Run Restic Backup Daily at 02:30 AM

[Timer]
# Run daily at 2:30 AM server time
OnCalendar=*-*-* 02:30:00
# Add random delay up to 10 minutes
RandomizedDelaySec=600
# If the machine was off, run at next boot if missed
Persistent=true

[Install]
# Enable the timer to start on boot
WantedBy=timers.target
EOF

echo "Systemd timer file created at /etc/systemd/system/restic-backup.timer"
```

### **5.4 Enable and Start the Timer**

Reload the systemd configuration and enable the timer to start automatically on boot and begin its schedule.

```bash
# Reload systemd manager configuration
sudo systemctl daemon-reload

# Enable the timer to start on boot and start it now
sudo systemctl enable --now restic-backup.timer

# Verify the timer is loaded and waiting
sudo systemctl list-timers restic-backup.timer
```

-----

## **6. Part 4: Wazuh Manager Integration (Agentless)**

This section configures the Wazuh Manager (running on the same host) to directly monitor the Restic log file created by the backup script.

### **6.1 Configure `ossec.conf`**

1.  **Backup Existing Configuration:**

    ```bash
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak_restic_$(date +%Y%m%d_%H%M%S)
    echo "Backed up current ossec.conf"
    ```

2.  **Edit `ossec.conf`:**

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

3.  **Add `<localfile>` Block:**
    Inside the `<ossec_config>` section, add the following block. This tells the manager's *own* log collector (which runs even without an agent installed) to monitor the `backup.log` file using the `syslog` format (suitable for Restic's log lines).

    ```xml
      <localfile>
        <location>/var/log/restic/backup.log</location>
        <log_format>syslog</log_format>
      </localfile>
    ```

4.  **(Recommended for Validation)** **Enable Log Archiving:**
    Ensure the `<global>` section includes `<logall_json>yes</logall_json>`. This archives *all* received logs (even if they don't trigger rules) to `/var/ossec/logs/archives/archives.json` (or dated subdirectories), which is essential for verifying ingestion during setup.

    ```xml
      <global>
        <logall_json>yes</logall_json>
        ...
      </global>
    ```

    *Note: Keeping `logall_json` enabled permanently can consume significant disk space.*

### **6.2 Restart Wazuh Manager**

Apply the configuration changes by restarting the Wazuh Manager service.

```bash
echo "Restarting Wazuh Manager to apply changes..."
sudo systemctl restart wazuh-manager

# Verify manager status after restart
sudo systemctl status --no-pager wazuh-manager
```

-----

## **7. Part 5: Validation**

Verify that the integration works by triggering a backup and checking if the logs appear in Wazuh.

### **7.1 Trigger a Manual Backup**

Run the backup service manually to generate fresh log entries.

```bash
echo "Starting a manual Restic backup to generate logs..."
sudo systemctl start restic-backup.service
```

*Wait a few minutes for the backup (and prune) to complete. You can monitor its progress by tailing the Restic log:*

```bash
echo "Monitoring Restic log file for completion..."
sudo tail -f /var/log/restic/backup.log
```

*(Press `Ctrl+C` once you see the "FINISH backup job OK" message)*

### **7.2 Check Wazuh Archives**

Check the Wazuh archive log file (`archives.json` or dated files) on the Manager to confirm the log entries were ingested.

```bash
echo "Checking Wazuh archives for Restic log entries..."
# Search the JSON archives for the backup success message
# Adjust the path if Wazuh rotates archives into dated directories (e.g., /var/ossec/logs/archives/YYYY/Mon/)
sleep 10 # Allow a few seconds for ingestion
sudo grep "FINISH backup job OK" /var/ossec/logs/archives/archives.json
```

  * **Expected Output:** You should see JSON objects containing the `full_log` field with your Restic log messages, including `[timestamp] START backup job`, `[...] SNAPSHOT created`, `[...] Pruning process finished`, and `[...] FINISH backup job OK`. Example:

    ```json
    {
      "timestamp": "2025-10-19T...",
      "agent": {
        "id": "000",        // ID 000 indicates logs collected by the manager itself
        "name": "YourManagerHostname" 
      },
      "manager": {
        "name": "YourManagerHostname"
      },
      "id": "...",
      "full_log": "[2025-10-19T...] FINISH backup job OK", 
      "decoder": {},
      "location": "/var/log/restic/backup.log" // Confirms the source file
    }
    ```

  * **If logs are missing:** Double-check the `<localfile>` path in `ossec.conf`, ensure the Wazuh manager has read permissions for `/var/log/restic/backup.log` (should be covered by root running the service), and confirm `logall_json` is enabled. Restart the manager if changes were made.

This successful ingestion confirms the integration is working. You can now proceed to create custom Wazuh rules (in `local_rules.xml`) to generate alerts based on specific messages like "START backup", "FINISH backup job OK", or potential error messages from Restic.

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab – Threat Intelligence Stack*
