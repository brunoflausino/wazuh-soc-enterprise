# **VeraCrypt Integration with Wazuh Monitoring**

## **1. Overview**

This guide provides the methodology for integrating VeraCrypt (console version) with the Wazuh SIEM to monitor encrypted volume operations (mounts and dismounts) on **Ubuntu 24.04**.

A key challenge with VeraCrypt is that it does **not** natively log mount or dismount events to standard system logs like `syslog` or `journald`. To overcome this, this integration uses custom **wrapper scripts** (`vc-mount`, `vc-umount`). These scripts perform two main functions:

1.  They execute the actual VeraCrypt command you intend to run.
2.  They explicitly log the success or failure of that command to `systemd-journald` using the `logger` utility, adding specific tags (`veracrypt-mount`, `veracrypt-dismount`) that Wazuh can filter.

Wazuh is then configured to monitor `journald` for these specific tags and uses custom rules to generate alerts for successful mounts, failed mounts, and potential brute-force attempts based on repeated failures.

## **2. System Environment**

  * **Operating System:** Ubuntu 24.04 LTS
  * **Encryption Tool:** VeraCrypt Console 1.26.24+
  * **SIEM:** Wazuh Manager 4.12.0+
  * **Logging System:** `systemd` with `journald`
  * **Privileges:** All commands require `sudo`.

-----

## **3. Part 1: Installation**

### **3.1 Install VeraCrypt Console**

Download and install the official VeraCrypt console `.deb` package for Ubuntu 24.04.

```bash
# Download the .deb package
wget https://launchpad.net/veracrypt/trunk/1.26.24/+download/veracrypt-console-1.26.24-Ubuntu-24.04-amd64.deb

# Install the downloaded package (this handles dependencies)
sudo apt install ./veracrypt-console-1.26.24-Ubuntu-24.04-amd64.deb

# Verify installation (optional)
veracrypt --version

# Clean up the downloaded file
rm ./veracrypt-console-1.26.24-Ubuntu-24.04-amd64.deb
```

### **3.2 Create Logging Wrapper Scripts**

Because VeraCrypt doesn't log mount/dismount events itself, we need to create simple scripts that *wrap* the `veracrypt` command and add the necessary logging step. These scripts will live in `/usr/local/bin/`, which is typically in the system's PATH, allowing you to call them easily.

1.  **Create the Mount Wrapper Script (`vc-mount`)**

      * **Purpose:** This script will handle mounting VeraCrypt volumes. It runs the `veracrypt --mount` command and then uses `logger` to send a "Success" or "Failed" message to `journald` with the tag `veracrypt-mount`.

      * **Create the file:** Open the file using `nano` (or your preferred editor).

        ```bash
        sudo nano /usr/local/bin/vc-mount
        ```

      * **Paste the script code:** Copy the entire code block below and paste it into the editor.

        ```bash
        #!/usr/bin/env bash
        # Wrapper script for VeraCrypt mount with logging to journald

        # Exit immediately if a command exits with a non-zero status,
        # treats unset variables as an error, and fails if any command in a pipeline fails.
        set -euo pipefail

        # --- Input Validation ---
        # Ensure at least two arguments (volume path and mount point) are provided.
        if [ $# -lt 2 ]; then
          echo "Usage: vc-mount <volume> <mountpoint> [veracrypt-options]" >&2
          exit 1
        fi

        # --- Argument Processing ---
        # Assign the first argument to VOL (volume path).
        VOL="$1"
        # Assign the second argument to MP (mount point).
        MP="$2"
        # Remove the first two arguments ($1 and $2) from the list.
        # Any remaining arguments ("$@") will be passed directly to the veracrypt command.
        shift 2

        # --- VeraCrypt Execution and Logging ---
        echo "Attempting to mount $VOL to $MP ..." >&2

        # Execute the actual VeraCrypt mount command in text mode (--text)
        # --non-interactive prevents prompts if possible (e.g., filesystem checks)
        if veracrypt --text --non-interactive --mount "$VOL" "$MP" "$@"; then
          # If the command succeeds (exit code 0):
          echo "Mount successful." >&2
          # Log a success message to journald with the tag 'veracrypt-mount'.
          logger --tag veracrypt-mount "Success volume=$VOL mp=$MP"
          exit 0 # Exit the script successfully.
        else
          # If the command fails (non-zero exit code):
          RC=$? # Capture the exit code from the failed veracrypt command.
          echo "Mount failed with exit code $RC." >&2
          # Log a failure message to journald, including the volume, mount point, and exit code.
          logger --tag veracrypt-mount "Failed volume=$VOL mp=$MP rc=$RC"
          exit $RC # Exit the script with the same error code as veracrypt.
        fi
        ```

      * **Save and close:** Press `Ctrl+O`, then `Enter` to save, and `Ctrl+X` to exit `nano`.

2.  **Create the Dismount Wrapper Script (`vc-umount`)**

      * **Purpose:** This script handles dismounting VeraCrypt volumes. It runs `veracrypt --dismount` and logs the result to `journald` with the tag `veracrypt-dismount`.

      * **Create the file:**

        ```bash
        sudo nano /usr/local/bin/vc-umount
        ```

      * **Paste the script code:** Copy and paste the code below into the editor.

        ```bash
        #!/usr/bin/env bash
        # Wrapper script for VeraCrypt dismount with logging to journald

        set -euo pipefail

        # --- Input Validation ---
        # Ensure at least one argument (mount point or volume path) is provided.
        if [ $# -lt 1 ]; then
          echo "Usage: vc-umount <mountpoint|volume>" >&2
          exit 1
        fi

        # --- Argument Processing ---
        # Assign the first argument to TARGET. This can be the mount point or the volume file itself.
        TARGET="$1"

        # --- VeraCrypt Execution and Logging ---
        echo "Attempting to dismount $TARGET ..." >&2

        # Execute the actual VeraCrypt dismount command.
        if veracrypt --text --non-interactive --dismount "$TARGET"; then
          # If the command succeeds:
          echo "Dismount successful." >&2
          # Log success to journald with the tag 'veracrypt-dismount'.
          logger --tag veracrypt-dismount "Success mp=$TARGET"
          exit 0 # Exit successfully.
        else
          # If the command fails:
          RC=$? # Capture the exit code.
          echo "Dismount failed with exit code $RC." >&2
          # Log failure to journald, including the target and exit code.
          logger --tag veracrypt-dismount "Failed mp=$TARGET rc=$RC"
          exit $RC # Exit with the same error code.
        fi
        ```

      * **Save and close:** Press `Ctrl+O`, `Enter`, `Ctrl+X`.

3.  **Make Wrappers Executable:**
    Allow the system to run these scripts.

    ```bash
    sudo chmod +x /usr/local/bin/vc-mount
    sudo chmod +x /usr/local/bin/vc-umount
    echo "Wrapper scripts created and made executable."
    ```

-----

## **4. Part 2: Wazuh Manager Configuration**

Configure the Wazuh Manager to monitor `journald` for the specific tags generated by the wrapper scripts.

### **4.1 Configure `ossec.conf` for Journald Monitoring**

1.  **Backup `ossec.conf`:**

    ```bash
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak_veracrypt_$(date +%Y%m%d_%H%M%S)
    echo "Backed up current ossec.conf"
    ```

2.  **Edit `ossec.conf`:**

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

3.  **Add `<localfile>` Block for Journald:**
    Inside `<ossec_config>`, add this block. It tells Wazuh to read from `journald` but **only** ingest logs where the `SYSLOG_IDENTIFIER` field (which `logger --tag` sets) matches the regular expression `^veracrypt-(mount|dismount)$`.

    ```xml
      <localfile>
        <location>journald</location>
        <log_format>journald</log_format>
        <filter field="SYSLOG_IDENTIFIER">^veracrypt-(mount|dismount)$</filter>
      </localfile>
    ```

4.  **(Recommended for Validation)** **Enable Log Archiving:**
    Ensure the `<global>` section includes `<logall_json>yes</logall_json>` to archive all ingested logs (useful during setup).

    ```xml
      <global>
        <logall>yes</logall> <logall_json>yes</logall_json>
        ...
      </global>
    ```

### **4.2 Add Custom Rules (local\_rules.xml)**

Add rules to generate alerts based on the logs ingested from `journald`.

1.  **Edit `local_rules.xml`:**

    ```bash
    sudo nano /var/ossec/etc/rules/local_rules.xml
    ```

2.  **Add VeraCrypt Rules:**
    Paste the following rule group inside the main `<group name="local,">` tags (or create the file if it doesn't exist).

    ```xml
    <group name="veracrypt,syslog,">

      <rule id="110200" level="5">
        <program_name>veracrypt-mount</program_name>
        <match>Success</match>
        <description>VeraCrypt: Volume mounted successfully</description>
        <group>veracrypt,mount_success,</group>
      </rule>

      <rule id="110210" level="7">
        <program_name>veracrypt-mount</program_name>
        <match>Failed</match>
        <description>VeraCrypt: Failed to mount volume</description>
        <group>veracrypt,mount_failure,</group>
      </rule>

      <rule id="110211" level="10" frequency="3" timeframe="60">
        <if_matched_sid>110210</if_matched_sid>
        <same_location />
        <description>VeraCrypt: Multiple mount failures detected (3 in 60s) - Potential brute-force attempt</description>
        <group>veracrypt,brute_force,authentication_failures,</group>
      </rule>

      <rule id="110202" level="4">
        <program_name>veracrypt-dismount</program_name>
        <match>Success</match>
        <description>VeraCrypt: Volume unmounted successfully</description>
        <group>veracrypt,umount_success,</group>
      </rule>

      <rule id="110203" level="7">
        <program_name>veracrypt-dismount</program_name>
        <match>Failed</match>
        <description>VeraCrypt: Failed to unmount volume</description>
        <group>veracrypt,umount_failure,</group>
      </rule>

    </group>
    ```

### **4.3 Restart Wazuh Manager**

Apply the `ossec.conf` and rule changes.

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status --no-pager wazuh-manager # Check status after restart
```

-----

## **5. Part 3: Usage and Validation**

### **5.1 Usage Instructions**

To ensure mount/dismount operations are logged and monitored by Wazuh, you **must** now use the `vc-mount` and `vc-umount` wrapper scripts instead of the standard `veracrypt` command.

  * **To Mount a Volume:**

    ```bash
    # Example: Mount a container file, prompting for password
    vc-mount /path/to/mycontainer.vc /mnt/myvolume

    # Example: Mount using a keyfile and other options
    # Note: Options like --keyfiles are passed *after* the volume and mount point
    vc-mount /path/to/mycontainer.vc /mnt/myvolume --keyfiles=/path/to/key.file --protect-hidden=no --password=YourPasswordHere
    ```

  * **To Dismount a Volume:**

    ```bash
    # Example: Dismount by mount point
    vc-umount /mnt/myvolume

    # Example: Dismount by volume path (also works)
    vc-umount /path/to/mycontainer.vc
    ```

### **5.2 Validation Steps**

Perform mount and dismount operations (both successful and intentionally failing ones, e.g., wrong password) using the `vc-mount` and `vc-umount` commands. Then, verify the events at each stage:

1.  **Check `journald` Logs (Real-time on Endpoint):**
    See the raw logs generated by the wrappers immediately after running `vc-mount` or `vc-umount`.

    ```bash
    # Follow journald logs filtered by the tags used in the wrappers
    journalctl -f -t veracrypt-mount -t veracrypt-dismount
    ```

      * **Expected:** You will see lines like `Oct 19 07:10:00 yourhostname veracrypt-mount[PID]: Success volume=/path/to/mycontainer.vc mp=/mnt/myvolume` or `Oct 19 07:11:00 yourhostname veracrypt-mount[PID]: Failed volume=/path/to/mycontainer.vc mp=/mnt/myvolume rc=3`.

2.  **Check Wazuh Archives (on Manager):**
    Verify that Wazuh ingested the logs from `journald` (requires `logall_json=yes`).

    ```bash
    # Follow the Wazuh archive log and filter for veracrypt
    sudo tail -f /var/ossec/logs/archives/archives.json | grep veracrypt
    ```

      * **Expected:** You should see JSON objects where the `full_log` field contains the message from `journald`, and the `program_name` field matches `veracrypt-mount` or `veracrypt-dismount`.

3.  **Check Wazuh Alerts (on Manager):**
    Confirm that the custom rules triggered and generated alerts based on the "Success" or "Failed" messages.

    ```bash
    # Follow the Wazuh alert log and filter for the VeraCrypt rule IDs (starting with 1102)
    sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"rule":{"id":"1102'
    ```

      * **Expected:** See JSON alert objects corresponding to the rules: `110200` (Mount Success), `110210` (Mount Failed), `110202` (Dismount Success), `110203` (Dismount Failed). If you trigger rule `110210` three times within 60 seconds, you should also see an alert for rule `110211` (Multiple Mount Failures).

### **5.3 Rule ID Summary**

  * **110200:** Successful mount (Level 5)
  * **110202:** Successful unmount (Level 4)
  * **110210:** Failed mount (Level 7) - Base rule for failures.
  * **110203:** Failed unmount (Level 7)
  * **110211:** Multiple mount failures (3 in 60s) (Level 10) - Correlation rule for potential brute-force.

This setup provides visibility into VeraCrypt mount/dismount activities within your Wazuh SIEM by capturing events that VeraCrypt itself does not log.

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab – Threat Intelligence Stack*
