# VeraCrypt Integration with Wazuh Monitoring

[cite_start]This document provides the methodology for integrating VeraCrypt (console version) with the Wazuh SIEM to monitor encrypted volume operations (mounts and dismounts) on Ubuntu 24.04. [cite: 822]

## Overview

[cite_start]The integration captures VeraCrypt events by using custom wrapper scripts (`vc-mount`, `vc-umount`) that execute the real VeraCrypt commands. [cite: 824] [cite_start]These wrappers use the `logger` utility to send success or failure events to `systemd-journald` with a specific tag. [cite: 824, 851, 855, 869, 873]

[cite_start]Wazuh is then configured to monitor `journald`, filter for these specific tags, and process the events through a set of custom rules to generate alerts for successful mounts, failed mounts, and potential brute-force attempts. [cite: 824, 971]

## Prerequisites

* [cite_start]Ubuntu 24.04 LTS [cite: 826]
* [cite_start]VeraCrypt Console 1.26.24+ [cite: 827]
* [cite_start]Wazuh Manager 4.12.0+ [cite: 828]
* [cite_start]`systemd` with `journald` [cite: 829]

---

## 1. Installation

### 1.1 Install VeraCrypt Console

Download and install the official VeraCrypt console package for Ubuntu 24.04.

```bash
wget [https://launchpad.net/veracrypt/trunk/1.26.24/+download/veracrypt-console-1.26.24-Ubuntu-24.04-amd64.deb](https://launchpad.net/veracrypt/trunk/1.26.24/+download/veracrypt-console-1.26.24-Ubuntu-24.04-amd64.deb)
sudo apt install ./veracrypt-console-1.26.24-Ubuntu-24.04-amd64.deb
````

[cite\_start][cite: 834]

### 1.2 Create Logging Wrappers

Create custom scripts in `/usr/local/bin/` that will replace the standard `veracrypt` command for mounting and dismounting. These scripts add the logging layer before executing the real command.

**Wrapper Script: `vc-mount`**

This script mounts a volume and logs the success or failure to `journald` with the tag `veracrypt-mount`.

```bash
sudo tee /usr/local/bin/vc-mount > /dev/null << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: vc-mount <volume> <mountpoint> [veracrypt-options]" >&2
  exit 1
fi

VOL="$1"
MP="$2"
shift 2

if veracrypt-text --non-interactive --mount "$VOL" "$MP" "$@"; then
  logger --tag veracrypt-mount "Success volume=$VOL mp=$MP"
else
  RC=$?
  logger --tag veracrypt-mount "Failed volume=$VOL mp=$MP rc=$RC"
  exit $RC
fi
EOF
```

[cite\_start][cite: 842-856]

**Wrapper Script: `vc-umount`**

This script dismounts a volume and logs the success or failure to `journald` with the tag `veracrypt-dismount`.

```bash
sudo tee /usr/local/bin/vc-umount > /dev/null << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: vc-umount <mountpoint|volume>" >&2
  exit 1
fi

TARGET="$1"

if veracrypt-text --non-interactive --dismount "$TARGET"; then
  logger --tag veracrypt-dismount "Success mp=$TARGET"
else
  RC=$?
  logger --tag veracrypt-dismount "Failed mp=$TARGET rc=$RC"
  exit $RC
fi
EOF
```

[cite\_start][cite: 860-874]

**Make Wrappers Executable**

```bash
sudo chmod +x /usr/local/bin/vc-mount
sudo chmod +x /usr/local/bin/vc-umount
```

[cite\_start][cite: 857, 875]

-----

## 2\. Wazuh Manager Configuration

### 2.1 Configure `ossec.conf` for Journald

Edit the Wazuh manager configuration to monitor `journald` and specifically filter for the `veracrypt-mount` and `veracrypt-dismount` tags.

1.  Edit `/var/ossec/etc/ossec.conf`:

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

2.  Add the following `<localfile>` block. This tells Wazuh to read from `journald` but *only* ingest logs that match the specified `SYSLOG_IDENTIFIER` filter.

    ```xml
    <localfile>
      <location>journald</location>
      <log_format>journald</log_format>
      <filter field="SYSLOG_IDENTIFIER">^veracrypt-(mount|dismount)$</filter>
    </localfile>
    ```

    [cite\_start][cite: 883-886]

3.  Also in `ossec.conf`, ensure log archiving is enabled in the `<global>` section. This allows you to see all ingested logs, not just alerts.

    ```xml
    <global>
      <logall>yes</logall>
      <logall_json>yes</logall_json>
    </global>
    ```

    [cite\_start][cite: 887-892]

### 2.2 Add Custom Rules

Create a new file (or add to your existing one) for VeraCrypt-specific rules.

1.  Edit `/var/ossec/etc/rules/local_rules.xml`:

    ```bash
    sudo nano /var/ossec/etc/rules/local_rules.xml
    ```

2.  Add the following rules:

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
        <description>VeraCrypt: Multiple mount failures (3 in 60s)</description>
        <group>veracrypt,brute_force,</group>
      </rule>

      <rule id="110202" level="4">
        <program_name>veracrypt-dismount</program_name>
        <match>Success</match>
        <description>VeraCrypt: Volume unmounted</description>
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

    [cite\_start][cite: 899-936]

### 2.3 Restart Wazuh Manager

Apply all configuration changes by restarting the manager.

```bash
sudo systemctl restart wazuh-manager
```

[cite\_start][cite: 941]

-----

## 3\. Usage and Validation

### 3.1 Usage

To ensure events are logged, you **must** use the new wrapper scripts instead of the standard `veracrypt` command.

  * **To Mount:**
    ```bash
    vc-mount /path/to/container.vc /mnt/point
    ```
    [cite\_start][cite: 948]
  * **To Unmount:**
    ```bash
    vc-umount /mnt/point
    ```
    [cite\_start][cite: 950]

### 3.2 Validation and Monitoring

You can monitor the logs and alerts at three different stages.

1.  **Check `journald` (Live on Agent):**
    See the raw logs as they are generated by the wrappers.

    ```bash
    journalctl -f -t veracrypt-mount -t veracrypt-dismount
    ```

    [cite\_start][cite: 955]

2.  **Check Wazuh Archives (on Manager):**
    See the JSON-formatted logs *after* Wazuh has ingested them (requires `logall_json` enabled).

    ```bash
    sudo tail -f /var/ossec/logs/archives/archives.json | grep veracrypt
    ```

    [cite\_start][cite: 957]

3.  **Check Wazuh Alerts (on Manager):**
    See the final alerts generated by the custom rules.

    ```bash
    sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"id":"1102'
    ```

    [cite\_start][cite: 959]

### 3.3 Rule ID Summary

  * [cite\_start]**110200:** Successful mount (Level 5) [cite: 961]
  * [cite\_start]**110202:** Successful unmount (Level 4) [cite: 962]
  * [cite\_start]**110210:** Failed mount (Level 7) [cite: 963]
  * [cite\_start]**110203:** Failed unmount (Level 7) [cite: 964]
  * [cite\_start]**110211:** Multiple mount failures (3 in 60s) (Level 10) [cite: 965]

<!-- end list -->
