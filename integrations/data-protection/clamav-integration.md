# ClamAV Integration with Wazuh: A Methodological Guide

## 1. Executive Summary

This report provides a complete, reproducible methodology for the installation, configuration, and validation of ClamAV antivirus within a Wazuh Security Information and Event Management (SIEM) environment. The primary objective is to establish a robust communication channel where malware detections from ClamAV are forwarded to and processed by the Wazuh manager, generating actionable security alerts.

The procedure was conducted on an Ubuntu 24.04 LTS system running the all-in-one Wazuh server stack and ClamAV. The integration is achieved by configuring ClamAV to log detection events to the system's logging service (journald/syslog), which Wazuh inherently monitors.

Validation via the EICAR test file confirmed the successful generation of a Level 8 alert (Rule ID: 52502), validating the end-to-end communication.

## 2. System Environment

* **Operating System**: Ubuntu 24.04 LTS PRO
* **Wazuh Stack**: Wazuh Manager, Indexer, and Dashboard (All-in-one)
* **ClamAV Version**: 1.4.3+dfsg-0ubuntu0.24.04.1

## 3. Methodology

The integration was performed in three distinct phases: Service Verification, System Configuration, and End-to-End Validation.

### Phase 1: Service & Configuration Verification

The initial step was to ensure all necessary components were installed and active.

**1. ClamAV Service Verification**
Services were started, enabled, and confirmed to be `active (running)`.

```bash
# Verify installation
dpkg -l | grep "clamav"

# Start and enable core services
sudo systemctl start clamav-daemon
sudo systemctl start clamav-freshclam

# Check status
sudo systemctl status clamav-daemon
sudo systemctl status clamav-freshclam
````

**2. Wazuh Service Verification**
All Wazuh components were confirmed to be `active (running)`.

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Phase 2: System Configuration for Integration

This phase establishes the data pipeline between ClamAV and Wazuh.

**1. ClamAV Configuration (`/etc/clamav/clamd.conf`)**
The critical step is directing the `clamd` daemon to log to the system logger. This is achieved by ensuring the `LogSyslog` directive is set to `true`.

```bash
# Command to verify the setting
sudo grep "LogSyslog" /etc/clamav/clamd.conf
```

*Expected Output: `LogSyslog true`*

**2. Wazuh Manager Configuration (`/var/ossec/etc/ossec.conf`)**
The configuration must monitor the system's central log sources, not ClamAV's native log files (which are bypassed by `LogSyslog`).

*Incorrect* blocks pointing to `/var/log/clamav/clamav.log` or `freshclam.log` must be removed.

The *correct*, default blocks must be present to monitor logs from syslog and journald:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>

<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```

**3. Apply Configuration**
Restart the Wazuh manager to apply the changes.

```bash
sudo systemctl restart wazuh-manager
```

### Phase 3: End-to-End Validation

A controlled test to validate the full event pipeline.

**1. EICAR Test File Creation**
The standard EICAR test file was downloaded using `curl`.

```bash
curl -o /tmp/eicar.txt [https://secure.eicar.org/eicar.com.txt](https://secure.eicar.org/eicar.com.txt)
```

**2. Triggering Detection**
The `clamdscan` command is used to instruct the *running daemon* to scan the file. Using `clamscan` (without the 'd') will *not* use the daemon and will *not* log to syslog/journald.

```bash
sudo clamdscan /tmp/eicar.txt
```

*Observed Output: `/tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND`*

**3. Alert Verification**
Monitor the `alerts.json` file on the Wazuh manager in real-time.

```bash
sudo tail -f /var/ossec/logs/alerts/json/alerts.json
```

## 5\. Results and Analysis

The validation test was a definitive success. Within seconds, a new alert was written to `alerts.json`, confirming all aspects of the integration.

**Key Alert Details**:

  * **Timestamp**: `2025-10-08T...`
  * **Rule ID**: `52502`
  * **Level**: `8`
  * **Description**: `ClamAV: Virus detected`
  * **Agent**: `000` / `flausino`
  * **full\_log**: `... flausino clamd[...]: /tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND`
  * **Decoder**: `clamd`
  * **Location**: `journald`

**Analysis**:

  * **Rule ID 52502 / Level 8**: Confirms Wazuh's out-of-the-box ruleset correctly identified the event as high-severity.
  * **full\_log**: Contains the original raw log, showing the exact file and signature.
  * **location: "journald"**: Proves that the Wazuh logcollector correctly ingested the event from the `systemd-journald` service, as configured.

## 6\. Conclusion

The integration of ClamAV with the Wazuh SIEM was successfully completed and validated. This methodology ensures all malware detections are now centrally visible, significantly enhancing the security monitoring posture.

The key to this integration is the correct configuration:

1.  **ClamAV**: Must be set to log to the system's central logging service (`LogSyslog true`).
2.  **Wazuh**: Must be configured to monitor that service (`journald` or `/var/log/syslog`).

