Aqui está o documento de metodologia para a integração do ClamAV, refeito para seguir o formato solicitado e com a assinatura de autor correta no final.

-----

# **ClamAV Integration with Wazuh Monitoring**

## **1. Overview**

This document provides a complete, reproducible methodology for installing and configuring ClamAV on a monitored endpoint (Ubuntu 24.04) and integrating its detection logs with the Wazuh SIEM platform.

The primary objective is to establish a robust channel where malware detections from ClamAV are forwarded to and processed by the Wazuh manager, generating actionable security alerts.

This integration works by configuring the ClamAV daemon (`clamd`) to send its detection events to the system's logging service (syslog/journald). The Wazuh agent, which already monitors these system logs by default, forwards the events to the Wazuh manager. The manager then uses its native, out-of-the-box ClamAV decoders and rules (`0320-clam_av_rules.xml`) to analyze the log and generate the appropriate alerts.

## **2. System Environment**

  * **Operating System:** Ubuntu 24.04 LTS
  * **Antivirus:** ClamAV 1.4.3
  * **SIEM:** Wazuh 4.x (Manager, Indexer, Dashboard)

-----

## **3. Part 1: Endpoint Configuration (ClamAV)**

This phase is performed on the monitored endpoint that needs to be protected by ClamAV.

### **3.1 Install ClamAV and Services**

1.  Install the ClamAV daemon and the signature update utility:

    ```bash
    sudo apt-get install clamav clamav-freshclam
    ```

2.  Start and enable the core ClamAV services:

    ```bash
    sudo systemctl start clamav-daemon
    sudo systemctl start clamav-freshclam
    ```

3.  Verify that both services are active and running:

    ```bash
    sudo systemctl status clamav-daemon
    sudo systemctl status clamav-freshclam
    ```

      * **Note:** If you run `freshclam` manually, you may see a "Failed to lock the log file" error. This is expected behavior, as the `clamav-freshclam` *service* already holds the lock. Rely on the service status to confirm it is working.

### **3.2 Configure ClamAV for Syslog Logging**

This is the most critical step for the integration.

1.  Edit the ClamAV daemon configuration file:

    ```bash
    sudo nano /etc/clamav/clamd.conf
    ```

2.  Find the `LogSyslog` directive, uncomment it (if necessary), and ensure it is set to `true`:

    ```ini
    # Send all logging to syslog
    LogSyslog true
    ```

      * **Rationale:** This configuration forces `clamd` to stop logging to `/var/log/clamav/clamav.log` and instead send all its output to the system's central logger (`/var/log/syslog` or `journald`). The Wazuh agent already monitors this location by default.

3.  Restart the `clamav-daemon` service to apply the configuration changes:

    ```bash
    sudo systemctl restart clamav-daemon
    ```

-----

## **4. Part 2: Wazuh Agent Log Collection (Endpoint)**

This phase involves verifying the Wazuh agent's configuration on the *same endpoint*.

### **4.1 Verify Wazuh Agent Log Collection**

1.  Verify the Wazuh agent's configuration at `/var/ossec/etc/ossec.conf`.

2.  Ensure the default block for collecting system logs is present. This configuration is included in the default `ossec.conf` and is all that is needed.

    For most systems (including Ubuntu):

    ```xml
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/syslog</location>
    </localfile>
    ```

    For modern systems that rely heavily on `journald` (like Ubuntu 24.04):

    ```xml
    <localfile>
      <log_format>journald</log_format>
      <location>journald</location>
    </localfile>
    ```

      * **Crucial:** Do **not** add `<localfile>` blocks pointing directly to `/var/log/clamav/clamav.log` or `/var/log/clamav/freshclam.log`. This will conflict with the `LogSyslog` method and prevent alerts from being generated.

3.  Restart the Wazuh agent to ensure its configuration is loaded:

    ```bash
    sudo systemctl restart wazuh-agent
    ```

-----

## **5. Part 3: Wazuh Manager Rule Verification (Server)**

This integration relies on native rules, so configuration on the manager is minimal and primarily for verification.

### **5.1 Verify Native Ruleset**

Wazuh ships with all necessary decoders and rules for ClamAV. No custom rules are required.

1.  You can confirm the ruleset exists on the **Wazuh Manager**:
    ```bash
    ls -l /var/ossec/ruleset/rules/0320-clam_av_rules.xml
    ```

### **5.2 Key Rule IDs**

The integration will generate alerts based on the following pre-defined rules:

  * **Rule 52502: "ClamAV: Virus detected"**

      * **Level:** 8 (High Severity)
      * **Trigger:** Fires when the `clamd` log contains a "FOUND" message for a virus signature. This is the primary alert for a malware detection.

  * **Rule 52511: "Virus detected multiple times"**

      * **Level:** 10 (Critical Severity)
      * **Trigger:** A composite rule that fires if rule 52502 triggers multiple times (e.g., 8 times in 360 seconds).

  * **Rule 52510: "Clamd stopped"**

      * **Level:** 6 (Medium Severity)
      * **Trigger:** Alerts when the ClamAV daemon service stops, indicating a gap in protection.

  * **Rule 52507: "ClamAV database update"**

      * **Level:** 3 (Low Severity)
      * **Trigger:** A low-level event indicating the `freshclam` signature update process has started.

-----

## **6. Part 4: End-to-End Validation**

This procedure validates that the entire pipeline is working, from detection on the endpoint to an alert in the Wazuh dashboard.

### **6.1 Create EICAR Test File (on Endpoint)**

Use the standard EICAR antivirus test file to perform a benign detection. Using `curl` is recommended to avoid syntax errors.

```bash
curl -o /tmp/eicar.txt https://secure.eicar.org/eicar.com.txt
```

### **6.2 Trigger Detection (on Endpoint)**

You **must** use `clamdscan` to trigger the detection. Using `clamscan` will not work as it is a standalone scanner and does not use the daemon or log to syslog.

```bash
sudo clamdscan /tmp/eicar.txt
```

You should see an immediate "FOUND" message in your terminal:
`... /tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND`
(or a similar `Eicar-Signature FOUND` message)

### **6.3 Verify Log Ingestion (on Endpoint)**

First, confirm the log appeared in `/var/log/syslog` (or journal) on the endpoint. This validates Part 1 and 2.

```bash
tail -n 20 /var/log/syslog | grep -i "eicar"
```

You should see a log line similar to:
`... clamd[...]: /tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND`

### **6.4 Verify Wazuh Alert (on Manager)**

Finally, check the `alerts.json` file on the **Wazuh Manager** to confirm the alert was received and processed.

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i "52502"
```

A successful integration will show a JSON alert containing:

  * `"rule"."id":"52502"`
  * `"rule"."level":8`
  * `"rule"."description":"ClamAV: Virus detected"`
  * The `full_log` field showing the original detection event from `clamd`.
  * The `location` field showing `syslog` or `journald`.

### **6.5 Run wazuh-logtest (on Manager)**

You can also paste the full log line directly into `wazuh-logtest` to verify the decoding and rule matching.

```bash
sudo /var/ossec/bin/wazuh-logtest
```

**Paste the following log line:**
`Oct 08 18:39:38 flausino clamd[2252]: /tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND`

**Expected Test Output:**

```
**Phase 1: Completed pre-decoding.
    full event: 'Oct 08 18:39:38 flausino clamd[2252]: /tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND'
    timestamp: 'Oct 08 18:39:38'
    hostname: 'flausino'
    program_name: 'clamd'

**Phase 2: Completed decoding.
    name: 'clamd'
    parent: 'clamd'
    id: '/tmp/eicar.txt'
    url: 'Win.Test.EICAR_HDB-1 FOUND'

**Phase 3: Completed filtering (rules).
    id: '52502'
    level: '8'
    description: 'ClamAV: Virus detected'
    groups: '['clamd', 'freshclam', 'virus']'
**Alert to be generated.
```

### **6.6 Cleanup (on Endpoint)**

Remove the EICAR test file.

```bash
rm /tmp/eicar.txt
```

-----

## **7. Part 5: Troubleshooting**

  * **Problem:** I ran `clamscan /tmp/eicar.txt` but no alert appeared in Wazuh.

      * **Cause:** You used `clamscan` instead of `clamdscan`. `clamscan` is a standalone scanner and does not log to syslog/journald, so the daemon (and Wazuh) never sees the event.
      * **Solution:** You must use `clamdscan /tmp/eicar.txt` to instruct the *daemon* to perform the scan, which will log correctly.

  * **Problem:** I ran `freshclam` manually and got a "log lock" error.

      * **Cause:** This is normal. The `clamav-freshclam` *service* is already running in the background and has a lock on the log files.
      * **Solution:** Do nothing. Rely on the service. Check its status with `sudo systemctl status clamav-freshclam` to ensure it is running and updating signatures.

  * **Problem:** I ran `clamdscan` and saw the "FOUND" message, but no alert appeared in Wazuh.

      * **Cause 1:** Your `clamd.conf` does not have `LogSyslog true` enabled.
      * **Cause 2:** You did not restart the `clamav-daemon` service after enabling `LogSyslog true`.
      * **Cause 3:** Your Wazuh agent `ossec.conf` is still pointing to `/var/log/clamav/clamav.log` instead of the default `/var/log/syslog` or `journald`.
      * **Solution:** Verify all steps in Part 1 and Part 2 are correct, then restart both `clamav-daemon` and `wazuh-agent`.

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab – Threat Intelligence Stack*
