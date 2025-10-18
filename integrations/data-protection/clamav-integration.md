# ClamAV Integration with Wazuh Monitoring

[cite_start]This document provides a complete, reproducible methodology for installing and configuring ClamAV on a monitored endpoint (Ubuntu 24.04) and integrating its detection logs with the Wazuh SIEM platform[cite: 176, 541].

[cite_start]The primary objective is to establish a robust channel where malware detections from ClamAV are forwarded to and processed by the Wazuh manager, generating actionable security alerts[cite: 176, 542].

[cite_start]This integration works by configuring the ClamAV daemon (`clamd`) to send its detection events to the system's logging service (syslog/journald)[cite: 198, 544, 671, 673]. [cite_start]The Wazuh agent, which already monitors these system logs by default, forwards the events to the Wazuh manager[cite: 199, 544]. [cite_start]The manager then uses its native, out-of-the-box ClamAV decoders and rules to analyze the log and generate the appropriate alerts[cite: 176, 184, 214, 553].

## Architecture Overview

* [cite_start]**Endpoint (Agent Host):** An Ubuntu 24.04 system [cite: 178, 555] [cite_start]running both the Wazuh agent [cite: 178] [cite_start]and the ClamAV suite[cite: 178, 557].
* **`clamav-daemon`:** The ClamAV daemon service. [cite_start]This is configured to send all detection logs to `syslog`[cite: 198, 576, 672].
* [cite_start]**`clamav-freshclam`:** The service responsible for keeping the ClamAV signature databases up to date[cite: 172, 189, 205, 566].
* [cite_start]**Wazuh Agent:** The agent on the endpoint is configured to collect logs from `/var/log/syslog` [cite: 199, 208, 674] [cite_start]and/or `journald`[cite: 602, 652], which receive the ClamAV daemon's output.
* [cite_start]**Wazuh Manager (Server):** The server receives the logs from the agent and uses its default ruleset (`0320-clam_av_rules.xml`) to identify malware detections and generate high-priority alerts[cite: 184, 215, 685].

---

## Part 1: Endpoint Configuration (Wazuh Agent & ClamAV)

This phase is performed on the monitored endpoint that needs to be protected by ClamAV.

### 1.1 Install ClamAV and Services

1.  Install the ClamAV daemon and the signature update utility:
    ```bash
    sudo apt-get install clamav clamav-freshclam
    ```
    [cite_start][cite: 190, 256]

2.  Start and enable the core ClamAV services:
    ```bash
    sudo systemctl start clamav-daemon
    sudo systemctl start clamav-freshclam
    ```
    [cite_start][cite: 565, 566]

3.  Verify that both services are active and running:
    ```bash
    sudo systemctl status clamav-daemon
    sudo systemctl status clamav-freshclam
    ```
    [cite_start][cite: 192, 193, 567]

    * [cite_start]**Note:** If you run `freshclam` manually, you may see a "Failed to lock the log file" error[cite: 194, 271]. [cite_start]This is expected behavior, as the `clamav-freshclam` *service* already holds the lock[cite: 195, 272, 304]. [cite_start]Rely on the service status to confirm it is working[cite: 195, 273].

### 1.2 Configure ClamAV for Syslog Logging

This is the most critical step for the integration.

1.  Edit the ClamAV daemon configuration file:
    ```bash
    sudo nano /etc/clamav/clamd.conf
    ```
    [cite_start][cite: 197, 257]

2.  Find the `LogSyslog` directive, uncomment it (if necessary), and ensure it is set to `true`:
    ```ini
    # Send all logging to syslog
    LogSyslog true
    ```
    [cite_start][cite: 198, 258, 576, 672]

    * [cite_start]**Rationale:** This configuration forces `clamd` to stop logging to `/var/log/clamav/clamav.log` and instead send all its output to the system's central logger (`/var/log/syslog` or `journald`)[cite: 199, 544, 579, 673]. [cite_start]The Wazuh agent already monitors this location by default[cite: 199, 544].

3.  Restart the `clamav-daemon` service to apply the configuration changes:
    ```bash
    sudo systemctl restart clamav-daemon
    ```
    [cite_start][cite: 202, 259]

### 1.3 Configure Wazuh Agent Log Collection

1.  [cite_start]Verify the Wazuh agent's configuration at `/var/ossec/etc/ossec.conf`[cite: 208, 581].
2.  [cite_start]Ensure the default block for collecting system logs is present[cite: 208]. This configuration is included in the default `ossec.conf` and is all that is needed.

    For most systems (including Ubuntu):
    ```xml
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/log/syslog</location>
    </localfile>
    ```
    [cite_start][cite: 209, 210, 596, 597, 679]

    For modern systems that rely heavily on `journald` (like Ubuntu 24.04):
    ```xml
    <localfile>
      <log_format>journald</log_format>
      <location>journald</location>
    </localfile>
    ```
    [cite_start][cite: 601, 602, 652, 682]

    [cite_start]**Crucial:** Do **not** add `<localfile>` blocks pointing directly to `/var/log/clamav/clamav.log` or `/var/log/clamav/freshclam.log`[cite: 585, 588, 592]. [cite_start]This will conflict with the `LogSyslog` method and prevent alerts from being generated[cite: 582, 683].

3.  Restart the Wazuh agent to ensure its configuration is loaded:
    ```bash
    sudo systemctl restart wazuh-agent
    ```
    [cite_start][cite: 213, 287]

---

## Part 2: Wazuh Manager Configuration (Server)

This integration relies on native rules, so configuration on the manager is minimal and primarily for verification.

### 2.1 Verify Native Ruleset

[cite_start]Wazuh ships with all necessary decoders and rules for ClamAV[cite: 176, 214, 553]. [cite_start]No custom rules are required[cite: 214].

1.  You can confirm the ruleset exists on the **Wazuh Manager**:
    ```bash
    ls -l /var/ossec/ruleset/rules/0320-clam_av_rules.xml
    ```
    [cite_start][cite: 184, 215, 290, 685]

### 2.2 Key Rule IDs

The integration will generate alerts based on the following pre-defined rules:

* [cite_start]**Rule 52502: "ClamAV: Virus detected"** [cite: 232, 625, 687]
    * [cite_start]**Level:** 8 (High Severity) [cite: 232, 650, 689]
    * [cite_start]**Trigger:** Fires when the `clamd` log contains a "FOUND" message for a virus signature[cite: 636, 637, 690]. [cite_start]This is the primary alert for a malware detection[cite: 688].

* [cite_start]**Rule 52511: "Virus detected multiple times"** [cite: 238, 691]
    * [cite_start]**Level:** 10 (Critical Severity) [cite: 238, 693]
    * [cite_start]**Trigger:** A composite rule that fires if rule 52502 triggers multiple times (e.g., 8 times in 360 seconds)[cite: 692].

* [cite_start]**Rule 52510: "Clamd stopped"** [cite: 237, 694]
    * [cite_start]**Level:** 6 (Medium Severity) [cite: 237, 696]
    * [cite_start]**Trigger:** Alerts when the ClamAV daemon service stops, indicating a gap in protection[cite: 695].

* [cite_start]**Rule 52507: "ClamAV database update"** [cite: 236, 697]
    * [cite_start]**Level:** 3 (Low Severity) [cite: 236, 699]
    * [cite_start]**Trigger:** A low-level event indicating the `freshclam` signature update process has started[cite: 698].

---

## Part 3: End-to-End Validation

This procedure validates that the entire pipeline is working, from detection on the endpoint to an alert in the Wazuh dashboard.

### 3.1 Create EICAR Test File (on Endpoint)

[cite_start]Use the standard EICAR antivirus test file to perform a benign detection[cite: 176, 545]. [cite_start]Using `curl` is recommended to avoid syntax errors[cite: 608].

```bash
curl -o /tmp/eicar.txt [https://secure.eicar.org/eicar.com.txt](https://secure.eicar.org/eicar.com.txt)
````

[cite\_start][cite: 609]
[cite\_start]*(Alternatively, you can use `echo` [cite: 218, 262])*

### 3.2 Trigger Detection (on Endpoint)

You **must** use `clamdscan` to trigger the detection. [cite\_start]Using `clamscan` will not work as it is a standalone scanner and does not use the daemon or log to syslog[cite: 180, 219, 220, 275, 611].

```bash
sudo clamdscan /tmp/eicar.txt
```

[cite\_start][cite: 221, 276, 612]

You should see an immediate "FOUND" message in your terminal:
[cite\_start]`... /tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND` [cite: 614]
[cite\_start](or a similar `Eicar-Signature FOUND` message [cite: 225])

### 3.3 Verify Log Ingestion (on Endpoint)

First, confirm the log appeared in `/var/log/syslog` on the endpoint. This validates Part 1.

```bash
tail -n 20 /var/log/syslog | grep -i "eicar"
```

[cite\_start][cite: 223]
You should see a log line similar to:
[cite\_start]`... clamd[...]: /tmp/eicar.txt: Win.Test.EICAR_HDB-1 FOUND` [cite: 636, 637]

### 3.4 Verify Wazuh Alert (on Manager)

Finally, check the `alerts.json` file on the **Wazuh Manager** to confirm the alert was received and processed.

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i "52502"
```

[cite\_start][cite: 230, 291, 616]

A successful integration will show a JSON alert containing:

  * [cite\_start]`"rule"."id":"52502"` [cite: 232, 546, 626]
  * [cite\_start]`"rule"."level":8` [cite: 232, 624, 650]
  * [cite\_start]`"rule"."description":"ClamAV: Virus detected"` [cite: 232, 625]
  * [cite\_start]The `full_log` field showing the original detection event from `clamd`[cite: 636, 637, 651].
  * [cite\_start]The `location` field showing `syslog` or `journald`[cite: 646, 652].

### 3.5 Cleanup (on Endpoint)

Remove the EICAR test file.

```bash
rm /tmp/eicar.txt
```

[cite\_start][cite: 254]

-----

## Troubleshooting

  * **Problem:** I ran `clamscan /tmp/eicar.txt` but no alert appeared in Wazuh.

      * [cite\_start]**Cause:** You used `clamscan` instead of `clamdscan`[cite: 274, 275]. [cite\_start]`clamscan` is a standalone scanner and does not log to syslog/journald, so the daemon (and Wazuh) never sees the event[cite: 219, 275, 611].
      * [cite\_start]**Solution:** You must use `clamdscan /tmp/eicar.txt` to instruct the *daemon* to perform the scan, which will log correctly[cite: 221, 276, 283].

  * **Problem:** I ran `freshclam` manually and got a "log lock" error.

      * [cite\_start]**Cause:** This is normal[cite: 194, 272]. [cite\_start]The `clamav-freshclam` *service* is already running in the background and has a lock on the log files[cite: 195, 272, 304].
      * **Solution:** Do nothing. Rely on the service. [cite\_start]Check its status with `sudo systemctl status clamav-freshclam` to ensure it is running and updating signatures[cite: 195, 273].

  * **Problem:** I ran `clamdscan` and saw the "FOUND" message, but no alert appeared in Wazuh.

      * [cite\_start]**Cause 1:** Your `clamd.conf` does not have `LogSyslog true` enabled[cite: 198].
      * [cite\_start]**Cause 2:** You did not restart the `clamav-daemon` service after enabling `LogSyslog true`[cite: 202].
      * [cite\_start]**Cause 3:** Your Wazuh agent `ossec.conf` is still pointing to `/var/log/clamav/clamav.log` instead of the default `/var/log/syslog` or `journald`[cite: 582, 683].
      * [cite\_start]**Solution:** Verify all steps in Part 1 (Endpoint Configuration) are correct, then restart both `clamav-daemon` [cite: 202] [cite\_start]and `wazuh-agent`[cite: 213].

<!-- end list -->
