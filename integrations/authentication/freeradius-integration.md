# FreeRADIUS Integration with Wazuh (JSON/Linelog Method - Complete & Hardened)

## 1. Abstract

This document details the complete, end-to-end integration of FreeRADIUS 3.x with Wazuh SIEM, synthesizing best practices from provided technical reports. This methodology represents a robust and secure approach, combining:

1.  **Hardened Security:** FreeRADIUS is configured to listen *only* on the localhost interface (`127.0.0.1` and `::1`), significantly reducing its direct network exposure. This configuration is suitable for scenarios where authentication requests are received locally (e.g., from local applications, test tools, or a dedicated proxy service documented elsewhere).
2.  **Modern JSON Logging:** Utilizes the FreeRADIUS `rlm_linelog` module to output structured JSON logs directly to a file. This method leverages Wazuh's native JSON decoding, ensuring reliable parsing and resilience against log format changes compared to regex-based syslog methods.
3.  **Critical Logging Fix:** Incorporates the mandatory configuration step to explicitly invoke the JSON logging module within the `Post-Auth-Type REJECT` block. This ensures that failed authentication attempts (`Access-Reject`) are reliably logged, addressing a common configuration oversight.

This guide provides reproducible steps for configuration, Wazuh integration, and validation specific to this JSON-based approach.

## 2. System Environment

* **Operating System**: Ubuntu 24.04 LTS
* **FreeRADIUS**: 3.2.5 (or compatible 3.x version)
* **Wazuh SIEM**: 4.x (Tested with 4.13.1)

## 3. Phase 1: FreeRADIUS Configuration

This phase focuses on hardening FreeRADIUS network listeners and configuring reliable JSON logging for all authentication outcomes.

### 3.1. Configure Module for JSON Logging (`wazuh_json`)

Define a dedicated `linelog` module instance to format authentication events into JSON objects suitable for Wazuh.

**Action:** Create/Edit the module configuration file.

```bash
sudo nano /etc/freeradius/3.0/mods-available/wazuh_json
````

**Content:** Paste the following configuration.

```text
# FreeRADIUS Linelog Module Instance for Wazuh JSON Output
# File: /etc/freeradius/3.0/mods-available/wazuh_json

linelog wazuh_json {
  filename = /var/log/freeradius/wazuh-radius.json
  permissions = 0640
  format = "{\"event\":\"radius\",\"timestamp\":\"%{%{Event-Timestamp}:-%l}\",\"result\":\"%{%{reply:Packet-Type}:-unknown}\",\"user\":\"%{%{User-Name}:-unknown}\",\"calling_station\":\"%{%{Calling-Station-Id}:-unknown}\",\"called_station\":\"%{%{Called-Station-Id}:-unknown}\",\"nas_ip\":\"%{%{NAS-IP-Address}:-unknown}\",\"nas_identifier\":\"%{%{NAS-Identifier}:-unknown}\",\"service\":\"%{%{Service-Type}:-unknown}\",\"protocol\":\"%{%{Protocol}:-unknown}\",\"auth_type\":\"%{%{Auth-Type}:-none}\",\"reply_message\":\"%{%{Reply-Message}:-none}\",\"error_cause\":\"%{%{Error-Cause}:-none}\"}"
  escape_string = json
}
```

**Action:** Enable the newly defined module.

```bash
sudo ln -sf /etc/freeradius/3.0/mods-available/wazuh_json /etc/freeradius/3.0/mods-enabled/wazuh_json
```

### 3.2. Configure `clients.conf` (Hardening)

Restrict FreeRADIUS to accept connections *only* from the local machine (`127.0.0.1` and `::1`).

**Action:** Edit the clients configuration file.

```bash
sudo nano /etc/freeradius/3.0/clients.conf
```

**Content:** Ensure only localhost clients are defined and active.

```conf
# Define the client connecting from localhost IPv4
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123  # IMPORTANT: Use a strong, unique secret in production!
    require_message_authenticator = no # Often needed for local testing
    nastype = other
}

# Define the client connecting from localhost IPv6
client localhost_ipv6 {
    ipv6addr = ::1
    secret = testing123  # IMPORTANT: Use the same strong secret!
}

# Ensure any default 'client 0.0.0.0/0' or other wide-open clients are REMOVED or COMMENTED OUT.
```

### 3.3. Configure `sites-enabled/default` (Hardening & Critical Reject Fix)

Modify the main virtual server configuration to:
(A) Bind the server's network listeners exclusively to localhost IPs.
(B) Ensure the `wazuh_json` logging module is invoked correctly for *both* `Access-Accept` and `Access-Reject` outcomes.

**Action:** Edit the primary site configuration file.

```bash
sudo nano /etc/freeradius/3.0/sites-available/default # Adjust if using a different site name
```

**Content Modifications:**

**A. Bind Listeners to Localhost:** Locate the `listen` blocks within `server default { ... }`.

```conf
server default {
    # --- Listener Configuration (Hardening) ---
    listen {
        type = auth
        ipaddr = 127.0.0.1      # Listen ONLY on localhost IPv4
        port = 1812
    }
    listen {
        type = acct
        ipaddr = 127.0.0.1      # Listen ONLY on localhost IPv4
        port = 1813
    }
    # IPv6 Listeners (Optional - configure or disable)
    listen {
        type = auth
        ipv6addr = ::1          # Listen ONLY on localhost IPv6
        port = 0                # Set to 0 to disable IPv6 listener
    }
    listen {
        type = acct
        ipv6addr = ::1          # Listen ONLY on localhost IPv6
        port = 0                # Set to 0 to disable IPv6 listener
    }
    # --- End Listener Configuration ---

    # ... (authorize, authenticate, etc. sections remain) ...

    # --- Post-Authentication Logging Configuration (Includes CRITICAL FIX) ---
    post-auth {
        # Log successful authentications (Access-Accept)
        wazuh_json

        # --- Sub-section for handling Access-Reject packets ---
        Post-Auth-Type REJECT {
            # CRITICAL FIX: Explicitly log failed authentications (Access-Reject)
            wazuh_json
        }
        # --- End REJECT sub-section ---
    }
    # --- End Post-Authentication Logging ---

    # ... rest of server configuration ...
} # End server default
```

### 3.4. Set Log File Permissions

Ensure the FreeRADIUS process can write to the log file, and the Wazuh agent user (`wazuh`) can read it.

**Action:** Set ownership and permissions.

```bash
# 1. Ensure the log file exists
sudo touch /var/log/freeradius/wazuh-radius.json
# 2. Set ownership to the FreeRADIUS user and group (usually freerad:freerad)
sudo chown freerad:freerad /var/log/freeradius/wazuh-radius.json
# 3. Set permissions: Owner=rw, Group=r, Other=
sudo chmod 0640 /var/log/freeradius/wazuh-radius.json
# 4. Add the 'wazuh' user to the 'freerad' group for read access
sudo usermod -a -G freerad wazuh
```

### 3.5. Restart FreeRADIUS Service

Apply all configuration changes.

**Action:** Check syntax and restart.

```bash
# 1. Perform a syntax check
sudo freeradius -C
# Look for "Configuration appears to be OK."

# 2. If syntax is OK, restart the service
sudo systemctl restart freeradius.service

# 3. Verify the service started correctly
sudo systemctl status freeradius.service
# Look for "active (running)"
```

## 4\. Phase 2: Wazuh Manager Configuration (JSON)

Configure the Wazuh Manager to collect, automatically decode, and alert on the structured JSON logs.

### 4.1. Configure Log Collection (`ossec.conf`)

Instruct the Wazuh Manager to monitor the FreeRADIUS JSON log file.

**Action:** Add a `<localfile>` block to `/var/ossec/etc/ossec.conf`.

```xml
<ossec_config>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/freeradius/wazuh-radius.json</location>
    <label key="@source">freeradius-json</label> <only-future-events>yes</only-future-events>
  </localfile>

  </ossec_config>
```

### 4.2. Add Custom Rules (`local_rules.xml`)

Define Wazuh rules specifically for the JSON log format produced by the `wazuh_json` module.

**Action:** Add the following rule group to `/var/ossec/etc/rules/local_rules.xml`.

````xml
<group name="local,freeradius,radius,authentication,">

  <rule id="200100" level="0">
    <decoded_as>json</decoded_as>
    <field name="event">radius</field>
    <description>FreeRADIUS: JSON Authentication event received.</description>
  </rule>

  <rule id="200101" level="8">
    <if_sid>200100</if_sid>
    <field name="result">Access-Reject</field>
    <description>FreeRADIUS: Authentication Rejected for user $(user) from client $(calling_station).</description>
    <mitre>
      <id>T1110</id> <id>T1078</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>

  <rule id="200102" level="3">
    <if_sid>200100</if_sid>
    <field name="result">Access-Accept</field>
    <description>FreeRADIUS: Authentication Successful for user $(user) from client $(calling_station).</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>

  <rule id="200103" level="10" frequency="5" timeframe="300" context="correlation">
    <if_matched_sid>200101</if_matched_sid>
    <same_field>calling_station</same_field>
    <description>FreeRADIUS: Multiple authentication failures detected from client $(calling_station). Possible Brute Force attack.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,attack,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,</group>
  </rule>

</group> ```

### 4.3. Restart Wazuh Manager

Apply the Wazuh configuration changes.

**Action:** Validate configuration and restart.

```bash
# 1. Validate Wazuh configuration syntax
sudo /var/ossec/bin/wazuh-analysisd -t -c /var/ossec/etc/ossec.conf
# Look for "Configuration OK"

# 2. If validation passes, restart the Wazuh Manager service
sudo systemctl restart wazuh-manager

# 3. Verify the service started correctly
sudo systemctl status wazuh-manager
# Look for "active (running)"
# Check logs for errors: sudo grep -i -E "error|warning" /var/ossec/logs/ossec.log | tail -n 20
````

## 5\. Phase 3: Validation

Perform end-to-end testing specific to the JSON logging method.

### 5.1. Execute Test Authentications via `radtest`

Use `radtest` on the FreeRADIUS server itself (targeting `127.0.0.1`) to generate authentication events.

**Action:** Run the following commands.

```bash
# 1. Simulate a FAILED login (should trigger Rule 200101)
echo "Sending FAILED authentication request..."
radtest testuser_bad badpassword 127.0.0.1 1812 testing123

# Wait ~5-10 seconds

# 2. Simulate a SUCCESSFUL login (should trigger Rule 200102)
# IMPORTANT: Replace 'gooduser' and 'goodpassword' with ACTUAL valid credentials
# echo "Sending SUCCESSFUL authentication request..."
# radtest gooduser goodpassword 127.0.0.1 1812 testing123

# Wait ~5-10 seconds

# 3. Simulate a BRUTE FORCE attack (should trigger Rule 200103 after 5th failure)
echo "Simulating BRUTE FORCE (sending 6 failed requests)..."
for i in {1..6}; do
  radtest testuser_bad badpassword 127.0.0.1 1812 testing123
  sleep 2 # Short delay
done
```

### 5.2. Monitor Wazuh Alerts

Confirm that the correct alerts are generated in Wazuh.

**Action:** Monitor the `alerts.json` file on the Wazuh Manager.

```bash
# Monitor alerts in real-time, filtering for the FreeRADIUS JSON rules
echo "Monitoring Wazuh alerts for FreeRADIUS JSON events (Ctrl+C to stop)..."
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.id >= 200100 and .rule.id <= 200103)'
```

**Expected Results & Verification:**

1.  **After Failed Login:** An alert with `rule.id: 200101` (Level 8) should appear.
2.  **After Successful Login:** An alert with `rule.id: 200102` (Level 3) should appear.
3.  **After Brute Force Simulation:** After the 5th failure, an alert with `rule.id: 200103` (Level 10) should appear.
4.  **Log File:** `/var/log/freeradius/wazuh-radius.json` should contain JSON entries for each test.

-----

## References

  * Wazuh Documentation - JSON Decoders & Log Collection (`https://documentation.wazuh.com/`)
  * FreeRADIUS Documentation - `rlm_linelog` Module, `sites-available/default`, `clients.conf` (`https://freeradius.org/documentation/`)

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab - Authentication Stack*
