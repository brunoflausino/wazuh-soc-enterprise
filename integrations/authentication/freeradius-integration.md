# **FreeRADIUS and Wazuh SIEM Integration**

## **1. Overview**

This guide details the complete methodology for installing and configuring a FreeRADIUS server on Ubuntu 24.04 LTS. The primary security objective is to configure the server to listen only on localhost (127.0.0.1 and ::1), preventing direct exposure.

The second objective is to integrate the FreeRADIUS server with a Wazuh 4.13.1 SIEM for real-time log collection, analysis, and alerting on authentication events. This document provides production-grade decoders and rules designed for robustness and accurate field extraction.

## **2. System Environment**

  * **Operating System:** Ubuntu 24.04 LTS
  * **RADIUS Server:** FreeRADIUS 3.2.5
  * **SIEM:** Wazuh 4.13.1
  * **Authentication (Example):** EAP-TLS

-----

## **3. Part 1: FreeRADIUS Installation and Configuration**

### **3.1 Install FreeRADIUS**

Update package lists and install the FreeRADIUS server.

```bash
sudo apt update
sudo apt install -y freeradius
```

### **3.2 Configure Virtual Server (Bind to Localhost)**

To enhance security, edit the default virtual server to only accept connections from localhost.

**File:** `/etc/freeradius/3.0/sites-enabled/default`

Modify the `listen` blocks to specify `127.0.0.1` and `::1`.

```ini
# FreeRADIUS Default Virtual Server Configuration
server default {
  listen {
    type = auth
    ipaddr = 127.0.0.1
    port = 1812
    limit {
      max_connections = 16
      lifetime = 0
      idle_timeout = 30
    }
  }
  listen {
    type = acct
    ipaddr = 127.0.0.1
    port = 1813
    limit {
      max_connections = 16
      lifetime = 0
      idle_timeout = 30
    }
  }
  listen {
    type = auth
    ipv6addr = ::1 # localhost
    port = 0
    limit {
      max_connections = 16
      lifetime = 0
      idle_timeout = 30
    }
  }
  listen {
    type = acct
    ipv6addr = ::1 # localhost
    port = 0
    limit {
      max_connections = 16
      lifetime = 0
      idle_timeout = 30
    }
  }

# ... (rest of the authorize, authenticate, etc. blocks) ...
```

### **3.3 Configure Localhost Client**

Define `localhost` as a valid RADIUS client, which is necessary for testing and for a local proxy to forward requests to FreeRADIUS.

**File:** `/etc/freeradius/3.0/clients.conf`

```ini
# Defines a RADIUS client
# '127.0.0.1' is another name for 'localhost'
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    nas_type = other
}

client localhost_ipv6 {
    ipv6addr = ::1
    secret = testing123
}
```

### **3.4 Configure EAP-TLS Module**

Configure the EAP module to use EAP-TLS as the default method and specify the paths for your certificates. This example uses the default "snakeoil" certificates for testing.

**File:** `/etc/freeradius/3.0/mods-available/eap`

```ini
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no
    
    # ...

    tls-config tls-common {
        private_key_password = whatever
        private_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
        certificate_file = /etc/ssl/certs/ssl-cert-snakeoil.pem

        # ...
        
        ca_file = /etc/ssl/certs/ca-certificates.crt
        
        # ...
        
        tls_min_version = "1.2"
        tls_max_version = "1.2"
        
        # ...
    }

    tls {
        tls = tls-common
    }
    
    # ... (ttls, peap, mschapv2 sections) ...
}
```

-----

## **4. Part 2: Wazuh Agent Configuration (on FreeRADIUS Server)**

### **4.1 Configure Log Collection**

Configure the Wazuh agent to monitor the FreeRADIUS log files. This includes the standard log, journald entries, and an optional JSON log.

**File:** `/var/ossec/etc/ossec.conf`

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/freeradius/radius.log</location>
</localfile>

<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
  <filter field="SYSLOG_IDENTIFIER">freeradius</filter>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/var/log/freeradius/wazuh-radius.json</location>
</localfile>
```

### **4.2 Set Log Permissions**

The Wazuh agent runs as user `wazuh`. You must grant this user read access to the FreeRADIUS log directory and files.

```bash
sudo chown -R root:wazuh /var/log/freeradius
sudo chmod 750 /var/log/freeradius
sudo chmod g+r /var/log/freeradius/radius.log
sudo chmod g+r /var/log/freeradius/wazuh-radius.json
```

-----

## **5. Part 3: Wazuh Manager Configuration**

These decoders and rules are designed to be robust, correctly identifying the `program_name` from a full syslog event and resiliently parsing MAC addresses that use either hyphens or colons.

### **5.1 Custom Decoders (Production-Grade)**

Save this file on the Wazuh Manager.

**File:** `/var/ossec/etc/decoders/freeradius_decoders.xml`

```xml
<decoder name="freeradius">
  <program_name>freeradius|radiusd</program_name>
</decoder>

<decoder name="freeradius-ok">
  <parent>freeradius</parent>
  <prematch>Login OK: </prematch>
  <regex>Login OK: \[([^\]]+)\] \(from client (\S+) port \d+ cli ([0-9A-Fa-f:-]+)\)</regex>
  <order>username, authenticator, mac_address</order>
</decoder>

<decoder name="freeradius-fail">
  <parent>freeradius</parent>
  <prematch>Login incorrect</prematch>
  <regex>Login incorrect \((\S+)\):.* \[[^\]]+\] \(from client (\S+) port \d+ cli ([0-9A-Fa-f:-]+)\)</regex>
  <order>eap_method, username, authenticator, mac_address</order>
</decoder>
```

### **5.2 Custom Rules (Production-Grade)**

Save this file on the Wazuh Manager. These rules match the decoders above.

**File:** `/var/ossec/etc/rules/freeradius_rules.xml`

```xml
<group name="freeradius, authentication,">

  <rule id="100811" level="3">
    <decoded_as>freeradius-ok</decoded_as>
    <description>FreeRADIUS: User $(username) authenticated successfully from MAC $(mac_address).</description>
    <group>authentication_success,</group>
  </rule>

  <rule id="100812" level="8">
    <decoded_as>freeradius-fail</decoded_as>
    <description>FreeRADIUS: Authentication failure for user $(username) from MAC $(mac_address). EAP-Method: $(eap_method).</description>
    <group>authentication_failed,</group>
  </rule>

</group>
```

### **5.3 Restart Wazuh Manager**

Apply the new decoders and rules by restarting the manager.

```bash
sudo systemctl restart wazuh-manager
```

-----

## **6. Part 4: Validation and Testing**

### **6.1 Check Service Status**

Ensure both FreeRADIUS (on its server) and Wazuh (on the manager) are running.

```bash
sudo systemctl status freeradius
sudo systemctl status wazuh-manager
```

### **6.2 Verify Port Binding**

On the FreeRADIUS server, confirm that the service is *only* listening on localhost ports 1812 and 1813.

```bash
sudo ss -tuln | grep -E '1812|1813'
```

**Expected Output:**

```
udp   UNCONN 0      0      127.0.0.1:1812       0.0.0.0:*
udp   UNCONN 0      0      127.0.0.1:1813       0.0.0.0:*
udp   UNCONN 0      0          [::1]:1812          [::]:*
udp   UNCONN 0      0          [::1]:1813          [::]:*
```

### **6.3 High-Fidelity Log Testing**

The `wazuh-logtest` tool is precise. To ensure accurate testing, you must provide the *full log event* as received by the manager, including the syslog header (timestamp, hostname, program\_name). Using log snippets will cause decoders based on `program_name` to fail.

1.  **Enable Archives:** On the Wazuh Manager, edit `/var/ossec/etc/ossec.conf` and set `<logall_json>yes</logall_json>`.
2.  **Restart Manager:** `sudo systemctl restart wazuh-manager`.
3.  **Trigger Event:** Perform a real login (success and fail) from a client.
4.  **Get Full Log:** On the manager, find the event in the archives:
    `sudo grep -i "freeradius" /var/ossec/logs/archives/archives.json`
5.  **Copy `full_log` Value:** From the JSON object, copy the *entire string* from the `"full_log"` field.

### **6.4 Run wazuh-logtest**

On the Wazuh Manager, start the tool and paste the `full_log` string.

```bash
sudo /var/ossec/bin/wazuh-logtest
```

**Example (Pasting a full "Login OK" log):**

```
Oct 10 00:00:00 flausino freeradius: Auth: (123) Login OK: [user123] (from client mynas port 123 cli aa-bb-cc-dd-ee-ff)
```

**Expected Test Output (Success):**

```
**Phase 1: Completed pre-decoding.
    full event: 'Oct 10 00:00:00 flausino freeradius: Auth: (123) Login OK: [user123] (from client mynas port 123 cli aa-bb-cc-dd-ee-ff)'
    timestamp: 'Oct 10 00:00:00'
    hostname: 'flausino'
    program_name: 'freeradius'

**Phase 2: Completed decoding.
    name: 'freeradius-ok'
    parent: 'freeradius'
    authenticator: 'mynas'
    mac_address: 'aa-bb-cc-dd-ee-ff'
    username: 'user123'

**Phase 3: Completed filtering (rules).
    id: '100811'
    level: '3'
    description: 'FreeRADIUS: User user123 authenticated successfully from MAC aa-bb-cc-dd-ee-ff.'
    groups: '['freeradius', 'authentication', 'authentication_success']'
**Alert to be generated.
```

**Example (Pasting a full "Login incorrect" log):**

```
Oct 10 00:01:00 flausino freeradius: Auth: (124) Login incorrect (mschap): [user456] (from client mynas port 124 cli 11-22-33-44-55-66)
```

**Expected Test Output (Failure):**

```
**Phase 1: Completed pre-decoding.
    full event: 'Oct 10 00:01:00 flausino freeradius: Auth: (124) Login incorrect (mschap): [user456] (from client mynas port 124 cli 11-22-33-44-55-66)'
    timestamp: 'Oct 10 00:01:00'
    hostname: 'flausino'
    program_name: 'freeradius'

**Phase 2: Completed decoding.
    name: 'freeradius-fail'
    parent: 'freeradius'
    authenticator: 'mynas'
    eap_method: 'mschap'
    mac_address: '11-22-33-44-55-66'
    username: 'user456'

**Phase 3: Completed filtering (rules).
    id: '100812'
    level: '8'
    description: 'FreeRADIUS: Authentication failure for user user456 from MAC 11-22-33-44-55-66. EAP-Method: mschap.'
    groups: '['freeradius', 'authentication', 'authentication_failed']'
**Alert to be generated.
```

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab — Threat Intelligence Stack*
