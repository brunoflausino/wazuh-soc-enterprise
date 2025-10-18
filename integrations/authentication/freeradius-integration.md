# **FreeRADIUS Authentication Server with Wazuh SIEM Integration**

## **Complete Methodology - Ubuntu 24.04 LTS**

***

## **1. System Environment**

- Operating System: Ubuntu 24.04 LTS
- FreeRADIUS: 3.2.5 (Universe repository)
- Wazuh: Manager, Indexer, Dashboard (bare metal)
- Authentication: EAP-TLS

***

## **2. FreeRADIUS Installation**

```bash
sudo apt update
sudo apt install -y freeradius
```

***

## **3. FreeRADIUS Configuration**

### **3.1 Virtual Server Configuration**

File: `/etc/freeradius/3.0/sites-enabled/default`

```bash
######################################################################
#  FreeRADIUS Default Virtual Server Configuration
######################################################################
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
    ipv6addr = ::1
    port = 0
    limit {
      max_connections = 16
      lifetime = 0
      idle_timeout = 30
    }
  }
  listen {
    type = acct
    ipv6addr = ::1
    port = 0
    limit {
      max_connections = 16
      lifetime = 0
      idle_timeout = 30
    }
  }
  authorize {
    filter_username
    preprocess
    chap
    mschap
    digest
    suffix
    eap {
      ok = return
    }
    files
    expiration
    logintime
    pap
  }
  authenticate {
    Auth-Type PAP {
      pap
    }
    Auth-Type CHAP {
      chap
    }
    Auth-Type MS-CHAP {
      mschap
    }
    mschap
    digest
    eap
  }
  preacct {
    preprocess
    acct_unique
    suffix
    files
  }
  accounting {
    detail
    unix
    exec
    attr_filter.accounting_response
  }
  post-auth {
    wazuh_json
    attr_filter.access_reject
    eap
    remove_reply_message_if_eap
  }
  Post-Auth-Type REJECT {
    wazuh_json
    attr_filter.access_reject
    eap
    remove_reply_message_if_eap
  }
  Post-Auth-Type Challenge { }
  Post-Auth-Type Client-Lost { }
  realm LOCAL { }
}
```

### **3.2 Clients Configuration**

File: `/etc/freeradius/3.0/clients.conf`

```bash
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

### **3.3 EAP Module Configuration**

File: `/etc/freeradius/3.0/mods-available/eap`

```bash
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no
    max_sessions = ${max_requests}
    md5 { }
    gtc { auth_type = PAP }
    tls-config tls-common {
        private_key_password = whatever
        private_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
        certificate_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
        ca_file = /etc/ssl/certs/ca-certificates.crt
        ca_path = ${cadir}
        cipher_list = "DEFAULT"
        cipher_server_preference = no
        tls_min_version = "1.2"
        tls_max_version = "1.2"
        ecdh_curve = ""
        cache {
            enable = no
            lifetime = 24
        }
        verify { }
        ocsp {
            enable = no
            override_cert_url = yes
            url = "http://127.0.0.1/ocsp/"
        }
    }
    tls {
        tls = tls-common
    }
    ttls {
        tls = tls-common
        default_eap_type = md5
        copy_request_to_tunnel = no
        virtual_server = "inner-tunnel"
        use_tunneled_reply = no
    }
    peap {
        tls = tls-common
        default_eap_type = mschapv2
        copy_request_to_tunnel = no
        virtual_server = "inner-tunnel"
        use_tunneled_reply = no
    }
    mschapv2 { }
}
```

***

## **4. Wazuh Agent Configuration**

### **4.1 Agent Configuration File**

File: `/var/ossec/etc/ossec.conf` (on FreeRADIUS server)

```xml
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/freeradius/radius.log</location>
</localfile>

<localfile>
    <log_format>journald</log_format>
    <location>journald</location>
    <filter field="SYSLOG_IDENTIFIER">freeradius</filter>
    <only-future-events>yes</only-future-events>
</localfile>

<localfile>
    <log_format>json</log_format>
    <location>/var/log/freeradius/wazuh-radius.json</location>
    <label key="@source">freeradius-json</label>
    <only-future-events>yes</only-future-events>
</localfile>
```

### **4.2 Log Directory Permissions**

```bash
sudo chown -R root:wazuh /var/log/freeradius
sudo chmod 750 /var/log/freeradius
sudo chmod g+r /var/log/freeradius/radius.log
sudo chmod g+r /var/log/freeradius/wazuh-radius.json
```

***

## **5. Wazuh Manager Configuration**

### **5.1 Custom Decoders**

File: `/var/ossec/etc/decoders/local_decoder.xml` (on Wazuh Manager)

```xml
<!-- Decoders for FreeRADIUS -->
<decoder name="freeradius_auth">
  <prematch>Auth: \((\d+)\)\s+Login OK</prematch>
</decoder>

<decoder name="freeradius_auth_fail">
  <prematch>Auth: \((\d+)\)\s+Login incorrect</prematch>
</decoder>

<decoder name="FREERADIUS_OK">
  <parent>freeradius_auth</parent>
  <regex>Login OK: \[(\S+)\] \(from client (\S+)</regex>
  <order>username, authenticator</order>
</decoder>

<decoder name="FREERADIUS_FAIL">
  <parent>freeradius_auth_fail</parent>
  <regex>Login incorrect \((\S+): .*: \[(\S+)/.* \(from client (\S+)</regex>
  <order>eap_method, username, authenticator</order>
</decoder>
```

### **5.2 Custom Rules**

File: `/var/ossec/etc/rules/local_rules.xml` (on Wazuh Manager)

```xml
<!-- Rules for FreeRADIUS -->
<group name="freeradius_auth,">
  <rule id="100100" level="3">
    <if_sid>5700</if_sid>
    <match>freeradius</match>
    <description>FreeRADIUS authentication event detected.</description>
  </rule>
  
  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <decoded_as>FREERADIUS_OK</decoded_as>
    <description>FreeRADIUS: Successful login for user $(username).</description>
    <group>authentication_success,pci_dss_10.2.5,</group>
  </rule>
  
  <rule id="100102" level="10">
    <if_sid>100100</if_sid>
    <decoded_as>FREERADIUS_FAIL</decoded_as>
    <description>FreeRADIUS: Failed login for user $(username).</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
```

### **5.3 Restart Wazuh Manager**

```bash
sudo systemctl restart wazuh-manager
```

***

## **6. Validation and Testing**

### **6.1 Port Binding Verification**

```bash
sudo ss -tuln | grep -E '1812|1813'
```

Expected output: FreeRADIUS bound to 127.0.0.1:1812 and 127.0.0.1:1813

### **6.2 Decoder Testing**

```bash
echo 'Oct 10 00:00:00 host freeradius: Auth: (123) Login OK: [user123] (from client localhost port 0)' | sudo /var/ossec/bin/wazuh-logtest
```

```bash
echo 'Oct 10 00:01:00 host freeradius: Auth: (124) Login incorrect (mschap): [user456] (from client localhost port 0)' | sudo /var/ossec/bin/wazuh-logtest
```

### **6.3 Service Status**

```bash
sudo systemctl status freeradius wazuh-manager
```

### **6.4 Log Monitoring**

```bash
sudo tail -f /var/log/freeradius/radius.log /var/log/syslog
```

### **6.5 Authentication Test**

```bash
radtest testuser testpassword 127.0.0.1 1812 testing123
```

***

## **7. Verification Results**

- FreeRADIUS service binds to localhost only (127.0.0.1 and ::1)
- EAP-TLS is the default EAP method (TLS 1.2 minimum)
- Snakeoil certificates used for testing (replace with proper CA for production)
- Wazuh agent collects syslog, journald, and JSON-formatted logs
- Log permissions restrict access to root and wazuh group
- Decoders extract username, authenticator, and eap_method fields
- Rules generate alerts for authentication success (100101) and failure (100102)
- Alerts include PCI-DSS compliance tagging (10.2.4, 10.2.5)

***

**END OF METHODOLOGY**

[1](https://www.zerozone.it/cybersecurity/how-to-add-freeradius-logs-in-wazuh-siem/23460)
[2](https://www.linkedin.com/pulse/integrating-freeradius-logs-our-favorite-siem-wazuh-gonzalez-diaz-grggf)
[3](https://wazuh.com/blog/leveraging-artificial-intelligence-for-threat-hunting-in-wazuh/)
[4](https://www.miniorange.com/iam/integrations/wazuh-siem-integration)
[5](https://www.scribd.com/document/758834969/Lab-14-Wazuh-pfsense-firewall-integration)
[6](https://techjunction.co/download/practical-guide-to-wazuh-siem-windows-active-directory-for-it-security-professionals/)
[7](https://kifarunix.com/install-freeradius-with-daloradius-on-debian-9/)
