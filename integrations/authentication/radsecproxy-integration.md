# radsecproxy Integration with FreeRADIUS & Wazuh

## Overview
**radsecproxy** is a TLS front-end/proxy for RADIUS (RadSec). It terminates TLS from RADIUS clients and forwards the decrypted RADIUS packets to one or more backend RADIUS servers (e.g., FreeRADIUS).  
This guide documents a minimal, production-sane setup used in the Wazuh SOC Enterprise lab: install, TLS, service management, logging, Wazuh ingestion, example rules, validation, and hardening.

---

## Architecture (at a glance)
```

[RADIUS client over TLS]  --2083/TCP-->  [radsecproxy]  --1812/1813-->  [FreeRADIUS]
logs -> journald (or file) -> Wazuh localfile

````

---

## Prerequisites
- Ubuntu 24.04 LTS
- FreeRADIUS reachable on `127.0.0.1:1812` (auth) and `1813` (acct)
- Root/sudo access
- Wazuh Manager with permission to read journald or a log file under `/var/log/radsecproxy/`

---

## Install radsecproxy

### Option A — From package (if available on your distro)
```bash
sudo apt update
sudo apt install -y radsecproxy  # if the package exists in your repo
````

### Option B — From source (portable)

```bash
sudo apt update
sudo apt install -y git make gcc libssl-dev libprotobuf-c-dev protobuf-c-compiler
git clone https://github.com/radsecproxy/radsecproxy.git /tmp/radsecproxy
cd /tmp/radsecproxy
make
sudo make install
# Binary typically at: /usr/local/sbin/radsecproxy
```

---

## TLS materials

Place certificates/keys under `/etc/radsecproxy/`:

```
/etc/radsecproxy/
├── radsecproxy.conf
├── certs/
│   ├── server-cert.pem
│   └── ca.pem
└── private/
    └── server-key.pem
```

Example (self-signed lab certs – replace with real CA-issued certs in production):

```bash
sudo mkdir -p /etc/radsecproxy/{certs,private}
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /etc/radsecproxy/private/server-key.pem \
  -out    /etc/radsecproxy/certs/server-cert.pem \
  -subj "/CN=radsecproxy.local"
sudo cp /etc/ssl/certs/ca-certificates.crt /etc/radsecproxy/certs/ca.pem   # lab: trust system CA bundle
sudo chown -R root:root /etc/radsecproxy
sudo chmod 750 /etc/radsecproxy/private
sudo chmod 640 /etc/radsecproxy/private/server-key.pem
```

---

## Minimal configuration

Create `/etc/radsecproxy/radsecproxy.conf`:

```text
# Listen for RadSec (RADIUS over TLS)
server default {
  listen {
    type = auth
    ipaddr = 0.0.0.0
    port = 2083
    tls {
      cert = /etc/radsecproxy/certs/server-cert.pem
      key  = /etc/radsecproxy/private/server-key.pem
      ca   = /etc/radsecproxy/certs/ca.pem
      clientcert = optional   # set to "required" for mTLS
    }
  }
}

# Backends (plain RADIUS)
targets {
  radius-auth {
    host = 127.0.0.1
    port = 1812
    type = radius
  }
  radius-acct {
    host = 127.0.0.1
    port = 1813
    type = radius
  }
}

# Simple mapping
mappings {
  clientproto     => radius-auth
  accountingproto => radius-acct
}
```

---

## Service management (systemd)

Create `/etc/systemd/system/radsecproxy.service`:

```ini
[Unit]
Description=radsecproxy (RADIUS over TLS proxy)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/radsecproxy -c /etc/radsecproxy/radsecproxy.conf -n
Restart=on-failure
RestartSec=2s
# Log to journald (default). To also write a file, see "File logging" below.
User=root
Group=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now radsecproxy
sudo systemctl status radsecproxy --no-pager
```

### (Optional) File logging with systemd

If you prefer a dedicated log file that Wazuh can tail:

```bash
sudo mkdir -p /var/log/radsecproxy
sudo chown root:wazuh /var/log/radsecproxy
sudo chmod 750 /var/log/radsecproxy
```

Add these lines under `[Service]` in the unit file:

```ini
StandardOutput=append:/var/log/radsecproxy/radsecproxy.log
StandardError=append:/var/log/radsecproxy/radsecproxy.err
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart radsecproxy
```

Logrotate policy `/etc/logrotate.d/radsecproxy`:

```text
/var/log/radsecproxy/*.log /var/log/radsecproxy/*.err {
  daily
  rotate 7
  compress
  missingok
  notifempty
  create 0640 root wazuh
}
```

---

## Wazuh ingestion

### Option 1 — Collect the dedicated file (recommended)

Add to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/radsecproxy/radsecproxy.log</location>
  <only-future-events>yes</only-future-events>
</localfile>
```

### Option 2 — Collect journald

If you keep logs only in journald and your Wazuh version supports journald input:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
  <!-- If your version supports filtering, keep a narrow scope.
       Otherwise, consider using file logging instead of broad journald ingestion. -->
</localfile>
```

Reload Wazuh:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

---

## Example Wazuh rules (local tuning)

Add to `/var/ossec/etc/rules/local_rules.xml` (use non-conflicting IDs):

```xml
<group name="radsecproxy,local,">
  <rule id="111000" level="4">
    <match>New connection from</match>
    <description>radsecproxy: new client connection</description>
    <group>radsecproxy,connection</group>
  </rule>

  <rule id="111001" level="7">
    <match>TLS handshake failed|certificate verify failed|handshake error</match>
    <description>radsecproxy: TLS handshake failure</description>
    <group>radsecproxy,tls,error</group>
  </rule>

  <rule id="111002" level="6">
    <match>Forwarding error|no available backends|failed to send</match>
    <description>radsecproxy: backend forwarding problem</description>
    <group>radsecproxy,backend,error</group>
  </rule>

  <rule id="111010" level="10" frequency="10" timeframe="60">
    <if_matched_sid>111001</if_matched_sid>
    <description>radsecproxy: multiple TLS failures in 60s (possible scan or cert issue)</description>
    <group>radsecproxy,tls,attack</group>
  </rule>
</group>
```

Validate and restart:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

---

## Validation

1. **Service health**

   ```bash
   sudo systemctl status radsecproxy --no-pager
   sudo ss -ntlp | grep 2083   # listening socket
   ```
2. **Basic TLS socket probe (handshake only)**

   ```bash
   openssl s_client -connect 127.0.0.1:2083 -servername radsecproxy.local -quiet </dev/null
   ```

   You should see a successful TLS handshake; errors will be logged by radsecproxy.
3. **Logs reaching Wazuh**

   * File: `sudo tail -n 50 /var/log/radsecproxy/radsecproxy.log`
   * Archives: `sudo grep -n 'radsecproxy' /var/ossec/logs/archives/archives.json | tail`
4. **Rule hits (if any)**

   ```bash
   sudo jq -c 'select((.rule.id|tostring)=="111001" or (.rule.id|tostring)=="111002") |
     {ts:.timestamp, rule:.rule.id, desc:.rule.description, msg:(.full_log // .data // "")}' \
     /var/ossec/logs/alerts/alerts.json | tail
   ```

---

## Troubleshooting

* **Port 2083 not listening**: check unit file path to binary/config and run `sudo journalctl -u radsecproxy -n 200`.
* **TLS errors**: verify key/cert/CA paths and permissions; confirm the client trusts your server CA and (if mTLS) presents a valid cert.
* **No logs in Wazuh**: confirm file path in `ossec.conf`, permissions (`root:wazuh` + `640`), or switch to file logging instead of pure journald.
* **Backend errors**: ensure FreeRADIUS is listening on `127.0.0.1:1812/1813` and not blocked by firewall.

---

## Hardening checklist

* Bind radsecproxy only where needed; prefer firewall ACLs and rate limiting.
* Use **CA-issued certs** and **require client certificates** (`clientcert = required`) when feasible.
* Rotate logs and monitor TLS certificate expiry.
* Keep radsecproxy and OpenSSL up to date.
* Separate duties: radsecproxy for TLS/multiplexing; FreeRADIUS for policy/auth.

---

## Change log (lab)

* Initial version: minimal TLS + backend mapping + Wazuh ingestion (file or journald) + basic rules & validation.

---

### Author

**Bruno Rubens Flausino Teixeira**
Wazuh SOC Enterprise Lab — Authentication Stack
