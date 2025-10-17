# FreeRADIUS Integration with Wazuh

## Overview
This document covers the FreeRADIUS server deployment and the methodology used to collect FreeRADIUS telemetry into Wazuh, add decoders & rules, validate the pipeline and harden log handling. This file **only** describes the RADIUS server component (FreeRADIUS) — the TLS proxy (radsecproxy) is documented separately.

---

## Lab environment (validated)
- OS: Ubuntu 24.04 LTS (x86_64)
- FreeRADIUS: 3.x (package install used in lab)
- Wazuh Manager: 4.x (single-node lab)
- Logger, curl, ss, jq available for testing

---

## 1) Goals
- Collect authentication and accounting events from FreeRADIUS into Wazuh.
- Provide structured (best-effort JSON) and plain-text ingestion paths.
- Deploy decoders and rules for success/failure detection.
- Keep log permissions safe and maintainable.

---

## 2) Installation & basic configuration

### Install FreeRADIUS
```bash
sudo apt update
sudo apt install -y freeradius
sudo systemctl enable --now freeradius
sudo systemctl status freeradius
````

### Bind to loopback (recommended)

Edit `/etc/freeradius/3.0/sites-enabled/default` (listener sections) so it listens on `127.0.0.1` (and optionally `::1`) for auth/acct unless external access is required.

### Clients example (`/etc/freeradius/3.0/clients.conf`)

```text
client localhost {
  ipaddr = 127.0.0.1
  secret = testing123
  require_message_authenticator = no
  nas_type = other
}
```

---

## 3) Logging strategy

### Default log locations (lab)

* Plain text: `/var/log/freeradius/radius.log`
* Optionally emit structured JSON to: `/var/log/freeradius/wazuh-radius.json` (via rlm_python/rlm_detail or custom post-auth hook)

### Ensure rotation and permissions

Create a logrotate policy `/etc/logrotate.d/freeradius`:

```text
/var/log/freeradius/*.log {
  weekly
  rotate 12
  compress
  missingok
  notifempty
  create 0640 root wazuh
}
```

Set permissions so Wazuh (group `wazuh`) can read logs:

```bash
sudo chown -R root:wazuh /var/log/freeradius
sudo chmod 750 /var/log/freeradius
sudo chmod g+r /var/log/freeradius/radius.log
```

---

## 4) Wazuh Manager collection (ossec.conf)

Add these `localfile` entries on the Manager:

```xml
<!-- FreeRADIUS plain log -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/freeradius/radius.log</location>
  <only-future-events>no</only-future-events>
</localfile>

<!-- Optional structured JSON log -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/freeradius/wazuh-radius.json</location>
  <label key="@source">freeradius-json</label>
  <only-future-events>yes</only-future-events>
</localfile>
```

After editing, restart Wazuh:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

---

## 5) Example decoders (local_decoder.xml)

Place under `/var/ossec/etc/decoders/local_decoder.xml` (adapt regex to your log format):

```xml
<decoders>
  <decoder name="freeradius-parent">
    <program_name>freeradius|radiusd</program_name>
  </decoder>

  <decoder name="freeradius-auth-ok">
    <parent>freeradius-parent</parent>
    <prematch type="pcre2">Auth:.*Login OK</prematch>
    <regex type="pcre2">
      Auth:\s*\(\d+\)\s*Login OK:\s*\[([^\]]+)\]\s*\(from client\s+(\S+)\)
    </regex>
    <order>username,client</order>
  </decoder>

  <decoder name="freeradius-auth-fail">
    <parent>freeradius-parent</parent>
    <prematch type="pcre2">Auth:.*Login incorrect</prematch>
    <regex type="pcre2">
      Auth:\s*\(\d+\)\s*Login incorrect.*\:\s*\[([^\]]+)\]\s*\(from client\s+(\S+)\)
    </regex>
    <order>username,client</order>
  </decoder>
</decoders>
```

Test with `wazuh-logtest`.

---

## 6) Example rules (local_rules.xml)

Add to `/var/ossec/etc/rules/local_rules.xml`. Choose IDs that don't conflict with your environment.

```xml
<group name="freeradius_auth,">
  <rule id="110010" level="3">
    <if_decoder name="freeradius-auth-ok" />
    <description>RADIUS login OK: $(username) from $(client)</description>
    <group>local,auth,freeradius,authentication_success</group>
  </rule>

  <rule id="110011" level="8">
    <if_decoder name="freeradius-auth-fail" />
    <description>RADIUS login FAIL: $(username) from $(client)</description>
    <group>local,auth,freeradius,authentication_fail</group>
  </rule>
</group>
```

Then:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

---

## 7) Testing & validation

### Simulate log lines (append to radius.log)

```bash
# Success
echo 'Oct 17 00:00:00 hostname freeradius: Auth: (123) Login OK: [user1] (from client localhost)' | sudo tee -a /var/log/freeradius/radius.log

# Failure
echo 'Oct 17 00:00:10 hostname freeradius: Auth: (124) Login incorrect (mschap): [user2] (from client localhost)' | sudo tee -a /var/log/freeradius/radius.log
```

### Verify via logtest

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste the log line above (one line), then Ctrl+D. Confirm the matching rule id.
```

### Verify archives & alerts

```bash
sudo egrep -n "Login OK|Login incorrect" /var/ossec/logs/archives/archives.json | tail -n 10
sudo jq -c 'select(.rule.id=="110010" or .rule.id=="110011")' /var/ossec/logs/alerts/alerts.json | tail -n 20
```

---

## 8) Troubleshooting

* If no events: confirm file path in `ossec.conf` and permissions (`wazuh` group read).
* If decoders fail: use `wazuh-logtest` to inspect decoding stages and refine regex/prematch.
* If `alerts.json` corrupted: extract valid JSON lines to a `.fixed` file as a temporary workaround (small Python snippet can do this).
* If FreeRADIUS not starting: check `sudo journalctl -u freeradius -n 200`.

---

## 9) Hardening & operational notes

* Bind FreeRADIUS to loopback if external access not required.
* Use proper secrets management for shared client secrets; rotate keys periodically.
* If you generate JSON logs from FreeRADIUS, prefer structured fields to make rules robust.
* Keep certs and keys secure if using EAP/TLS.

---

## Author

**Bruno Rubens Flausino Teixeira**
Wazuh SOC Enterprise Lab — Authentication Stack

````

---

## 2) File: `integrations/authentication/radsecproxy-integration.md`
```markdown
# radsecproxy Integration with FreeRADIUS & Wazuh

## Overview
This document focuses on **radsecproxy** — a proxy that provides TLS wrapping for RADIUS (RadSec). radsecproxy is independent from FreeRADIUS and its purpose is to accept RADIUS-over-TLS connections and forward them to one or more backend RADIUS servers (like FreeRADIUS). This file documents radsecproxy deployment, TLS considerations, forwarding configuration, and log integration into Wazuh.

---

## Lab environment (validated)
- OS: Ubuntu 24.04 LTS
- radsecproxy: built from upstream source or installed from package (if available)
- Backends: FreeRADIUS on `127.0.0.1:1812` (auth) and `1813` (acct)
- Wazuh Manager: collects radsecproxy logs (stdout/stderr or file)

---

## 1) What radsecproxy does (summary)
- Terminates TLS for RADIUS client connections (RadSec).
- Validates client certificates (optional) and performs mutual TLS if desired.
- Forwards decrypted RADIUS packets to backend RADIUS servers (UDP/TCP).
- Emits runtime logs (useful for debugging connection/TLS issues).

---

## 2) Installation (from source)
```bash
sudo apt update
sudo apt install -y git make gcc libssl-dev libprotobuf-c-dev protobuf-c-compiler
git clone https://github.com/radsecproxy/radsecproxy.git /tmp/radsecproxy
cd /tmp/radsecproxy
make
sudo make install
# radsecproxy usually installs to /usr/local/sbin/radsecproxy
````

---

## 3) Minimal config example (`/etc/radsecproxy/radsecproxy.conf`)

```text
server default {
  listen {
    type = auth
    ipaddr = 0.0.0.0
    port = 2083
    tls {
      cert = /etc/radsecproxy/certs/server-cert.pem
      key  = /etc/radsecproxy/private/server-key.pem
      ca   = /etc/radsecproxy/certs/ca.pem
      clientcert = optional
    }
  }
}

targets {
  radius-backend {
    host = 127.0.0.1
    port = 1812
    type = radius
  }
  accounting-backend {
    host = 127.0.0.1
    port = 1813
    type = radius
  }
}

mappings {
  clientproto => radius-backend
  accountingproto => accounting-backend
}
```

---

## 4) TLS & certificates

* Prefer CA-signed certificates; for lab testing self-signed certs are acceptable.
* Protect private keys (`chmod 640`, owned by root).
* If mutual TLS is required, set `clientcert = required` and ensure client certs exist and are signed by the configured CA.

---

## 5) Logging & Wazuh collection

radsecproxy usually logs to stdout/stderr. In systemd-managed installations, collect via journald or redirect to a file.

### Journald collection

Ensure Wazuh collects `journald` and filters `SYSLOG_IDENTIFIER` or unit name:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
  <filter field="SYSLOG_IDENTIFIER">radsecproxy</filter>
  <only-future-events>yes</only-future-events>
</localfile>
```

### File logging (alternative)

Configure a systemd service that redirects stdout to a file such as `/var/log/radsecproxy/radsecproxy.log` then configure an ossec `localfile` for that path (syslog or json depending on format).

Permissions:

```bash
sudo mkdir -p /var/log/radsecproxy
sudo chown root:wazuh /var/log/radsecproxy
sudo chmod 750 /var/log/radsecproxy
```

---

## 6) Example Wazuh decoders & rules (recommendation)

Radsecproxy logs typically contain TLS handshake status, client CN, remote IP, and forwarding status. Create lightweight rules to detect:

* TLS handshake failures
* Invalid client certificate attempts
* Backend forwarding errors
* Unexpected rate of connections (possible scanning)

Example rule snippet (place in `local_rules.xml`):

```xml
<group name="radsecproxy,">
  <rule id="111000" level="7">
    <match>TLS handshake failed|handshake error|certificate verify failed</match>
    <description>radsecproxy: TLS handshake failure</description>
    <group>radsecproxy,tls,error</group>
  </rule>

  <rule id="111001" level="6">
    <match>Forwarding error|no available backends|failed to send</match>
    <description>radsecproxy: Forwarding to backend RADIUS failed</description>
    <group>radsecproxy,radsec,backend</group>
  </rule>

  <rule id="111002" level="4">
    <match>New connection from</match>
    <description>radsecproxy: New client connection</description>
    <group>radsecproxy,connection</group>
  </rule>
</group>
```

Test with `wazuh-logtest` using a sample radsecproxy log line.

---

## 7) Testing & validation

1. Start radsecproxy in foreground for debugging:

```bash
sudo /usr/local/sbin/radsecproxy -c /etc/radsecproxy/radsecproxy.conf -n
# or systemctl start radsecproxy
```

2. From a client, attempt a RadSec connection (use radclient variants that support TLS or openssl s_client to test the socket).

3. Confirm logs appear in journald or the configured file and that Wazuh ingests them.

4. Verify alerts in Wazuh for TLS errors or forwarding issues.

---

## 8) Hardening & operational notes

* Do not expose radsecproxy admin/troubleshooting interfaces publicly.
* Place radsecproxy behind a hardened network perimeter (firewall, rate limits).
* Monitor TLS certificate expiry and automate renewal.
* Log retention & rotation: place radsecproxy logs under `/var/log/radsecproxy` and rotate via logrotate. Ensure Wazuh can read rotated files.
* Use client certificate validation for higher assurance (set `clientcert = required`).

---

## 9) Separation of responsibilities

* FreeRADIUS handles authentication/accounting and policy: keep its config and clients.conf separate and apply RADIUS-specific hardening.
* radsecproxy acts as TLS front-end / multiplexer: focus on TLS, certs, rate limiting, and forwarding policies.
* Both produce different types of logs: collect both in Wazuh and tune decoders/rules accordingly.

---

## Author

**Bruno Rubens Flausino Teixeira**
Wazuh SOC Enterprise Lab — Authentication Stack
