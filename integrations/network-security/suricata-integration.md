# Suricata IDS/IPS Integration with Wazuh

## Overview

This document describes the full integration of **Suricata 8.0.4** running in **IPS mode** (inline via NFQUEUE) with the **Wazuh 4.14.x SIEM** stack on Ubuntu 24.04 LTS. The pipeline captures network traffic through Netfilter, analyzes it in real-time, drops malicious packets, and forwards alerts to Wazuh for correlation and dashboard visualization.

**Architecture:**
```
Network Traffic → iptables NFQUEUE (queue 3) → Suricata IPS → eve.json
                                                                  ↓
                                              Wazuh Agent (logcollector)
                                                                  ↓
                                              Wazuh Manager (rules 113001-113005)
                                                                  ↓
                                              Wazuh Indexer → Dashboard
```

## Requirements

- Ubuntu 24.04 LTS (kernel 6.17+ with `xt_NFQUEUE` module)
- Wazuh Manager 4.14.x
- Suricata 8.0.4
- UFW (for persistent firewall management)
- `linux-modules-extra-$(uname -r)` package

## 1. Suricata Installation and IPS Configuration

### 1.1 Systemd Service Override

File: `/etc/systemd/system/suricata.service.d/override.conf`

```ini
[Service]
Type=simple
ExecStart=
ExecStart=/usr/bin/suricata -q 3 -c /etc/suricata/suricata.yaml
User=root
Group=root
Restart=on-failure
RestartSec=5s
```

### 1.2 Suricata YAML (NFQUEUE section)

File: `/etc/suricata/suricata.yaml`

```yaml
nfq:
  mode: accept
  queue: 3
  fail-open: yes

stream:
  inline: yes

default-rule-path: /etc/suricata/rules
rule-files:
  - local.rules

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - drop
```

**Critical parameters:**
- `nfq.queue: 3` — must match `-q 3` in systemd override and iptables rules
- `fail-open: yes` — ensures connectivity if Suricata stops (availability over security)
- `stream.inline: yes` — required for IPS mode

### 1.3 Custom IPS Rules

File: `/etc/suricata/rules/local.rules`

```suricata
# Rule 1: Block HTTP responses containing uid=0(root)
drop http any any -> any any (msg:"IPS: Block uid=0(root) in HTTP response"; \
    flow:established,to_client; file_data; content:"uid=0(root)"; sid:2100498; rev:3;)

# Rule 2: Block evil/malicious user-agents
drop http any any -> any any (msg:"IPS: Block evil user-agent"; \
    http.user_agent; content:"evil"; sid:2100500; rev:2;)

# Rule 3: Block .exe downloads via URI
drop http any any -> any any (msg:"IPS: Block EXE download"; \
    http.uri; content:".exe"; sid:2100499; rev:2;)
```

Note: Suricata 8.x requires **dot-notation sticky buffers** (`http.user_agent`, `http.uri`) instead of the legacy `http_user_agent` syntax.

## 2. NFQUEUE Persistence via UFW

**Important:** Do NOT install `iptables-persistent` — it conflicts with and removes UFW. Use `/etc/ufw/before.rules` instead.

File: `/etc/ufw/before.rules` (add before `COMMIT` in `*filter` table)

```
# Suricata IPS - NFQUEUE rules
-I ufw-before-input -j NFQUEUE --queue-num 3 --queue-bypass
-I ufw-before-output -j NFQUEUE --queue-num 3 --queue-bypass

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
```

Apply with:
```bash
sudo ufw reload
```

Verify:
```bash
sudo iptables -L ufw-before-input -n | grep NFQUEUE
sudo cat /proc/net/netfilter/nfnetlink_queue
```

## 3. Wazuh Integration

### 3.1 Log Collection

File: `/var/ossec/etc/ossec.conf`

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

### 3.2 Custom Rules

File: `/var/ossec/etc/rules/suricata_local.xml`

```xml
<group name="suricata,ids,ips,">
  <rule id="113001" level="0">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <description>Suricata alert received</description>
  </rule>

  <rule id="113002" level="10">
    <if_sid>113001</if_sid>
    <field name="alert.action">blocked</field>
    <description>Suricata IPS BLOCKED: $(alert.signature) [$(src_ip) -> $(dest_ip)]</description>
    <group>ips,blocked,attack,</group>
  </rule>

  <rule id="113003" level="8">
    <decoded_as>json</decoded_as>
    <field name="event_type">drop</field>
    <description>Suricata DROP: packet dropped [$(src_ip) -> $(dest_ip)]</description>
    <group>ips,drop,</group>
  </rule>

  <rule id="113004" level="7">
    <if_sid>113001</if_sid>
    <field name="alert.signature">Nmap</field>
    <description>Suricata: Nmap scan detected from $(src_ip)</description>
    <group>recon,scan,</group>
  </rule>

  <rule id="113005" level="12" frequency="10" timeframe="60">
    <if_matched_sid>113002</if_matched_sid>
    <description>Suricata IPS: Multiple blocks from same source - possible attack</description>
    <group>ips,attack,correlation,</group>
  </rule>
</group>
```

## 4. Validation

### 4.1 End-to-End IPS Test

```bash
# This request should be BLOCKED by Suricata (curl will timeout)
curl --max-time 10 -A "evil-bot" http://httpbin.org/user-agent

# Verify alert in Suricata
sudo tail -20 /var/log/suricata/eve.json | \
    python3 -c "import sys,json
for l in sys.stdin:
    e=json.loads(l)
    if e.get('event_type')=='alert':
        print(e['alert']['signature'], '|', e['alert']['action'])"

# Expected output:
# IPS: Block evil user-agent | blocked
```

### 4.2 Wazuh Alert Verification

```bash
sudo tail -50 /var/ossec/logs/alerts/alerts.json | \
    grep -E '"id":"11300[1-5]"'
```

## 5. Troubleshooting

| Symptom | Root Cause | Fix |
|---------|-----------|-----|
| `nf_queue` module not found after kernel update | Missing kernel modules | `sudo apt install --reinstall linux-modules-extra-$(uname -r) && sudo depmod -a` |
| All network traffic slow/frozen | NFQUEUE without `--queue-bypass` | Ensure `--queue-bypass` flag is present |
| `iptables-persistent` removes UFW | Package conflict | Use `/etc/ufw/before.rules` for NFQUEUE rules instead |
| Suricata alerts not reaching Wazuh | Missing `<localfile>` block | Add eve.json to `ossec.conf` |
| Rules fall under generic rule 1002 | Custom rules not loaded | Verify `/var/ossec/etc/rules/suricata_local.xml` exists and restart wazuh-manager |
| `curl` hangs on test | **Expected IPS behavior** — packet dropped | This confirms IPS is working |

## 6. Dashboard Visualizations

The following visualizations were created in the Wazuh Dashboard under `wazuh-alerts-*` index:

- **Suricata Alert Timeline** — Date histogram, `@timestamp` per minute
- **Suricata Alerts by Severity** — Bar chart, `rule.level`
- **Suricata Top Triggered Signatures** — Horizontal bar, `data.alert.signature`
- **Suricata Top Attacker IPs** — Vertical bar, `data.src_ip`
- **Suricata IPS Actions: Blocked vs Allowed** — Donut, `data.alert.action`

Base filter: `rule.groups: suricata`

## References

- [Suricata 8.0 Documentation](https://docs.suricata.io/en/latest/)
- [Wazuh Custom Rules](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [UFW before.rules manual](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html)
