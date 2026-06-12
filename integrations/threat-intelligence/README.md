# Threat Intelligence & Detection - Integrations

This directory documents threat intelligence and detection integrations with Wazuh SIEM for the Wazuh SOC Enterprise lab.

---

## Integrations

| Integration | Version | Status | Rules | Document |
| --- | --- | --- | --- | --- |
| [Auditd](auditd-integration.md) | System auditd | Complete | 110700-110721 | [auditd-integration.md](auditd-integration.md) |
| [MITRE Caldera](caldera-integration.md) | Caldera | Complete | — | [caldera-integration.md](caldera-integration.md) |
| [Cowrie](cowrie-integration.md) | Docker `cowrie/cowrie:latest` | Complete | 100500-100508 | [cowrie-integration.md](cowrie-integration.md) |
| [Falco](falco-integration.md) | Falco 0.43.0 (Modern eBPF) | Complete | 100600-100607 | [falco-integration.md](falco-integration.md) |
| [MISP](misp-integration.md) | Docker (ports 8080/8445) | Complete | 100700-100701, 120030 | [misp-integration.md](misp-integration.md) |
| [YARA](yara-integration.md) | YARA + Active Response | Complete | 100300-100302 | [yara-integration.md](yara-integration.md) |

---

## Cowrie Honeypot - Architecture Overview

```text
[Attacker / SSH or Telnet client]
          |
          | TCP 55222 (SSH) / 55223 (Telnet)
          v
 [Cowrie container - Docker]
          |
          | JSON logs (cowrie.json)
          v
 [Docker volume] -> [/var/log/cowrie.json symlink]
          |
          v
 [Wazuh logcollector]
          |
          | built-in JSON decoder
          v
 [Custom rules 100500-100508]
          |
          v
 [OpenSearch Indexer]
          |
          v
 [Wazuh Dashboard - 10 panels]
```

---

## Cowrie Rule Reference

| Rule ID | Level | Description | MITRE |
| --- | ---: | --- | --- |
| 100500 | 3 | Base rule - any Cowrie event | - |
| 100501 | 6 | New connection to honeypot | T1110 |
| 100502 | 8 | Login failed - brute force attempt | T1110.001 |
| 100503 | 12 | Login success - critical | T1110.001 |
| 100504 | 10 | Command executed in honeypot shell | T1059 |
| 100505 | 14 | Malware download attempt (`wget`, `curl`, `tftp`, `ftpget`) | T1105 |
| 100506 | 5 | Command not found | - |
| 100507 | 3 | Session closed | - |
| 100508 | 6 | SSH client version identified | T1046 |

---

## Cowrie Dashboard Screenshots

Store screenshots inside `assets/cowrie/`.

| File | Panel | Purpose |
| --- | ---: | --- |
| `01-cowrie-alert-volume-timeline-bar.png` | 1 | Vertical bar - Alert volume over time |
| `02-cowrie-honeypot-event-types.png` | 2 | Donut - Event distribution by `data.eventid` |
| `03-cowrie-malware-download-attempts-by-tool.png` | 3 | Horizontal bar - Malware download commands (T1105) |
| `04-cowrie-alerts-by-rule-id.png` | 4 | Horizontal bar - Alerts by rule ID |
| `05-cowrie-alert-severity-levels-by-rule.png` | 5 | Vertical bar - Alert severity distribution |
| `06-cowrie-top-source-ips.png` | 6 | Horizontal bar - Top attacker IPs |
| `07-cowrie-top-commands-executed.png` | 7 | Horizontal bar - Top shell commands |
| `08-cowrie-authentication-outcomes.png` | 8 | Donut - Failed vs successful logins |
| `09-cowrie-mitre-attack-techniques-by-rule.png` | 9 | Donut - MITRE technique distribution |
| `10-cowrie-recent-alert-details-discover.png` | 10 | Discover saved search - Tabular alert details |

---

## Key Technical Notes

- Cowrie logs are JSON and should be collected with `<log_format>json</log_format>` from a stable symlink such as `/var/log/cowrie.json`.
- The integration uses the built-in `json` decoder with `<decoded_as>json</decoded_as>` in rules.
- To keep JSON dynamic fields (`data.eventid`, `data.username`, `data.src_ip`, etc.) available in `alerts.json` and OpenSearch, do **not** use child decoders that inherit from `<parent>json</parent>`.
- Because `wazuh-logtest` is unreliable for JSON field testing in this workflow, the Cowrie rules use `<match>` against the raw JSON string instead of `<field>` conditions.
- Port 55222 (SSH) and 55223 (Telnet) are used because the host public port 22 is allocated to MITRE Caldera.

---

*Prepared for the Wazuh SOC Enterprise repository — Threat Intelligence & Detection integration pack.*
