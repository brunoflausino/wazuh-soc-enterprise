# Cowrie Honeypot - Integrations

This directory documents the Cowrie SSH/Telnet honeypot integration with Wazuh SIEM for the Wazuh SOC Enterprise lab.

---

## Integration

| Integration | Version | Status | Rules | Document |
| --- | --- | --- | --- | --- |
| [Cowrie](cowrie-integration.md) | Docker image `cowrie/cowrie:latest` | Complete | 100500-100508 | [cowrie-integration.md](cowrie-integration.md) |

---

## Architecture Overview

```text
[Attacker / SSH or Telnet client]
          |
          | TCP 2224 (SSH) / 2225 (Telnet)
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
 [Wazuh Dashboard]
```

---

## Rule Reference

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

## Expected Assets

Store screenshots inside `assets/cowrie/`.

### Core screenshots

| File | Purpose |
| --- | --- |
| `cowrie-activity-timeline.png` | Line chart - Honeypot activity timeline |
| `cowrie-event-distribution.png` | Pie / donut - Event distribution by `data.eventid` |
| `cowrie-alert-severity-distribution.png` | Vertical bar - Alert severity distribution |
| `cowrie-usernames-attacked.png` | Pie - Attacked usernames |
| `cowrie-mitre-techniques.png` | Pie - MITRE ATT&CK techniques |
| `cowrie-alerts-by-rule.png` | Horizontal bar - Alerts by rule |
| `cowrie-mitre-tactics.png` | Horizontal bar - MITRE ATT&CK tactics |
| `cowrie-alert-details.png` | Data table - Recent alert details |

### Supporting screenshots

| File | Purpose |
| --- | --- |
| `cowrie-dashboard-full.png` | Full dashboard view |
| `cowrie-devtools-verification.png` | Dev Tools query / aggregation verification |

---

## Key Technical Notes

- Cowrie logs are JSON and should be collected with `<log_format>json</log_format>` from a stable symlink such as `/var/log/cowrie.json`.
- The integration uses the built-in `json` decoder with `<decoded_as>json</decoded_as>` in rules.
- To keep JSON dynamic fields (`data.eventid`, `data.username`, `data.src_ip`, etc.) available in `alerts.json` and OpenSearch, do **not** use child decoders that inherit from `<parent>json</parent>`.
- Because `wazuh-logtest` is unreliable for JSON field testing in this workflow, the Cowrie rules use `<match>` against the raw JSON string instead of `<field>` conditions.

---

*Prepared for the Wazuh SOC Enterprise repository - Cowrie honeypot integration pack.*
