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
| [OSINT CDB](osint-cdb-integration.md) | AlienVault reputation feed (FireHOL mirror) | Complete | 113100-113103 | [osint-cdb-integration.md](osint-cdb-integration.md) |
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

## OSINT CDB - Architecture Overview

```text
[Public OSINT feed - AlienVault via FireHOL mirror]
          |
          | normalize_osint_ipv4.py (validate, dedupe, drop CIDR/private)
          v
 [/var/ossec/etc/lists/osint/osint_ipv4_reputation]  (609 valid public IPv4)
          |
          | Wazuh compiles
          v
 [osint_ipv4_reputation.cdb]
          |
          | consulted by analysisd at rule-evaluation time
          v
 [Parent rules 113100/113102 (decoded_as=json, noalert)]
          |
          v
 [Child rules 113101 (srcip hit, T1595) / 113103 (dstip hit, T1071)]
          |
          v
 [OpenSearch Indexer]
          |
          v
 [Wazuh Dashboard - 6 panels]
```

---

## OSINT CDB Rule Reference

| Rule ID | Level | Description | MITRE |
| --- | ---: | --- | --- |
| 113100 | 0 | Parent (`noalert`) — JSON source-IP correlation candidate | — |
| 113101 | 12 | Malicious **source** IP detected — `$(srcip)` | T1595 |
| 113102 | 0 | Parent (`noalert`) — JSON destination-IP correlation candidate | — |
| 113103 | 12 | Malicious **destination** IP detected — `$(dstip)` | T1071 |

---

## OSINT CDB Dashboard Screenshots

Store screenshots inside `assets/osint-cdb/`.

| File | Purpose |
| --- | --- |
| `osint-cdb-dashboard-controlled-storm-report.png` | Full dashboard report — 6 panels (Hits over time, Detection-type donut, Threat-category bar, Enriched MITRE bar, Top malicious source IPs, Top malicious destination IPs) under the filter `rule.id:(113101 OR 113103) AND data.event_type:controlled_osint_storm` |

---

## Key Technical Notes

- Cowrie logs are JSON and should be collected with `<log_format>json</log_format>` from a stable symlink such as `/var/log/cowrie.json`.
- The integration uses the built-in `json` decoder with `<decoded_as>json</decoded_as>` in rules.
- To keep JSON dynamic fields (`data.eventid`, `data.username`, `data.src_ip`, etc.) available in `alerts.json` and OpenSearch, do **not** use child decoders that inherit from `<parent>json</parent>`.
- Because `wazuh-logtest` is unreliable for JSON field testing in this workflow, the Cowrie rules use `<match>` against the raw JSON string instead of `<field>` conditions.
- Port 55222 (SSH) and 55223 (Telnet) are used because the host public port 22 is allocated to MITRE Caldera.
- **OSINT CDB:** `srcip` and `dstip` are static IP-typed fields in Wazuh — regex inside `<field name="srcip">` or `<srcip>` is rejected by `wazuh-analysisd -t`. The working pattern is a JSON parent candidate (`decoded_as=json`, `noalert=1`) followed by a child rule using `<list field="srcip|dstip" lookup="address_match_key">…</list>` against the CDB list.
- **OSINT CDB:** the list directory must be `root:wazuh` mode `770` and the source file `root:wazuh` mode `660`; otherwise `analysisd -t` fails to write the compiled `.cdb` artifact.

---

*Prepared for the Wazuh SOC Enterprise repository — Threat Intelligence & Detection integration pack.*
