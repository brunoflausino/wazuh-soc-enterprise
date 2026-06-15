# SpiderFoot OSINT → Wazuh SIEM/XDR Integration

**Status:** Complete · Validated · Dashboard published
**Rule range:** `113200–113205` (`spiderfoot_rules.xml`)
**MITRE ATT&CK:** T1589.001, T1589.002, T1590, T1595, T1596 (Reconnaissance tactic)

---

## Overview

Native OSINT correlation pipeline: SpiderFoot findings normalized to JSONL, ingested by Wazuh Logcollector via `log_format=json` localfile, classified by 6 custom detection rules (1 base + 5 child), mapped to MITRE ATT&CK Reconnaissance techniques, and visualized in a 5-panel OpenSearch dashboard.

No custom decoder is required — rules use `<decoded_as>json</decoded_as>` and match on `data.integration: "spiderfoot"`. This deliberately avoids the Wazuh bug where a custom child decoder attached to the built-in `json` parent silently destroys all JSON dynamic fields ([wazuh/wazuh#33798](https://github.com/wazuh/wazuh/issues/33798)).

---

## Architecture

```text
  SpiderFoot OSINT modules
            │
            ▼
   Normalized JSONL events
            │
            ▼
  /var/log/spiderfoot/events.jsonl   (owner: spiderfoot:wazuh, 640)
            │
            ▼  log_format=json localfile
   Wazuh Manager Logcollector
            │
            ▼  built-in JSON decoder
   Custom rules 113200–113205
            │
            ▼
        alerts.json
            │
            ▼
   Wazuh Indexer / OpenSearch
            │
            ▼
  SpiderFoot OSINT Validation Dashboard
```

---

## SpiderFoot Service Configuration

- **Installation path:** `/opt/spiderfoot` (git clone + Python venv)
- **Service user:** `spiderfoot` (dedicated, non-root)
- **Binding:** `127.0.0.1:5002` (loopback only — not exposed to LAN/Internet)
- **Authentication:** HTTP Digest (`/opt/spiderfoot/.spiderfoot/passwd`)
- **systemd unit:** `spiderfoot.service` with `NoNewPrivileges=true`, `PrivateTmp=true`, `Restart=on-failure`
- **JSONL output:** `/var/log/spiderfoot/events.jsonl` (owner `spiderfoot:wazuh`, mode `640`)

---

## Wazuh Configuration

### ossec.conf localfile block

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/spiderfoot/events.jsonl</location>
  <label key="@source">spiderfoot</label>
  <only-future-events>yes</only-future-events>
</localfile>
```

`only-future-events=yes` prevents replay of old JSONL content after Wazuh restarts.

---

## Rule Reference

| Rule ID | Level | Category | MITRE ATT&CK |
|---------|-------|----------|--------------|
| 113200 | 3 | Generic OSINT event (base rule) | — |
| 113201 | 10 | Credential or secret exposure | T1589.001 Credentials |
| 113202 | 6 | Identity / email exposure | T1589.002 Email Addresses |
| 113203 | 5 | Infrastructure intelligence | T1590, T1596 |
| 113204 | 7 | Open technical database finding | T1596 |
| 113205 | 8 | Active reconnaissance / probing | T1595 Active Scanning |

All child rules inherit from `113200` via `<if_sid>`. Classification is driven by a PCRE2 regex on the normalized `event_type` field.

**Rule file:** `/var/ossec/etc/rules/spiderfoot_rules.xml` (owner `root:wazuh`, mode `640`)

---

## Validation Evidence (controlled dataset)

Synthetic events (7 per category, all targeting `example.com`) were appended to the real JSONL file and validated at three layers:

### 1. wazuh-logtest — per-rule validation

All 6 rules individually confirmed via `sudo /var/ossec/bin/wazuh-logtest` with representative JSON events.

### 2. alerts.json — local verification

```bash
sudo jq -c 'select(.data.integration=="spiderfoot") | {rule:.rule.id, lvl:.rule.level, et:.data.event_type}' \
  /var/ossec/logs/alerts/alerts.json | tail -12
```

### 3. OpenSearch DevTools — authoritative aggregations

| Aggregation | Result |
|-------------|--------|
| Total alerts | 42 (7 × 6 rules) |
| Per rule | 113200–113205 each = 7 |
| Per event type | 6 categories each = 7 |
| Per MITRE ID | T1596 = 14 (mapped in 2 rules), others = 7 |
| Per severity | levels 3, 5, 6, 7, 8, 10 each = 7 |

T1596 fires 14 times by design — both the infrastructure-intelligence rule (`113203`) and the open-technical-database rule (`113204`) map to "Search Open Technical Databases".

---

## Dashboard Design

**Dashboard name:** SpiderFoot OSINT Validation Dashboard
**Dashboard-level DQL filter:** `data.integration: "spiderfoot"`

| # | Panel | Type | Aggregation |
|---|-------|------|-------------|
| 1 | SpiderFoot OSINT Alerts Over Time | Vertical bar | Date histogram on `@timestamp` |
| 2 | SpiderFoot Alerts by Detection Rule | Horizontal bar | Filters on `rule.id` per rule |
| 3 | SpiderFoot Alert Severity Distribution | Vertical bar | Filters on `rule.level` per severity |
| 4 | SpiderFoot Findings by Event Type | Vertical bar | Filters on `data.event_type` per category |
| 5 | SpiderFoot Findings Mapped to MITRE ATT&CK | Vertical bar | Terms on `rule.mitre.technique` |

### Dashboard Screenshot

![SpiderFoot OSINT Validation Dashboard](assets/spiderfoot/dashboard-spiderfoot-validation.png)

---

## Security & Privacy Notes

- SpiderFoot Digest credentials (`passwd` file) are **not** committed to this repository
- All validation events target `example.com` (synthetic data)
- Personal OSINT findings from the audit phase are kept separate and never indexed for portfolio use
- No real email addresses, adult-site URLs, or API keys are published

---

## Files in this repository

| Path | Purpose |
|------|---------|
| `integrations/threat-intelligence/spiderfoot-integration.md` | This document |
| `integrations/threat-intelligence/assets/spiderfoot/` | Dashboard screenshot and report PDF |
| `scripts/spiderfoot/` | Operational helper scripts (neutralize Filebeat, ensure rules, logrotate, credentials, ingest & verify) |

---

## Full Methodology

The complete 55-page methodology document covering installation, configuration, rule strategy, per-rule wazuh-logtest validation, OpenSearch DevTools queries, and dashboard panel specifications is available as `assets/spiderfoot/methodology.pdf`.

---

## References

- Parent project: [`wazuh-soc-enterprise`](../../README.md)
- Wazuh JSON decoder bug context: [wazuh/wazuh#33798](https://github.com/wazuh/wazuh/issues/33798)
- SpiderFoot upstream: [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)
- MITRE ATT&CK Reconnaissance tactic: [TA0043](https://attack.mitre.org/tactics/TA0043/)
