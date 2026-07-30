# Detection Rule Corpus

This directory holds the custom Wazuh rules and decoders authored for this lab, exported from
the live manager and sanitised for publication.

**212 rules across 16 files.** Decoders live in [`../decoders/`](../decoders/) — 49 across 3
files. Totals are verified by [`verify-metrics.sh`](../scripts/verify-metrics.sh) against
[`METRICS.md`](../METRICS.md).

## Why this directory exists

A detection-engineering portfolio is judged on its detections. Screenshots and prose describe
the work; the rule XML *is* the work — readable, diffable and open to critique.

Files were exported from the live manager with [`scripts/export-rules.sh`](../scripts/export-rules.sh),
which redacts internal addresses, credentials, e-mail addresses, MAC addresses and home paths,
then reports anything that looks sensitive for manual review. Wazuh's own shipped rulesets are
excluded; only custom work appears here.

## Rule ID allocation

Ranges are allocated per source so collisions cannot happen silently. Wazuh reserves
`100000+` for custom rules.

| ID range | Source | Rules | File |
| --- | --- | :---: | --- |
| `100000–100007` | Zeek NSM | 8 | [`11000-zeek_rules.xml`](11000-zeek_rules.xml) |
| `100049–113103` | General, Suricata, OSINT CDB, MISP, UFW, WireGuard, VeraCrypt | 68 | [`local_rules.xml`](local_rules.xml) |
| `100205–100209` | OpenVAS / GVM | 5 | [`openvas_rules.xml`](openvas_rules.xml) |
| `100300–100302` | YARA (incl. Active Response) | 3 | [`yara_rules.xml`](yara_rules.xml) |
| `100400–100419` | Velociraptor DFIR | 17 | [`velociraptor_rules.xml`](velociraptor_rules.xml) |
| `100500–100508` | Cowrie honeypot | 9 | [`cowrie_rules.xml`](cowrie_rules.xml) |
| `100600–100607` | Falco (eBPF) | 8 | [`falco_rules.xml`](falco_rules.xml) |
| `100630–100650` | GNN anomaly ingestion | 8 | [`gnn_rules.xml`](gnn_rules.xml) |
| `100660–100668` | Falco tuning | 9 | [`falco_tuning.xml`](falco_tuning.xml) |
| `110000–110005` | Nuclei | 6 | [`nuclei_rules.xml`](nuclei_rules.xml) |
| `110500–110505` | MITRE CALDERA | 6 | [`050-caldera-ttp-marker.xml`](050-caldera-ttp-marker.xml) |
| `110700–110721` | Auditd MITRE pack | 22 | [`110700-auditd-mitre.xml`](110700-auditd-mitre.xml) |
| `110750–110770` | Auditd tuning | 18 | [`110700-auditd-tuning.xml`](110700-auditd-tuning.xml) |
| `113200–113205` | SpiderFoot OSINT | 6 | [`spiderfoot_rules.xml`](spiderfoot_rules.xml) |
| `120000–120064` | GRR, DFIR-IRIS, CAPE, generic JSON | 16 | [`local_rules_json.xml`](local_rules_json.xml) |
| `120200–120202` | HTTP reconnaissance | 3 | [`local_http_recon_rules.xml`](local_http_recon_rules.xml) |
| | **Total** | **212** | **16 files** |

Before adding a rule, check the range is free:

```bash
grep -rhoE '<rule id="[0-9]+"' /var/ossec/etc/rules/*.xml \
  | grep -oE '[0-9]+' | sort -n | uniq -d
```

An empty result means no duplicate IDs. Any output is a collision and must be fixed before
`wazuh-analysisd -t` is trusted — Wazuh will silently prefer one definition.

## Validation gate

No rule reaches this directory, or production, without passing all four stages:

1. `wazuh-logtest` — the rule fires on a real sample of the log line it targets
2. `wazuh-analysisd -t` — the full ruleset still parses with the rule added
3. OpenSearch DevTools — the alert is indexed with the expected fields populated
4. Dashboard — the alert appears in the panel it is meant to feed

A rule that passes 1 and 2 but fails 3 is the most common silent failure: it fires, and nobody
ever sees it.
