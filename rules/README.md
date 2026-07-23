# Detection Rule Corpus

This directory holds the custom Wazuh rules and decoders authored for this lab, exported from
the live manager and sanitised for publication.

## Why this directory exists

A detection-engineering portfolio is judged on its detections. Screenshots and prose describe
the work; the rule XML *is* the work. Until this directory is populated, every rule and decoder
figure quoted in this repository rests on the author's word rather than on an artifact a
reviewer can read, diff and critique.

That is the single largest remaining gap in this portfolio, and closing it costs one afternoon.

## Populating it

Run [`scripts/export-rules.sh`](../scripts/export-rules.sh) on the Wazuh manager. It copies
`/var/ossec/etc/rules/*.xml` and `/var/ossec/etc/decoders/*.xml` here, redacts host-specific
values, and prints a manual review checklist.

**Nothing in this directory should be pushed without reading the diff first.** The export
script redacts known patterns; it cannot know what is sensitive in a comment you wrote at
02:00. Review every file before committing.

## Layout

```
rules/
├── README.md
├── <NNNNN>-<source>.xml        # one file per log source, prefixed by its ID range
└── ...
decoders/
└── <source>_decoders.xml
```

## Rule ID allocation

Ranges are allocated per source so collisions cannot happen silently. Wazuh reserves
`100000+` for custom rules.

| Range | Source | Status |
| --- | --- | --- |
| `100049–100099` | General / local overrides | Active |
| `100300–100399` | YARA (incl. Active Response `100301`/`100302`) | Active |
| `100500–100599` | Cowrie honeypot | Active |
| `100630–100650` | GNN anomaly ingestion | Active, detector not productionised |
| `100700–100799` | MISP | Active |
| `110700–110799` | Auditd MITRE pack | Active |
| `113000–113099` | Suricata correlation | Active |
| `113100–113199` | OSINT CDB | Active |
| `113200–113299` | SpiderFoot | Active |
| `120000–120099` | GRR, DFIR-IRIS, CAPE, misc JSON | Active, guides pending |

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
