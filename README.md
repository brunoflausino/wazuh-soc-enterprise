# 🛡️ Wazuh SOC Enterprise — Detection Engineering Lab

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange)](https://ubuntu.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.5-blue)](https://wazuh.com)
[![Rules](https://img.shields.io/badge/Custom%20Rules-188-success)](./integrations)
[![Decoders](https://img.shields.io/badge/Custom%20Decoders-51-success)](./integrations)
[![Documented Integrations](https://img.shields.io/badge/Documented%20Integrations-22-green)](./integrations)
[![ML Research](https://img.shields.io/badge/ML%20Research-Honest%20Benchmark-purple)](./integrations/ml-research)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)](./integrations)

## Overview

Production-grade Security Operations Center (SOC) lab on **Ubuntu 24.04 LTS bare metal**, with **Wazuh 4.14.5 SIEM/XDR** as the core. Engineering-driven, hands-on, end-to-end ownership — from data ingestion to dashboard delivery.

Maintained by [Bruno Flausino](https://www.linkedin.com/in/brflausino/) — SOC Engineer, Detection Engineering & SIEM Specialist.

**Kaggle:** [kaggle.com/brunoflausino](https://www.kaggle.com/brunoflausino) (18 competitions • 72 public notebooks)

---

## 🎯 Detection Engineering — by the numbers

| Metric | Value |
| --- | --- |
| Custom rules authored | **188** (across 14 active files in `/var/ossec/etc/rules/`) |
| Custom decoders authored | **51** |
| Rule ID range | `100049 – 120064` |
| Wazuh version | `4.14.5` |
| MITRE ATT&CK techniques referenced (active rules) | T1021, T1046, T1055, T1059, T1070, T1070.006, T1071, T1078, T1082, T1083, T1105, T1110, T1110.001, T1119, T1136, T1499, T1543, T1548.001, T1562, T1589.001, T1589.002, T1590, T1595, T1596 |

End-to-end validation pipeline: `wazuh-logtest` → `wazuh-analysisd -t` → OpenSearch DevTools, before any rule reaches production. Disciplined change management: timestamped backups, TimeShift snapshots. English-language documentation for every integration.

---

## 📊 Integrated Security Stack — 22 Documented

Every tool below ships its own markdown guide with configuration, validated `wazuh-logtest` output, and dashboard screenshots. This table lists **only** what is actually deployed **and** documented.

| Category | Tools | Documentation |
| --- | --- | --- |
| **Core SIEM** | Wazuh Manager, Indexer, Dashboard, Filebeat | ✅ Operational |
| **Network Security** | Suricata, Zeek NSM, WireGuard, UFW | ✅ Documented |
| **Threat Intelligence & Detection** | MISP, OSINT CDB (AlienVault/FireHOL), SpiderFoot OSINT, CALDERA, YARA, Falco (eBPF), Cowrie, Auditd | ✅ Documented |
| **Incident Response & SOAR** | Velociraptor, Shuffle SOAR | ✅ Documented |
| **System Inventory** | OSQuery | ✅ Documented |
| **Authentication** | FreeRADIUS, Radsecproxy | ✅ Documented |
| **Vulnerability Management** | OpenVAS / GVM | ✅ Documented |
| **Data Protection** | ClamAV, VeraCrypt, NWIPE, Restic | ✅ Documented |

📚 **[Browse the integrations folder](./integrations)** — each integration ships its own markdown guide and assets.

### Latest dashboard evidence — SpiderFoot OSINT

![SpiderFoot OSINT Validation Dashboard](./integrations/threat-intelligence/assets/spiderfoot/dashboard-spiderfoot-validation.png)

The newest documented Threat Intelligence integration is a native SpiderFoot OSINT pipeline: JSONL ingestion through Wazuh `log_format=json`, custom rules `113200–113205`, MITRE ATT&CK reconnaissance mapping, 42 controlled indexed validation alerts, and a 5-panel OpenSearch dashboard.

---

## 🗺️ Roadmap — not part of the documented count above

Listed separately and honestly so the table above stays trustworthy. Verified against the live `/var/ossec/etc/rules/` and `ossec.conf` on 2026-06-12.

**Wazuh-side integration deployed, public guide pending:**
- **GRR Rapid Response** — rules `120000–120003` in `local_rules_json.xml`; localfile `/var/log/grr/hunt-events.json` configured. Awaiting a written guide.
- **Nuclei** — `nuclei_rules.xml` (6 rules); localfile `/opt/nuclei-scans/logs/nuclei.jsonl` configured. Awaiting a written guide.
- **Auditd MITRE pack** — `110700-auditd-mitre.xml` (22 rules) ships alongside the existing Auditd guide and could be promoted to its own section.
- **CAPE Sandbox** — rule `120050` in `local_rules_json.xml`; localfile `/var/log/cape/events.log` configured. Awaiting a guide.
- **DFIR-IRIS** — inbound rule `120040` defined; outbound `custom-wazuh_iris.py` integration block is **currently commented out** in `ossec.conf`. Decide whether to re-enable then document.
- **OpenCanary** — localfile `/var/tmp/opencanary.log` configured; no custom rules. Decide whether to add rules + a guide or remove the localfile.

---

## 🧪 ML Research

### Local LLM runtime — Ollama

Local LLM runtime deployed via Docker (`wazuh-ollama`) for on-prem experimentation with LLM-assisted log triage and alert summarisation. No security data leaves the lab.

### GNN vs Gradient Boosting — Honest Benchmark on Real Suricata Flows (T1046)

**Status:** Benchmark complete · negative result, rigorously documented.

End-to-end edge-classification pipeline to test whether Graph Neural Networks (GNNs) beat gradient boosting at detecting **Nmap SYN scans** (MITRE ATT&CK T1046), on **~2 million real Suricata flows** collected over 57 days in this lab.

**Pre-registered hypothesis** — that GNNs should win because scan-vs-benign is determined by a source's *neighborhood* (fan-out to many destinations) and not by any individual flow — **was not supported**:

| Best tabular (XGBoost) | Best GNN (E-GraphSAGE) | Δ PR-AUC |
| :--------------------: | :--------------------: | :------: |
| **PR-AUC 0.196 [0.15, 0.26]** | PR-AUC 0.093 [0.07, 0.13] | **−0.102** |

**Why** — mean/attention aggregation in E-GraphSAGE / GATv2 mathematically cannot encode node degree (the GIN argument; Xu et al., 2019). Even with the GNN's structural advantage (transductive message passing over the full graph, including test-time edges), per-flow edge features already saturate the SYN-scan signature for XGBoost. A degree-stripping ablation also showed train-window node profiles do *not* transfer across a temporal split.

What the work documents:

- Resilient ingestion of 8 rotated `eve.json` files (4.4 GB, ~2 M flows; 2 malformed lines skipped over the entire corpus)
- **Community ID v1** flow keying to deduplicate across rotated logs (Suricata's `flow_id` is a reused memory address — OISF Redmine #1696)
- Temporal 70 / 15 / 15 split; all scalers and node features fit on TRAIN only
- Imbalance-aware metrics — **PR-AUC, MCC, Balanced Accuracy, TPR@FPR=1%** — with 1,000-resample bootstrap 95% CIs
- Two model families (E-GraphSAGE via custom `MessagePassing`, GATv2 with `edge_dim`) over five seeds with ensembled probabilities
- Honest discussion of limitations, expected follow-ups, and a model card (Mitchell et al., 2019) for the winning model

📄 **[Full report → integrations/ml-research/gnn-vs-tabular-scan-detection.md](./integrations/ml-research/gnn-vs-tabular-scan-detection.md)**

### GNN → Wazuh Ingestion — deployed at Wazuh layer

A Wazuh rule chain and dashboard scaffold ingest GNN-style anomaly events from `/var/log/gnn-security/alerts.json` (configured as a `localfile` in `ossec.conf`). The 8-rule chain is live in `/var/ossec/etc/rules/gnn_rules.xml`:

| Rule | Level | Detection type | MITRE |
|---|---|---|---|
| `100630` | 0 | base (no-alert) | — |
| `100631` | 10 | potential network scanner | T1046, T1595 |
| `100632` | 12 | potential C2 server | T1071, T1102, T1573 |
| `100633` | 11 | high-severity source IP | T1059 |
| `100634` | 9 | high-volume anomalous traffic | T1498 |
| `100635` | 8 | suspicious communication pattern | T1570 |
| `100640` | 14 | severe anomaly (gnn_score ≤ −0.7) | T1570, T1021 |
| `100650` | 13 | repeated anomalies, same src_ip in 1h | T1595 |

**What is deployed:** the Wazuh-side ingestion, classification and alerting path. Rule chain validated with `wazuh-analysisd -t`.
**What is not yet productionised:** the GNN detector itself runs as ad-hoc development code (outside this repo), not as a persistent service writing to the watched file. The benchmark above showed the underlying model has not yet beaten the tabular baseline, so promoting the detector to a service is paused pending model work.

📄 **[Rule-chain details → integrations/ml-research/gnn-security-detector-integration.md](./integrations/ml-research/gnn-security-detector-integration.md)**

### Note on resources

This is a **self-funded, single-workstation lab** (Ubuntu 24.04, Intel i9, 32 GB RAM, RTX 4070 SUPER 12 GB, one Suricata sensor). Cross-environment validation, large-scale GIN / sum-aggregation training, multi-vendor dataset replication and longer time horizons are out of reach for a one-person setup. Collaborations, dataset access and feedback are very welcome.

---

## 🔍 Wireless & Network Security Assessments

The lab is also used for hands-on Wi-Fi and internal network security assessments following **OWASP / NIST SP 800-115 / PTES** methodology.

Findings documented as formal security reports.

---

## 🖥️ System Requirements

- **OS**: Ubuntu 24.04 LTS (bare metal)
- **RAM**: 32 GB minimum (64 GB recommended)
- **CPU**: 8+ cores (16 recommended)
- **Storage**: 500 GB+ SSD
- **Network**: static IP, 1 Gbps+

---

## 📈 Project Status

- ✅ Core platform deployed and operational on bare metal
- ✅ **188 custom rules + 51 decoders**, validated and active across 14 rule files
- ✅ **22 integrations fully documented** (incl. Shuffle SOAR, native OSINT CDB, and SpiderFoot OSINT)
- ✅ **OSINT CDB threat intelligence** — native Wazuh CDB list (609 public IPv4 indicators from AlienVault via FireHOL), rules `113100–113103`, bidirectional `srcip`/`dstip` correlation, 6-panel OpenSearch dashboard, 58 indexed storm alerts with zero false positives on negative controls
- ✅ **SpiderFoot OSINT correlation** — native SpiderFoot service bound to `127.0.0.1:5002`, JSONL ingestion from `/var/log/spiderfoot/events.jsonl`, rules `113200–113205`, no custom decoder, per-rule `wazuh-logtest` validation, 42 indexed controlled alerts, and a 5-panel OpenSearch dashboard
- ✅ **GNN-vs-tabular benchmark on real Suricata flows** — complete, honestly documented
- ✅ **GNN → Wazuh ingestion** deployed at the Wazuh layer (rules `100630–100650`); detector itself remains dev-only, awaiting a model that beats the tabular baseline
- ✅ Active Response live for `firewall-drop` (rule `5763`) and `yara_linux` (rules `100301/100302`)
- 🚧 Guides pending for several Wazuh-side-deployed integrations: **GRR**, **Nuclei**, **CAPE**, **DFIR-IRIS** (inbound), **OpenCanary**, and the **Auditd-MITRE** rule pack

---

## 📄 License

MIT License — see [LICENSE](./LICENSE).

---

**Note**: This is a real, operational SOC lab running on bare metal. Documentation is migrated progressively from internal notes to public guides.

**Open to opportunities**: Detection Engineer • Threat Hunter • SIEM/XDR Engineer (remote-first, EU timezones). Fluent in English, Spanish and Portuguese.

- LinkedIn: [linkedin.com/in/brflausino](https://www.linkedin.com/in/brflausino/)
- Kaggle: [kaggle.com/brunoflausino](https://www.kaggle.com/brunoflausino)
- GitHub: [github.com/brunoflausino/wazuh-soc-enterprise](https://github.com/brunoflausino/wazuh-soc-enterprise)
