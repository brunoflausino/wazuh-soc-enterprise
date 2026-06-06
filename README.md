# 🛡️ Wazuh SOC Enterprise — Detection Engineering Lab

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange)](https://ubuntu.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.5-blue)](https://wazuh.com)
[![Rules](https://img.shields.io/badge/Custom%20Rules-168-success)](./integrations)
[![Decoders](https://img.shields.io/badge/Custom%20Decoders-51-success)](./integrations)
[![Documented Integrations](https://img.shields.io/badge/Documented%20Integrations-18-green)](./integrations)
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
| Custom rules authored | **168** |
| Custom decoders authored | **51** |
| Rule ID range | `100000 – 120064` |
| Wazuh version | `4.14.5` |
| MITRE ATT&CK techniques referenced (active rules) | T1021, T1046, T1055, T1059, T1070, T1070.006, T1078, T1082, T1083, T1105, T1110, T1110.001, T1119, T1136, T1499, T1543, T1548.001, T1562 |

End-to-end validation pipeline: `wazuh-logtest` → `wazuh-analysisd -t` → OpenSearch DevTools, before any rule reaches production. Disciplined change management: timestamped backups, TimeShift snapshots. English-language documentation for every integration.

---

## 📊 Integrated Security Stack — 18 Documented

| Category | Tools | Documentation |
| --- | --- | --- |
| **Core SIEM** | Wazuh Manager, Indexer, Dashboard, Filebeat | ✅ Operational |
| **Network Security** | Suricata, Zeek NSM, WireGuard, UFW | ✅ Documented |
| **Threat Intelligence & Detection** | CALDERA, YARA Forge, Falco (eBPF), Cowrie, Auditd | ✅ Documented |
| **Incident Response** | Velociraptor | ✅ Documented |
| **System Inventory** | OSQuery | ✅ Documented |
| **Authentication** | FreeRADIUS, Radsecproxy | ✅ Documented |
| **Vulnerability Management** | OpenVAS / GVM | ✅ Documented |
| **Data Protection** | ClamAV, VeraCrypt, NWIPE, Restic | ✅ Documented |

📚 **[Browse the integrations folder](./integrations)** — each integration ships its own markdown guide and assets.

---

## 🛠️ Additional Lab Components — documentation in progress

Deployed in the lab; integration guides being added:

- **SOAR & Orchestration**: Shuffle (Docker stack)
- **Threat Intel Platforms**: MISP, SpiderFoot
- **DFIR**: GRR Rapid Response, DFIR-IRIS
- **ICS/SCADA Honeypot**: Conpot
- **Vulnerability scanner**: Nuclei

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

### GNN → Wazuh Ingestion Framework (rules 100630–100650)

A separate, working artifact: a Wazuh rule chain and OpenSearch dashboard scaffold that parse, classify and alert on GNN anomaly events written as JSON to `localfile`. The plumbing is real and `wazuh-analysisd -t` / `wazuh-logtest` validated; it is now waiting on a model that beats the tabular baseline above.

📄 **[Ingestion framework → integrations/ml-research/gnn-security-detector-integration.md](./integrations/ml-research/gnn-security-detector-integration.md)**

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
- ✅ 168 custom rules + 51 decoders, validated and active
- ✅ 18 integrations fully documented
- ✅ **GNN-vs-tabular benchmark on real Suricata flows** — complete, honestly documented
- ✅ **GNN → Wazuh ingestion framework** (rules `100630–100650`) — operational, model-agnostic, awaiting a model that beats the tabular baseline
- 🚧 Documentation rolling out for additional lab components (Shuffle, MISP, SpiderFoot, DFIR-IRIS, GRR, Conpot, Nuclei)

---

## 📄 License

MIT License — see [LICENSE](./LICENSE).

---

**Note**: This is a real, operational SOC lab running on bare metal. Documentation is migrated progressively from internal notes to public guides.

**Open to opportunities**: Detection Engineer • Threat Hunter • SIEM/XDR Engineer (remote-first, EU timezones). Fluent in English, Spanish and Portuguese.

- LinkedIn: [linkedin.com/in/brflausino](https://www.linkedin.com/in/brflausino/)
- Kaggle: [kaggle.com/brunoflausino](https://www.kaggle.com/brunoflausino)
- GitHub: [github.com/brunoflausino/wazuh-soc-enterprise](https://github.com/brunoflausino/wazuh-soc-enterprise)
