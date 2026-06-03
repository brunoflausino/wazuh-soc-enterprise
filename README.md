# 🛡️ Wazuh SOC Enterprise — Detection Engineering Lab

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange)](https://ubuntu.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.5-blue)](https://wazuh.com)
[![Rules](https://img.shields.io/badge/Custom%20Rules-168-success)](./integrations)
[![Decoders](https://img.shields.io/badge/Custom%20Decoders-51-success)](./integrations)
[![Documented Integrations](https://img.shields.io/badge/Documented%20Integrations-18-green)](./integrations)
[![GNN](https://img.shields.io/badge/GNN-Validated%20Prototype-purple)](./integrations/ml-research)
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

### GNN Anomaly Detection Prototype

**Status**: Documented + Productionization roadmap active

Custom Python anomaly detector (~1,200 lines) using **PyTorch + torch_geometric** (GCNConv / SAGEConv / GATConv) with **networkx** graph construction and **IsolationForest** hybrid scoring. Ingests host/IP/process graphs from Wazuh OpenSearch.

**Targets:**
- Scanners (T1046, T1595)
- C2 communication (T1071, T1102)
- High-volume / DDoS traffic (T1498)
- Lateral movement (T1570)

**Already delivered:**
- Validated pipeline in lab (320+ alerts indexed)
- Chain of 8 custom Wazuh rules
- 5 dashboard panels
- Full technical documentation available

📄 **[See full GNN documentation →](./integrations/ml-research/gnn-security-detector-integration.md)**

> **Next**: Native Wazuh integration (rule emission + indexed events) + public Kaggle notebook in progress.

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
- ✅ **GNN Anomaly Detection** — documented with validated pipeline
- 🚧 Documentation rolling out for additional lab components (Shuffle, MISP, SpiderFoot, DFIR-IRIS, GRR, Conpot, Nuclei)
- 🚀 GNN productionization roadmap active (see `integrations/ml-research/`)

---

## 📄 License

MIT License — see [LICENSE](./LICENSE).

---

**Note**: This is a real, operational SOC lab running on bare metal. Documentation is migrated progressively from internal notes to public guides.

**Open to opportunities**: Detection Engineer • Threat Hunter • SIEM/XDR Engineer (remote-first, EU timezones). Fluent in English, Spanish and Portuguese.

- LinkedIn: [linkedin.com/in/brflausino](https://www.linkedin.com/in/brflausino/)
- Kaggle: [kaggle.com/brunoflausino](https://www.kaggle.com/brunoflausino)
- GitHub: [github.com/brunoflausino/wazuh-soc-enterprise](https://github.com/brunoflausino/wazuh-soc-enterprise)
