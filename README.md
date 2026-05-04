# 🛡️ Wazuh SOC Enterprise — Detection Engineering Lab

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange)](https://ubuntu.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.5-blue)](https://wazuh.com)
[![Rules](https://img.shields.io/badge/Custom%20Rules-168-success)](./integrations)
[![Decoders](https://img.shields.io/badge/Custom%20Decoders-51-success)](./integrations)
[![Documented Integrations](https://img.shields.io/badge/Documented%20Integrations-17-green)](./integrations)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)](./integrations)

## Overview

Production-grade Security Operations Center (SOC) lab on **Ubuntu 24.04 LTS bare metal**, with **Wazuh 4.14.5 SIEM/XDR** as the core. Engineering-driven, hands-on, end-to-end ownership — from data ingestion to dashboard delivery.

Maintained by [Bruno Flausino](https://www.linkedin.com/in/brflausino/) — SOC Engineer, Detection Engineering & SIEM Specialist.

## 🎯 Detection Engineering — by the numbers

| Metric | Value |
| --- | --- |
| Custom rules authored | **168** |
| Custom decoders authored | **51** |
| Rule ID range | `100000 – 120064` |
| Wazuh version | `4.14.5` |
| MITRE ATT&CK techniques referenced (active rules) | T1021, T1046, T1055, T1059, T1070, T1070.006, T1078, T1082, T1083, T1105, T1110, T1110.001, T1119, T1136, T1499, T1543, T1548.001, T1562 |

End-to-end validation pipeline: `wazuh-logtest` → `wazuh-analysisd -t` → OpenSearch DevTools, before any rule reaches production. Disciplined change management: timestamped backups, TimeShift snapshots. English-language documentation for every integration.

## 📊 Integrated Security Stack — 17 Documented

| Category | Tools | Documentation |
| --- | --- | --- |
| **Core SIEM** | Wazuh Manager, Indexer, Dashboard, Filebeat | ✅ Operational |
| **Network Security** | Suricata, Zeek NSM, WireGuard, UFW | ✅ Documented |
| **Threat Intelligence & Detection** | CALDERA, YARA Forge, Falco (eBPF), Cowrie, Auditd | ✅ Documented |
| **Incident Response** | Velociraptor | ✅ Documented |
| **Authentication** | FreeRADIUS, Radsecproxy | ✅ Documented |
| **Vulnerability Management** | OpenVAS / GVM | ✅ Documented |
| **Data Protection** | ClamAV, VeraCrypt, NWIPE, Restic | ✅ Documented |

📚 **[Browse the integrations folder](./integrations)** — each integration ships its own markdown guide and assets.

## 🛠️ Additional Lab Components — documentation in progress

Deployed in the lab; integration guides being added:

- **SOAR & Orchestration**: Shuffle (Docker stack — frontend, backend, opensearch, orborus, Tenzir node)
- **Threat Intel Platforms**: MISP, SpiderFoot
- **DFIR**: GRR Rapid Response, DFIR-IRIS
- **ICS/SCADA Honeypot**: Conpot
- **Vulnerability scanner**: Nuclei

## 🧪 ML Research

### Local LLM runtime — Ollama
Local LLM runtime deployed via Docker (`wazuh-ollama`) for on-prem experimentation with LLM-assisted log triage and alert summarisation. No security data leaves the lab.

### GNN Anomaly Detection Prototype (research stage)
Custom Python anomaly detector (~1,200 lines) using **PyTorch + torch_geometric** (GCNConv / SAGEConv / GATConv) with **networkx** graph construction and **IsolationForest** hybrid scoring. Ingests host/IP/process graphs from Wazuh OpenSearch and targets:

- Scanners (T1046, T1595)
- C2 communication (T1071, T1102)
- High-volume / DDoS traffic (T1498)
- Lateral movement (T1570)

> **Status**: research-stage component. Native Wazuh integration (rule emission + indexed events) is in progress. Code is not yet a production pipeline.

## 🔍 Wireless & Network Security Assessments

The lab is also used for hands-on Wi-Fi and internal network security assessments following **OWASP / NIST SP 800-115 / PTES** methodology:

- Passive 802.11 monitoring (Atheros AR9271, monitor mode)
- Nmap service discovery and OS fingerprinting (`-sV` / `-sC` / `-O`)
- NSE vulnerability scripts
- WPS configuration testing
- RSN / PMF (802.11w) capability analysis
- TLS / SSL and cryptographic review (SHA-1, MD5, certificate validation)

Findings documented as formal security reports.

## 🖥️ System Requirements

- **OS**: Ubuntu 24.04 LTS (bare metal)
- **RAM**: 32 GB minimum (64 GB recommended)
- **CPU**: 8+ cores (16 recommended)
- **Storage**: 500 GB+ SSD
- **Network**: static IP, 1 Gbps+

## 📈 Project Status

- ✅ Core platform deployed and operational on bare metal
- ✅ 168 custom rules + 51 decoders, validated and active
- ✅ 17 integrations fully documented
- 🚧 Documentation rolling out for additional lab components (Shuffle, MISP, SpiderFoot, DFIR-IRIS, GRR, Conpot, Nuclei)
- 🚧 GNN ML prototype — Wazuh native integration pending

## 📄 License

MIT License — see [LICENSE](./LICENSE).

---

**Note**: This is a real, operational SOC lab running on bare metal. Documentation is migrated progressively from internal notes to public guides.
