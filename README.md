<p align="center">
  <img src="assets/wazuh-soc-pipeline.png" alt="Wazuh SOC — detection engineering pipeline" width="100%">
</p>

# 🛡️ Wazuh SOC Enterprise — Detection Engineering Lab

[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.6-3B7DDD)](https://wazuh.com)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange)](https://ubuntu.com)
[![Rules](https://img.shields.io/badge/Custom%20Rules-188-success)](./METRICS.md)
[![Decoders](https://img.shields.io/badge/Custom%20Decoders-51-success)](./METRICS.md)
[![Documented Integrations](https://img.shields.io/badge/Documented%20Integrations-22-green)](./integrations)
[![ATT&CK Coverage](https://img.shields.io/badge/ATT%26CK-coverage%20%2B%20gaps-red)](./detection-coverage/attack-coverage.md)
[![Metrics](https://img.shields.io/badge/metrics-script%20verified-blueviolet)](./METRICS.md)

**Hands-on detection engineering and SOC operations portfolio built on Wazuh SIEM/XDR** — log
source integration, custom rule development, MITRE ATT&CK mapping, alert triage, incident
investigation and response automation, on Ubuntu 24.04 bare metal.

Maintained by **[Bruno Flausino](https://www.linkedin.com/in/brflausino/)**.

---

## Start here — three case studies

If you read nothing else, read these. Each one is end-to-end: ingestion → parsing → rules →
ATT&CK mapping → validation → indexing → dashboard → response.

### 1. 🔥 Suricata inline IPS → Wazuh correlation
**Network detection with active blocking.**

Suricata 8.0.6 in inline IPS mode via NFQUEUE queue 3 with fail-open safety, 7 custom Suricata
rules (SID `2100498–2100504`), 6 Wazuh correlation rules (`113000–113005`) with ATT&CK mapping,
and frequency-based correlation firing on 10+ drops from one source in 60 seconds.

*Why it matters:* an inline IPS is a control, not just a sensor. Getting NFQUEUE persistence
right without breaking UFW is the kind of detail that separates a working deployment from a
tutorial.

📄 **[Read the integration →](integrations/network-security/suricata-integration.md)**

### 2. 🎯 OSINT CDB threat-intelligence correlation
**Native Wazuh threat intel with bidirectional matching.**

609 public IPv4 indicators from AlienVault via FireHOL, normalised and validated into a native
Wazuh CDB list. Rules `113100–113103` correlate on both `srcip` and `dstip`, 6-panel OpenSearch
dashboard, 58 indexed alerts with zero false positives against negative controls.

*Why it matters:* the architecture is native to Wazuh — no external HTTP call during analysis,
so enrichment cannot become a latency or availability dependency in the detection path. The
bidirectional matching is the operationally important part: outbound matches mean something
inside chose that destination.

📄 **[Read the integration →](integrations/threat-intelligence/osint-cdb-integration.md)**

### 3. 🚨 Incident response — from detection chain to client report
**What the alerts actually produce.**

A full SSH compromise chain — brute force → successful authentication → command execution →
payload retrieval — detected end-to-end by chained Cowrie rules (`100501–100508`), written up
as a P1 incident report in client-deliverable format with timeline, impact assessment, response
actions and findings.

*Why it matters:* rules are the input. This is the output.

📄 **[Read INC-0001 →](incident-reports/2026-07-16-INC-0001-ssh-honeypot-compromise.md)**

---

## Capability evidence

| Capability | Primary evidence |
| --- | --- |
| **SIEM engineering** | 188 custom rules, 51 decoders, 14 rule files — [`METRICS.md`](METRICS.md) |
| **Network detection** | [Suricata inline IPS](integrations/network-security/suricata-integration.md) + [Zeek NSM](integrations/network-security/zeek-integration.md) |
| **Threat intelligence** | [Native OSINT CDB](integrations/threat-intelligence/osint-cdb-integration.md) + [MISP](integrations/threat-intelligence/misp-integration.md) + [SpiderFoot](integrations/threat-intelligence/spiderfoot-integration.md) |
| **Alert triage & SOC process** | [L1 triage playbook](playbooks/L1-triage-playbook.md) + [escalation matrix](playbooks/escalation-matrix.md) |
| **Incident response** | [INC-0001 report](incident-reports/) · [Shuffle SOAR](integrations/incident-response/shuffle-integration.md) · Active Response |
| **DFIR** | [Velociraptor](integrations/incident-response/velociraptor-integration.md) |
| **Detection coverage analysis** | [ATT&CK matrix — coverage *and* gaps](detection-coverage/attack-coverage.md) |
| **Validation discipline** | `wazuh-logtest` → `wazuh-analysisd -t` → OpenSearch DevTools → dashboard |
| **Applied ML** | [Honest GNN vs XGBoost benchmark](integrations/ml-research/gnn-vs-tabular-scan-detection.md) — negative result, fully documented |

---

## Repository map

```
├── METRICS.md              Single source of truth for every number quoted anywhere
├── integrations/           22 documented tool integrations across 7 categories
├── playbooks/              L1 triage playbook, L1/L2/L3 escalation matrix
├── incident-reports/       Worked incidents in client-deliverable format
├── detection-coverage/     ATT&CK coverage assessment, including gaps
├── rules/                  Detection rule corpus (see rules/README.md)
└── scripts/                verify-metrics.sh, export-rules.sh, integration tooling
```

**On metrics.** Every figure in this repository is defined once in [`METRICS.md`](METRICS.md) and
checked by [`scripts/verify-metrics.sh`](scripts/verify-metrics.sh), which fails if any document
disagrees. Integration guides record the Wazuh version they were *validated against*, which
deliberately differs from the current lab version — a validation report that claims a version it
was not run against is worthless. The [version policy](METRICS.md#version-policy-for-integration-guides)
explains the convention.

**On honesty.** The [ATT&CK coverage matrix](detection-coverage/attack-coverage.md) documents
14 techniques with no coverage at all, and states that only 6 of 51 assessed techniques have
detection that would resist a competent operator. The [ML benchmark](integrations/ml-research/gnn-vs-tabular-scan-detection.md)
documents a hypothesis that failed. Both are there on purpose: a portfolio that only reports
successes tells a reviewer nothing about judgement.

---

## Integrated security stack — 22 documented

Every tool below ships a markdown guide with configuration, validated `wazuh-logtest` output,
DevTools queries and dashboard screenshots. This table lists **only** what is deployed **and**
documented.

| Category | Tools |
| --- | --- |
| **Core SIEM** | Wazuh Manager, Indexer, Dashboard, Filebeat |
| **Threat Intelligence & Detection** (8) | MISP, OSINT CDB, SpiderFoot, CALDERA, YARA, Falco (eBPF), Cowrie, Auditd |
| **Network Security** (4) | Suricata, Zeek NSM, WireGuard, UFW |
| **Data Protection** (4) | ClamAV, VeraCrypt, NWIPE, Restic |
| **Incident Response & SOAR** (2) | Shuffle SOAR, Velociraptor |
| **Authentication** (2) | FreeRADIUS, Radsecproxy |
| **System Inventory** (1) | OSQuery |
| **Vulnerability Management** (1) | OpenVAS / GVM |

📚 **[Browse the full catalog →](./integrations)** — including the roadmap of integrations
deployed at the Wazuh layer whose guides are still pending, listed separately so the count above
stays trustworthy.

---

## Applied ML research

### GNN vs Gradient Boosting on real Suricata flows (T1046)

**A pre-registered hypothesis that failed, documented in full.**

End-to-end edge-classification pipeline testing whether Graph Neural Networks beat gradient
boosting at detecting Nmap SYN scans, on **~2 million real Suricata flows** collected over 57
days in this lab.

| Best tabular (XGBoost) | Best GNN (E-GraphSAGE) | Δ PR-AUC |
| :---: | :---: | :---: |
| **PR-AUC 0.196** [0.15, 0.26] | PR-AUC 0.093 [0.07, 0.13] | **−0.102** |

The hypothesis — that GNNs should win because scan-vs-benign is a property of a source's
*neighbourhood* rather than of any individual flow — was not supported. Mean and attention
aggregation in E-GraphSAGE/GATv2 mathematically cannot encode node degree (the GIN argument;
Xu et al., 2019), and per-flow edge features already saturate the SYN-scan signature.

Method: Community ID v1 flow keying to deduplicate across rotated logs, temporal 70/15/15 split
with all scalers fit on TRAIN only, imbalance-aware metrics (PR-AUC, MCC, Balanced Accuracy,
TPR@FPR=1%) with 1,000-resample bootstrap CIs, five seeds, degree-stripping ablation, and a
model card for the winning model.

📄 **[Full report →](integrations/ml-research/gnn-vs-tabular-scan-detection.md)**

**Wazuh-side ingestion is deployed** — an 8-rule chain (`100630–100650`) validated with
`wazuh-analysisd -t`. **The detector is not productionised**: it runs as ad-hoc development code
outside this repository, paused until a model beats the tabular baseline.
📄 **[Rule chain →](integrations/ml-research/gnn-security-detector-integration.md)**

### Malware phylogenetics
Maximum Likelihood phylogeny of 18 Mirai variants via IQ-TREE, with cross-validation.
📄 **[Analysis →](integrations/ml-research/malware-phylogenetics/)**

### Local LLM runtime
Ollama via Docker (`wazuh-ollama`) for on-prem experimentation with LLM-assisted log triage. No
security data leaves the lab.

---

## Lab environment

Self-funded single-workstation lab: Ubuntu 24.04 LTS bare metal, Intel i9, 32 GB RAM,
RTX 4070 SUPER 12 GB, one Suricata sensor.

**What this environment cannot demonstrate**, stated plainly rather than left to inference:
enterprise incident volume, multi-client operations, commercial SIEM/EDR platforms, Windows or
cloud or identity telemetry, 24/7 shift operation under real SLA, and cross-environment
validation. The playbooks and coverage assessment are written to production standards, but they
have not been operated under production conditions.

Collaborations, dataset access and critical feedback are welcome.

---

## License

MIT — see [LICENSE](./LICENSE).

---

**Open to opportunities:** SOC Analyst • Cybersecurity Analyst • SIEM Analyst • Detection
Engineer • Threat Hunter — remote Spain/EU, and hybrid or on-site in Alicante, Valencia and
Murcia. Working languages: English, Spanish, Portuguese; German B1.

- LinkedIn: [linkedin.com/in/brflausino](https://www.linkedin.com/in/brflausino/)
- Kaggle: [kaggle.com/brunoflausino](https://www.kaggle.com/brunoflausino) — 18 competitions, 72 public notebooks
