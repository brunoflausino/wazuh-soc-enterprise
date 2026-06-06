# 🧪 ML Research — GNN vs Tabular Benchmark + Wazuh Ingestion Framework

This directory contains two related artifacts, both documented honestly for what they are:

1. **A rigorous benchmark** on ~2 million real Suricata flows comparing Graph Neural Networks against gradient boosting for Nmap SYN-scan detection (MITRE ATT&CK T1046). **The GNN lost.** The report explains exactly why and why that finding is worth publishing.
2. **A Wazuh ingestion framework** — custom rule chain `100630–100650` plus OpenSearch dashboard scaffold — ready to consume GNN anomaly events from `/var/log/gnn-security/alerts.json`. The plumbing is real, validated, and model-agnostic.

---

## 1. GNN vs Tabular Baselines (T1046) — Headline

| Best tabular (XGBoost) | Best GNN (E-GraphSAGE) | Δ PR-AUC |
| :--------------------: | :--------------------: | :------: |
| **PR-AUC 0.196 [0.15, 0.26]** | PR-AUC 0.093 [0.07, 0.13] | **−0.102** |

- **Data:** ~2,000,000 real Suricata flows, 57 days, single lab environment
- **Labels:** Suricata IPS "Nmap SYN scan" custom rule (weak labels)
- **Split:** temporal 70 / 15 / 15; scalers and node features fit on TRAIN only
- **Metrics:** PR-AUC + MCC + TPR@FPR=1%, with 1,000-resample bootstrap CIs
- **Ablation A** (degree-stripping): `full < stripped` for *every* tabular model — frozen train-window node profiles regress test performance
- **GNN architectures:** E-GraphSAGE via custom `MessagePassing` (mean aggregation, faithful to Lo et al., 2022) + GATv2 with `edge_dim`

**Why the GNN lost:** mean/attention message passing cannot encode node degree (the GIN argument; Xu et al., 2019) — and node degree *is* the scan signal. The four GNN configurations collapsed to near-identical MCC ≈ 0.21, regardless of whether degree features were given or had to be derived. Per-flow edge features already saturate the SYN-scan signature for tree-based models.

📄 **[Read the full report →](./gnn-vs-tabular-scan-detection.md)**

### Operational reading

Best model (XGBoost, stripped) detects **63% of scan flows at 1% false positive rate** (`TPR@FPR=1%` = 0.632 [0.561, 0.724]). Over the 33-day test window's 81,009 benign flows, that is ≈ 25 false alerts/day — a usable triage operating point with the honest caveat that recall is capped and low-and-slow/distributed scans will evade it.

### Reproducibility

- **Hardware:** Ubuntu 24.04, Intel i9 (24 threads), 32 GB RAM, RTX 4070 SUPER (12 GB, sm_89), driver 595.71.05, CUDA 13.2
- **Software:** Python 3.12.3 · PyTorch 2.11.0+cu128 · torch_geometric 2.7.0 · scikit-learn 1.9.0 · xgboost 3.2.0 · pandas 3.0.3 · ijson 3.5.0
- **Seeds:** `[42, 1, 7, 13, 99]` (probability ensemble)
- **Determinism:** global `SEED=42`; temporal split (not random); leakage-controlled feature engineering

---

## 2. GNN → Wazuh Ingestion Framework

Operational plumbing for ingesting GNN anomaly events into the Wazuh SIEM/XDR pipeline.

| Component | Status |
| --- | --- |
| Custom rule chain `100630–100650` | ✅ Deployed and `wazuh-analysisd -t` validated |
| `localfile` JSON ingestion via `/var/log/gnn-security/alerts.json` | ✅ Operational |
| OpenSearch dashboard scaffold | ✅ Documented |
| MITRE ATT&CK mapping (T1046, T1071, T1102, T1498, T1570, T1595) | ✅ Tagged on rules |

The framework is **model-agnostic**. It is ready to consume events from any model emitting the documented JSON schema. The benchmark above shows that — for flow-level SYN-scan detection — XGBoost on per-flow features is currently the better candidate to plug into this pipeline.

📄 **[Integration documentation →](./gnn-security-detector-integration.md)**

---

## Where this could go next

- **Reframe as node-level classification with GIN / sum aggregation** — the single experiment most likely to *confirm* the original hypothesis. Sum aggregation preserves the multiset cardinality that mean / softmax-attention discard.
- **Online structural features** (sliding-window degree, fan-out entropy) replacing the frozen train-window node profile that hurt the tabular `full` variant.
- **Self-supervised structural learning** (Anomal-E; Caville et al., 2022) to reduce reliance on weak supervised labels.
- **Cross-environment validation** — currently out of reach for a self-funded single-workstation lab. Dataset collaborations and broader access are welcome.

---

## Files in this folder

- `gnn-vs-tabular-scan-detection.md` — Full benchmark report (data, methods, results, ablation, discussion, references, model card)
- `gnn-security-detector-integration.md` — Wazuh ingestion framework (rule chain, JSON schema, dashboard)
- `assets/` — Diagrams and dashboard screenshots

---

## Related Links

- **Main portfolio README**: [../../README.md](../../README.md)
- **Kaggle profile**: [kaggle.com/brunoflausino](https://www.kaggle.com/brunoflausino)
- **LinkedIn**: [linkedin.com/in/brflausino](https://www.linkedin.com/in/brflausino/)
