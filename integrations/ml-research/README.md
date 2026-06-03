# 🧪 ML Research — GNN Anomaly Detection

This directory contains the documentation and assets for the **Graph Neural Network (GNN) Anomaly Detection** prototype developed inside the Wazuh SOC Enterprise lab.

## Current Status

| Item | Status |
|------|--------|
| Pipeline validation | ✅ Completed in lab |
| Alerts indexed | 320+ |
| Custom Wazuh rules | 8 rules |
| Dashboard panels | 5 visualizations |
| Technical documentation | ✅ Available |

## What it does

Custom anomaly detector built with **PyTorch + torch_geometric** (GCNConv, SAGEConv, GATConv) combined with **networkx** for graph construction and **IsolationForest** hybrid scoring.

It ingests host, IP and process graphs from Wazuh OpenSearch and targets the following MITRE ATT&CK techniques:

- Scanners (T1046, T1595)
- C2 communication (T1071, T1102)
- High-volume / DDoS traffic (T1498)
- Lateral movement (T1570)

## Productionization Roadmap

| Phase | Objective | Current Status |
|-------|-----------|----------------|
| **1** | Native Wazuh integration (rule emission + JSON feedback loop) | In progress |
| **2** | Advanced feature engineering (temporal features + MITRE context) | Planned |
| **3** | Model improvements + explainability (GNNExplainer / Captum) | Planned |
| **4** | Rigorous evaluation with metrics (Precision, Recall, F1, FP reduction) | Planned |
| **5** | Public Kaggle notebook + enhanced documentation | Planned |
| **6** | Dissemination (LinkedIn post + blog) | Planned |

## Files in this folder

- `gnn-security-detector-integration.md` — Full technical documentation (lab setup, rule chain, validation process, dashboard evidence)
- `assets/` — Dashboard screenshots and visualizations

## Related Links

- **Main portfolio README**: [../../README.md](../../README.md)
- **Kaggle profile**: [kaggle.com/brunoflausino](https://www.kaggle.com/brunoflausino)
- **LinkedIn**: [linkedin.com/in/brflausino](https://www.linkedin.com/in/brflausino/)
