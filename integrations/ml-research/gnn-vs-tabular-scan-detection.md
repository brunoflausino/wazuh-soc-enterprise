<!-- soc-banner -->
<p align="center"><img src="assets/banners/banner-gnn-vs-tabular-scan-detection.svg" alt="GNN vs XGBoost — Wazuh SOC" width="100%"></p>

<p align="center">
<img src="https://img.shields.io/badge/GNN%20vs%20XGBoost-benchmark-c026d3?style=for-the-badge&logo=gnn-vs-tabular-scan-detection&logoColor=white" alt="GNN vs XGBoost"> <img src="https://img.shields.io/badge/Wazuh-4.14.5-3B7DDD?style=for-the-badge" alt="Wazuh"> <img src="https://img.shields.io/badge/status-validated-2ea44f?style=for-the-badge" alt="Status"> <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1046-E23E3E?style=for-the-badge" alt="MITRE">
</p>

# Do Graph Neural Networks Beat Gradient Boosting for Network Scan Detection?

### A rigorous negative result on ~2M real Suricata flows (MITRE ATT&CK T1046)

**Author:** Bruno Flausino
**Date:** 2026-06-06
**Environment:** bare-metal Wazuh 4.14.x SOC lab (`wazuh-soc-enterprise`) + RTX 4070 SUPER
**Status:** complete — single benchmark, honestly reported

---

## TL;DR

I built an edge-classification pipeline to test a specific, pre-registered hypothesis: that
Graph Neural Networks (GNNs) should outperform tabular models at detecting Nmap SYN scans,
because the discriminative signal of a scan (one source fanning out to many destinations) is a
**neighborhood property**, not a property of any single flow.

On **~2 million real Suricata flows** collected over 57 days in a live lab, with proper
imbalance-aware metrics and bootstrap confidence intervals, **the hypothesis did not hold.**
A plain gradient-boosted tree (XGBoost) on per-flow features was the best model by a wide margin:

| Best tabular (XGBoost) | Best GNN (E-GraphSAGE) | Delta PR-AUC |
| :--------------------: | :--------------------: | :------: |
| **PR-AUC 0.196** | PR-AUC 0.093 | **-0.102** |

This is not a tooling failure. It is a finding: **at flow-level granularity, the SYN-scan
signature is already linearly/tree-separable from per-flow features, and the message-passing
architectures tested (mean-aggregation E-GraphSAGE, attention-based GATv2) add no value — they
in fact regress.** The result reproduces the difficult side of the published GNN-NIDS literature
and is consistent with the theory of why mean/attention aggregation cannot encode node degree.

The repository documents the full pipeline (corpus ingestion, cleaning, graph construction,
temporal benchmark, ablations) as a worked example of doing this kind of comparison honestly.

---

## 1. Motivation and hypothesis

**Threat model.** MITRE ATT&CK **T1046 — Network Service Discovery**. An attacker performing a
horizontal Nmap SYN scan sends SYN packets to many hosts/ports from a single source, producing a
characteristic *fan-out*: high out-degree, low reciprocity, high destination-port entropy.

**Pre-registered hypothesis (either outcome is informative):**

> Because scan-vs-benign is determined by the *neighborhood* of the source node and not by any
> individual flow, a GNN that aggregates over a node's neighborhood should detect scans better
> than a tabular model that sees one flow at a time.
>
> - **GNN > tabular** = structural advantage demonstrated.
> - **GNN = tabular** = honest finding that per-flow features suffice for this signature.

The benchmark was designed so that *both* outcomes are publishable. This report documents the
second outcome — and, more strongly, a case where the GNN actively underperforms.

---

## 2. Data

All data is **real**, collected from a live Suricata 8.0.4 sensor integrated into a personal
Wazuh SOC lab. No synthetic traffic, no public benchmark dataset.

| Property | Value |
| :--- | :--- |
| Source | 8 rotated `eve.json` files (JSONL) |
| Raw size | 4.4 GB |
| Time span | 2026-04-10 to 2026-06-06 (~57 days) |
| Flows parsed | 1,996,179 (after dedup; 120 duplicates removed) |
| Alert events | 16,058 across 28 distinct signatures |
| Malformed lines | 2 / ~2M (0.0001%) — skipped by a resilient line parser |

### 2.1 Noise profile

The lab's own infrastructure dominated raw traffic: **72.7% of flows were loopback**
(127.0.0.1, mostly the Wazuh indexer on port 9200). After removing loopback, multicast
(224.0.0.0/4), and zero-packet flows:

| | Flows |
| :--- | ---: |
| Raw | 1,996,179 |
| **After noise filter** | **541,069** |

### 2.2 Flow keying — Community ID v1

Suricata's `flow_id` is a reused memory address and is **not** a stable cross-file identifier
(OISF Redmine #1696). To deduplicate flows and join alerts to flows across rotated log files,
I computed the **Community ID v1** hash (corelight/community-id-spec) from each flow's canonical
5-tuple, and used `(community_id, ts_start floored to 1 min)` as the dedup key.

### 2.3 Labels — scan-only weak labels (T1046)

Positives are flows whose Community ID matches a Suricata **"Nmap SYN scan"** alert (the lab's
custom IPS rule). This is a **weak label**: Suricata's own detector is the oracle.

An earlier iteration used an `alerted OR scan` label (any Suricata alert). It produced an
uninterpretable result — degree features did not help (full = stripped) — because the positive
class was dominated by **non-topological** signatures (STUN binding, RustDesk/TeamViewer DNS
lookups, HTTP header anomalies, APT user-agents). Those have no fan-out signature, so node-degree
features were dead weight. **Refocusing on scan-only labels concentrated the topological signal**
and is the correct target for the T1046 hypothesis. This relabeling is itself a documented
diagnostic step.

| Split | Edges | Scan positives | Rate | Window |
| :--- | ---: | ---: | ---: | :--- |
| train | 378,748 | 815 | 0.215% | 04/10 to 05/03 |
| val | 81,160 | 94 | 0.116% | 05/03 to 05/04 |
| test | 81,161 | 152 | 0.187% | 05/04 to 06/06 |

Class imbalance in train: **1:464**. Real scanners (confirmed in EDA): 192.168.1.51
(818 distinct destinations, 96 ports), 192.168.1.136 (714 / 13), 192.168.1.130 (259 / 9),
192.168.1.132. The loopback self-scan (127.0.0.1) was filtered as noise.

---

## 3. Methods

### 3.1 Graph construction

- **Nodes** = unique IPs (1,688). **Edges** = flows (541,069). Directed source to destination.
- **Edge features (14):** log1p of bytes/packets each direction, log1p(age), byte ratio,
  protocol one-hot (TCP/UDP), destination-port bucket (well-known / registered / ephemeral),
  TCP-state one-hot (new / established / closed).
- **Node features — full (8):** log out-degree, log in-degree, log bytes out/in,
  is_private, **log distinct destinations, log distinct destination-ports, port entropy**.
  The last three are the explicit *scan-specific topological* features.
- **Node features — stripped (1):** is_private only. Used for the degree-stripping ablation.

### 3.2 Leakage control and split

- **Temporal split** (70/15/15 by flow.start), not random. This is the honest setting for a
  detector that must generalize to *future* traffic.
- **All node features and all scalers are fit on the TRAIN window only.** Nodes appearing only in
  val/test receive zero/default features — exactly as a deployed model would face previously
  unseen hosts.

### 3.3 Models

**Tabular baselines** (feature vector = edge features + source-node features + dest-node features):

- XGBoost (n_estimators=400, max_depth=6, lr=0.05, GPU hist, scale_pos_weight=464)
- RandomForest (n_estimators=300, class_weight="balanced")
- LogisticRegression (class_weight="balanced")

**GNN models** (edge classification):

- **E-GraphSAGE** — faithful to Lo et al. (2022). PyG's SAGEConv silently ignores edge_attr,
  so the layer is a custom MessagePassing subclass whose message is concat(neighbor_node, edge_attr),
  **mean** aggregation.
- **GATv2** — GATv2Conv(edge_dim=14, heads=4, concat=False, add_self_loops=False).
- Both: 2 conv layers, hidden 64, dropout 0.3; edge head = MLP over concat(h_src, h_dst, edge_attr)
  to 2 classes; weighted CrossEntropyLoss; Adam lr=0.005; ReduceLROnPlateau; 300 epochs;
  **best checkpoint by validation PR-AUC** (evaluated every epoch).

### 3.4 Metrics

Macro-F1 was rejected as a primary metric: with ~150 test positives, a single
true/false-positive flip moves it by double-digit points. Primary and supporting metrics:

1. **PR-AUC (Average Precision)** — primary; threshold-independent and imbalance-robust
   (Saito and Rehmsmeier, 2015).
2. **MCC** — single-number balanced confusion-matrix metric.
3. **Balanced Accuracy** — reported, but see the caveat in section 5.
4. **TPR @ FPR = 1%** — the operational metric a SOC analyst cares about.
5. **Bootstrap 95% CIs** — 1,000 resamples for every metric.

All test results are a **5-seed probability ensemble** (seeds [42, 1, 7, 13, 99]).

### 3.5 Ablation A — degree stripping

Run every model on both full and stripped node features. If the topological signal is real
and transfers, full should beat stripped, and the GNN — forced to derive structure via message
passing when given stripped features — should recover what the tabular model loses.

---

## 4. Results

### 4.1 Head-to-head (scan-only, test set, 5-seed ensemble)

Sorted by PR-AUC (primary). GNN rows marked with arrow.

| Model | PR-AUC | MCC | Bal-Acc | Macro-F1 | TPR@1% |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **XGBoost (stripped)** | **0.1956** | **0.2921** | 0.9332 | 0.5849 | 0.6316 |
| RandomForest (stripped) | 0.1302 | 0.2478 | 0.7882 | 0.5882 | 0.6711 |
| XGBoost (full) | 0.1288 | 0.1868 | 0.6651 | 0.5795 | 0.6118 |
| RandomForest (full) | 0.1164 | 0.0575 | 0.5130 | 0.5213 | 0.6316 |
| LogisticReg (stripped) | 0.0948 | 0.2119 | 0.9778 | 0.5352 | 0.4079 |
| E-GraphSAGE (full) <-- GNN | 0.0932 | 0.2091 | 0.9803 | 0.5335 | 0.5724 |
| E-GraphSAGE (stripped) <-- GNN | 0.0930 | 0.2091 | 0.9803 | 0.5335 | 0.4934 |
| GATv2 (stripped) <-- GNN | 0.0829 | 0.2091 | 0.9803 | 0.5335 | 0.5066 |
| GATv2 (full) <-- GNN | 0.0799 | 0.2095 | 0.9804 | 0.5337 | 0.4671 |
| LogisticReg (full) | 0.0593 | 0.1440 | 0.9594 | 0.5009 | 0.3947 |

Selected 95% bootstrap CIs (PR-AUC): XGBoost (stripped) **0.196 [0.152, 0.258]**;
E-GraphSAGE (full) 0.093 [0.073, 0.126]. The intervals do not overlap at the point estimates —
the tabular advantage is not an artifact of a lucky seed.

**Winner: XGBoost on per-flow features.** Every GNN configuration lands at PR-AUC around 0.08-0.09,
roughly **half** the best tabular model.

### 4.2 Ablation A — does the topological signal transfer?

PR-AUC, full minus stripped:

| Model | full | stripped | Delta | Reading |
| :--- | ---: | ---: | ---: | :--- |
| XGBoost | 0.1288 | 0.1956 | **-0.067** | degree features **hurt** |
| RandomForest | 0.1164 | 0.1302 | -0.014 | approx no effect |
| LogisticReg | 0.0593 | 0.0948 | -0.036 | degree features **hurt** |

The pre-computed degree/fan-out node features **degrade** test performance. They are computed on
the train window; the scanners' behavior in the test window differs enough that the frozen
profiles act as noise and induce false positives.

### 4.3 A telling GNN signature

All four GNN configurations converged to **near-identical** MCC (0.2091) and Balanced Accuracy
(0.9803), with full = stripped. They collapsed to the same solution regardless of whether degree
features were provided or had to be learned. Combined with TP = 152/152 (100% recall at threshold
0.5) but PR-AUC around 0.09 (about 4-5% precision), this is the fingerprint of a model riding
entirely on the per-flow edge features and flagging liberally — **not** one exploiting
neighborhood structure.

### 4.4 Compute

GNN training (2 architectures x 2 variants x 5 seeds x 300 epochs) took **45 min** and peaked at
**3.5 GB / 12 GB (28%)** of the RTX 4070 SUPER. The graph is small (1.7k nodes); **compute was
never the bottleneck — the 152 test positives are.** Scaling GPU utilization would not change the
result.

---

## 5. Discussion — why the GNN lost

**1. Mean and attention aggregation cannot encode degree.** The scan signal *is* a count —
"this source contacted 800 destinations." Mean aggregation discards cardinality by construction
(the mean of 800 vectors does not encode "800"); attention with softmax normalization also sums to
1 and washes out magnitude. This is precisely the expressiveness gap that motivated **GIN**
(Xu et al., 2019): **sum** aggregation is required to preserve multiset cardinality. The E-GraphSAGE
(mean) and GATv2 (attention) layers tested here are theoretically ill-suited to read fan-out, and
the identical-MCC collapse in section 4.3 is that theory showing up in the data.

**2. The GNN had a structural advantage and still lost.** In this transductive setup the GNN
message-passes over the *full* graph, including test-time edges — so it could "see" the live
test-window topology that the tabular model (frozen train-window node features) could not. Even with
that advantage, it underperformed. That makes the negative result *stronger*, not weaker: live
structure access did not help because the architecture cannot convert it into a degree signal, and
because...

**3. ...the per-flow signature already saturates the task.** A SYN-scan flow is, individually,
highly distinctive: tiny byte counts, 1-2 packets, SYN/new or closed state, often to a
well-known port. XGBoost reads this directly from the 14 edge features. The neighborhood adds little
once each flow is already separable. The strongest model uses **only** edge features + is_private.

**4. Frozen historical node profiles do not transfer (Ablation A).** Degree features computed on a
past window mislabel hosts whose behavior changes — the source of the full < stripped regression.
A deployed degree-based detector would need *online* structural features, not a stale profile.

**5. This matches the literature.** GNN-NIDS results are highly dataset-dependent: E-GraphSAGE-family
models are strong on some reconnaissance benchmarks yet weak (F1 around 0.13) on others such as
NF-ToN-IoT scanning (Lo et al., 2022), and a 2024 study (arXiv:2402.18986) reports a plain Decision
Tree beating E-GraphSAGE on ToN-IoT. This benchmark reproduces the difficult side of that picture
on independent, real-world data.

### Operational reading

The best model (XGBoost, stripped) detects **63% of scan flows at a 1% false-positive rate**
(TPR@FPR1% = 0.632 [0.561, 0.724]). Over the 33-day test window's 81,009 benign flows, 1% FPR is
approximately 25 false alerts/day — a usable operating point for triage, with the honest caveat
that recall is capped at ~63% and low-and-slow scans (section 6) will evade it.

---

## 6. Limitations and where the result could change

- **Granularity.** This is *flow-level* classification. The hypothesis may yet hold at
  **source-node-level** classification (predict "is this IP a scanner?"), where fan-out is the label
  itself rather than a neighborhood attribute of an edge.
- **Aggregation untested.** The decisive experiment — **sum/GIN-style aggregation**, or an explicit
  degree-preserving readout — was not run. That is the single most important follow-up.
- **Weak labels.** Ground truth is Suricata's own SYN-scan rule; it inherits that rule's blind spots.
- **Single environment, recurring scanners.** One lab, a handful of scanner IPs. Cross-environment
  drift is unmeasured.
- **152 test positives.** Enough for bootstrap CIs, but a larger and more diverse positive set
  (multiple scan types, more sources) would tighten conclusions.
- **Evasion.** Low-and-slow and distributed scans are explicitly out of scope and would defeat both
  model families here.

---

## 7. What I would do differently (future work)

1. **Reframe as node classification** with sum aggregation (GIN) — the experiment most likely to
   *confirm* the original hypothesis.
2. **Add online/windowed structural features** instead of a single frozen train-window profile.
3. **Self-supervised structural learning** (Anomal-E; Caville et al., 2022) to reduce reliance on
   weak supervised labels.
4. **Broaden the positive class** — multiple scan techniques and more diverse sources.

---

## 8. Reproducibility

**Hardware:** Ubuntu 24.04, Intel i9 (24 threads), 32 GB RAM, NVIDIA RTX 4070 SUPER (12 GB, sm_89),
driver 595.71.05, CUDA 13.2.

**Software (pinned):** Python 3.12.3, torch 2.11.0+cu128, torch_geometric 2.7.0, scikit-learn 1.9.0,
xgboost 3.2.0, pandas 3.0.3, numpy 2.4.4, ijson 3.5.0, pyarrow 24.0.0, networkx 3.6.1.

**Determinism:** global SEED=42; results ensembled over seeds [42, 1, 7, 13, 99]; all scalers and
node features fit on TRAIN only; temporal (not random) split.

**Pipeline (notebook cell order):** corpus ingestion (resilient JSONL parser + Community ID v1) then
noise filtering and EDA with an explicit positive-count stop-condition then feature engineering then
graph construction (PyG Data) then tabular baselines with bootstrap CIs then GNN benchmark
(E-GraphSAGE + GATv2) then head-to-head.

---

## 9. Conclusion

The pre-registered hypothesis — that GNNs should beat tabular models at flow-level scan detection
because the signal is topological — **was not supported** on ~2M real Suricata flows. Gradient
boosting on per-flow features won decisively (PR-AUC 0.196 vs 0.093), and explicit topological
features *degraded* performance. The most defensible interpretation is that **at this granularity the
SYN-scan signature is already separable per-flow, and mean/attention message passing cannot encode
the one thing that would help — node degree.**

This is the kind of result that is easy to bury and worth publishing: a clean, imbalance-aware,
leakage-controlled benchmark on real data that says *the simpler model wins here, and here is exactly
why.* Knowing when **not** to reach for a GNN is as much a part of the job as knowing how to build one.

---

## References

1. Lo, W. W., Layeghy, S., Sarhan, M., Gallagher, M., and Portmann, M. (2022). *E-GraphSAGE: A Graph
   Neural Network based Intrusion Detection System for IoT.* IEEE/IFIP NOMS 2022. arXiv:2103.16329.
2. Xu, K., Hu, W., Leskovec, J., and Jegelka, S. (2019). *How Powerful are Graph Neural Networks?* (GIN).
   ICLR 2019. arXiv:1810.00826.
3. Hamilton, W. L., Ying, R., and Leskovec, J. (2017). *Inductive Representation Learning on Large
   Graphs* (GraphSAGE). NeurIPS 2017. arXiv:1706.02216.
4. Brody, S., Alon, U., and Yahav, E. (2022). *How Attentive are Graph Attention Networks?* (GATv2).
   ICLR 2022. arXiv:2105.14491.
5. Caville, E., Lo, W. W., Layeghy, S., and Portmann, M. (2022). *Anomal-E: A self-supervised network
   intrusion detection system based on graph neural networks.* Knowledge-Based Systems. arXiv:2207.06819.
6. (2024). On pre-training and tabular-vs-GNN baselines for NIDS. arXiv:2402.18986.
7. Mitchell, M., et al. (2019). *Model Cards for Model Reporting.* ACM FAT* 2019. arXiv:1810.03993.
8. Saito, T., and Rehmsmeier, M. (2015). *The Precision-Recall Plot Is More Informative than the ROC
   Plot When Evaluating Binary Classifiers on Imbalanced Datasets.* PLOS ONE 10(3): e0118432.
9. Corelight. *Community ID Flow Hashing Specification.* github.com/corelight/community-id-spec.
10. MITRE ATT&CK. *T1046 — Network Service Discovery.* attack.mitre.org/techniques/T1046.

---

## Appendix — Model card (Mitchell et al., 2019)

- **Model:** XGBoost binary classifier (best of benchmark), flow-level Nmap SYN-scan detection.
- **Input:** 16 features per flow (14 per-flow edge features + source/destination is_private).
- **Output:** P(scan) per flow; operating point chosen on the PR or TPR@FPR curve.
- **Training data:** 378,748 real Suricata flows (815 scan-positive), 2026-04-10 to 05-03.
- **Evaluation:** temporal hold-out, 81,161 flows (152 positives), 2026-05-04 to 06-06.
- **Performance:** PR-AUC 0.196 [0.152, 0.258]; MCC 0.292; TPR@FPR1% 0.632.
- **Intended use:** triage assistance in a single-environment lab SOC. **Not** validated for
  production, cross-environment deployment, or low-and-slow/distributed scans.
- **Ethical/operational notes:** weak labels (Suricata oracle); recall capped (~63% @ 1% FPR);
  retrain with online structural features before any real deployment.

---

<sub>
<b>Navigation</b> &nbsp;
<a href="../../README.md">Portfolio home</a> &nbsp;&middot;&nbsp;
<a href="README.md">ML Research</a> &nbsp;&middot;&nbsp;
<a href="../README.md">All 22 integrations</a> &nbsp;&middot;&nbsp;
<a href="../../detection-coverage/attack-coverage.md">Detection coverage</a> &nbsp;&middot;&nbsp;
<a href="../../playbooks/README.md">SOC playbooks</a> &nbsp;&middot;&nbsp;
<a href="../../METRICS.md">Metrics</a>
<br><br>
Validated in a single-workstation lab. Each guide records the versions it was validated
against; see <a href="../../README.md#lab-status">lab status</a>.
</sub>

