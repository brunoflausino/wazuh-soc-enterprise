# Wazuh SOC Integration Catalog

Each integration below has a dedicated markdown guide with configuration, validated
`wazuh-logtest` / `wazuh-analysisd -t` output, OpenSearch DevTools queries, and dashboard
screenshots captured during validation. This index lists **only** integrations that were
deployed, validated end-to-end **and** documented. See [lab status](../README.md#lab-status) for
which run continuously and which are brought up per project.

All counts on this page are verified by [`scripts/verify-metrics.sh`](../scripts/verify-metrics.sh)
against [`METRICS.md`](../METRICS.md). Do not edit them by hand.

## Documented Integrations (24)

### 🎯 [Threat Intelligence & Detection](threat-intelligence/) — 8
- [OSINT CDB threat-intelligence correlation](threat-intelligence/osint-cdb-integration.md) — native Wazuh CDB list, bidirectional `srcip`/`dstip` matching
- [SpiderFoot OSINT](threat-intelligence/spiderfoot-integration.md) — JSONL ingestion, rules `113200–113205`
- [MISP Threat Intelligence](threat-intelligence/misp-integration.md)
- [MITRE CALDERA](threat-intelligence/caldera-integration.md)
- [YARA](threat-intelligence/yara-integration.md)
- [Falco (eBPF)](threat-intelligence/falco-integration.md)
- [Cowrie Honeypot](threat-intelligence/cowrie-integration.md)
- [Auditd](threat-intelligence/auditd-integration.md)

### 🔒 [Network Security](network-security/) — 5
- [Suricata IDS/IPS](network-security/suricata-integration.md) — inline IPS via NFQUEUE queue 3
- [Zeek Network Monitor](network-security/zeek-integration.md)
- [WireGuard VPN](network-security/wireguard-integration.md)
- [UFW Firewall](network-security/ufw-integration.md)
- [Fail2ban Intrusion Prevention](network-security/fail2ban-integration.md) — custom decoders, rules `100800–100803`, brute-force correlation

### 💾 [Data Protection](data-protection/) — 4
- [ClamAV Antivirus](data-protection/clamav-integration.md)
- [VeraCrypt Encryption](data-protection/veracrypt-integration.md)
- [NWIPE Secure Erasure](data-protection/nwipe-integration.md)
- [Restic Backup](data-protection/restic-integration.md)

### 🚨 [Incident Response & SOAR](incident-response/) — 2
- [Shuffle SOAR](incident-response/shuffle-integration.md)
- [Velociraptor DFIR](incident-response/velociraptor-integration.md)

### 🔐 [Authentication](authentication/) — 2
- [FreeRADIUS](authentication/freeradius-integration.md)
- [Radsecproxy](authentication/radsecproxy-integration.md)

### 🖥️ [System Inventory](system-inventory/) — 1
- [OSQuery](system-inventory/osquery-integration.md)

### 🔓 [Vulnerability Management](vulnerability-scan/) — 1
- [OpenVAS / GVM](vulnerability-scan/openvas-integration.md)

---

## Integration Status

| Category | Documented tools | Status |
|----------|:----------------:|--------|
| Threat Intelligence & Detection | 8 | ✅ Complete |
| Network Security | 5 | ✅ Complete |
| Data Protection | 4 | ✅ Complete |
| Incident Response & SOAR | 2 | ✅ Complete |
| Authentication | 2 | ✅ Complete |
| System Inventory | 1 | ✅ Complete |
| Vulnerability Management | 1 | ✅ Complete |
| **TOTAL** | **24** | **Documented & validated** |

---

## 🧪 ML Research — counted separately

Research output, not operational integrations. Kept out of the total above so the integration
count stays a clean statement about deployed tooling.

- [GNN vs Gradient Boosting — honest benchmark on real Suricata flows](ml-research/gnn-vs-tabular-scan-detection.md)
  *Complete. Negative result: XGBoost PR-AUC 0.196 vs. E-GraphSAGE 0.093.*
- [GNN → Wazuh ingestion path](ml-research/gnn-security-detector-integration.md)
  *Wazuh-side ingestion, classification and alerting deployed and validated with
  `wazuh-analysisd -t` (rules `100630–100650`). The detector itself is **not** productionised —
  it runs as ad-hoc development code outside this repository, pending a model that beats the
  tabular baseline.*
- [Mirai botnet phylogenetics](ml-research/malware-phylogenetics/) — Maximum Likelihood
  phylogeny of 18 Mirai variants via IQ-TREE.

---

## Roadmap — deployed at the Wazuh layer, guide pending

Listed separately and honestly so the counts above stay trustworthy.

| Integration | Wazuh-side state | Blocking item |
| --- | --- | --- |
| GRR Rapid Response | Rules `120000–120003`; localfile configured | Write guide |
| Nuclei | `nuclei_rules.xml` (6 rules); localfile configured | Write guide |
| CAPE Sandbox | Rule `120050`; localfile configured | Write guide |
| Auditd MITRE pack | `110700-auditd-mitre.xml` (22 rules) | Promote to its own section |
| DFIR-IRIS | Inbound rule `120040`; outbound integration block commented out in `ossec.conf` | Decide re-enable, then document |
| OpenCanary | Localfile only, no custom rules | Add rules + guide, or remove the localfile |
