# Wazuh SOC Integration Catalog

Each integration below has a dedicated markdown guide with configuration, validated `wazuh-logtest` / `wazuh-analysisd -t` output, OpenSearch DevTools queries, and dashboard screenshots. This index lists **only** integrations that are deployed **and** documented.

## Documented Integrations (20)

### 🔒 [Network Security](network-security/) — 4
- [Suricata IDS/IPS](network-security/suricata-integration.md)
- [Zeek Network Monitor](network-security/zeek-integration.md)
- [WireGuard VPN](network-security/wireguard-integration.md)
- [UFW Firewall](network-security/ufw-integration.md)

### 🎯 [Threat Intelligence & Detection](threat-intelligence/) — 6
- [MISP Threat Intelligence](threat-intelligence/misp-integration.md)
- [MITRE CALDERA](threat-intelligence/caldera-integration.md)
- [YARA](threat-intelligence/yara-integration.md)
- [Falco (eBPF)](threat-intelligence/falco-integration.md)
- [Cowrie Honeypot](threat-intelligence/cowrie-integration.md)
- [Auditd](threat-intelligence/auditd-integration.md)

### 🚨 [Incident Response & SOAR](incident-response/) — 2
- [Velociraptor DFIR](incident-response/velociraptor-integration.md)
- [Shuffle SOAR](incident-response/shuffle-integration.md)

### 🖥️ [System Inventory](system-inventory/) — 1
- [OSQuery](system-inventory/osquery-integration.md)

### 🔓 [Vulnerability Management](vulnerability-scan/) — 1
- [OpenVAS / GVM](vulnerability-scan/openvas-integration.md)

### 🔐 [Authentication](authentication/) — 2
- [FreeRADIUS](authentication/freeradius-integration.md)
- [Radsecproxy](authentication/radsecproxy-integration.md)

### 💾 [Data Protection](data-protection/) — 4
- [ClamAV Antivirus](data-protection/clamav-integration.md)
- [VeraCrypt Encryption](data-protection/veracrypt-integration.md)
- [NWIPE Secure Erasure](data-protection/nwipe-integration.md)
- [Restic Backup](data-protection/restic-integration.md)

### 🧪 [ML Research](ml-research/)
- [GNN vs Gradient Boosting — honest benchmark on real Suricata flows](ml-research/gnn-vs-tabular-scan-detection.md) *(complete; negative result)*
- [GNN → Wazuh ingestion scaffold](ml-research/gnn-security-detector-integration.md) *(prototype; synthetic events only — detector not integrated end-to-end)*

---

## Integration Status

| Category | Documented tools | Status |
|----------|:----------------:|--------|
| Network Security | 4 | ✅ Complete |
| Threat Intelligence & Detection | 6 | ✅ Complete |
| Incident Response & SOAR | 2 | ✅ Complete |
| System Inventory | 1 | ✅ Complete |
| Vulnerability Management | 1 | ✅ Complete |
| Authentication | 2 | ✅ Complete |
| Data Protection | 4 | ✅ Complete |
| **TOTAL** | **20** | **Documented & validated** |

---

## Roadmap (not counted above)

**Wazuh-side integration deployed, guide pending:** GRR Rapid Response (rules `120000–120003`), Nuclei (`nuclei_rules.xml`), CAPE Sandbox (rule `120050`), DFIR-IRIS (inbound rule `120040`; outbound currently commented out), OpenCanary (localfile only), and the Auditd-MITRE rule pack (`110700-auditd-mitre.xml`).
