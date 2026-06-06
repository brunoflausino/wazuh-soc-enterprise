# 🛡️ MISP (Malware Information Sharing Platform) Integration

Centralized Threat Intelligence monitoring utilizing MISP integration within Wazuh. This dashboard displays active campaigns, precise IoC matches, and alert trends to support SOC triage and threat hunting operations.

## 📊 Dashboard Visualizations

### Top Event Information and Campaigns
Provides immediate correlation between active malicious campaigns (e.g., APT29, Emotet) and specific Indicators of Compromise (IoCs) detected in the environment.

![Top MISP Event Information and Campaigns](./assets/misp/top-misp-event-information-and-campaigns.png)

---

### Threat Event Categories
Breaks down the active threat categories triggered within the network, allowing for quick identification of the primary attack vectors.

![Threat Event Categories](./assets/misp/threat-event-categories.png)

---

### Distribution of MISP IoC Types
Visualizes the breakdown of IoC types detected by the integration (e.g., malicious Domains, IP addresses, File Hashes).

![Distribution of MISP IoC Types](./assets/misp/distribution-of-misp-ioc-types.png)

---

### Alerts by Threat Level
Illustrates the severity of threats based on the MISP threat level ID, helping prioritize incident response efforts.

![MISP Alerts by Threat Level](./assets/misp/misp-alerts-by-threat-level.png)
