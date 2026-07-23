<!-- soc-banner -->
<p align="center"><img src="assets/banners/banner-system-inventory.svg" alt="System Inventory -- Wazuh SOC" width="100%"></p>

# System Inventory

Endpoint visibility and host posture: continuous inventory, configuration drift and surface
enumeration rather than threat detection.

**1 documented integration** in this category.
Each guide includes configuration, validated `wazuh-logtest` output, OpenSearch DevTools
queries and dashboard screenshots captured during validation.

---

## Integrations

| Integration | What it detects | Rules | ID range | MITRE ATT&CK |
| --- | --- | :---: | --- | --- |
| **[OSQuery](osquery-integration.md)** | Scheduled queries over processes, packages, users, cron and container images | 2 | `24010 / 100000` | T1053.003, T1098.004, T1136, T1547.006 |

`--` indicates the integration relies on native Wazuh decoders or operates outside the custom
rule ID space. Rule counts reflect what each guide documents; the authoritative corpus totals
live in [`METRICS.md`](../../METRICS.md) and are verified by
[`verify-metrics.sh`](../../scripts/verify-metrics.sh).

---

## Navigation

[**Portfolio home**](../../README.md) ·
[All integrations](../README.md) ·
[Detection coverage](../../detection-coverage/attack-coverage.md) ·
[SOC playbooks](../../playbooks/README.md) ·
[Incident reports](../../incident-reports/README.md)
