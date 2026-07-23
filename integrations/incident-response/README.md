<!-- soc-banner -->
<p align="center"><img src="assets/banners/banner-incident-response.svg" alt="Incident Response & SOAR -- Wazuh SOC" width="100%"></p>

# Incident Response & SOAR

Forensic collection and response automation -- the layer that turns an alert into an action.

**2 documented integrations** in this category.
Each guide includes configuration, validated `wazuh-logtest` output, OpenSearch DevTools
queries and dashboard screenshots captured during validation.

---

## Integrations

| Integration | What it detects | Rules | ID range | MITRE ATT&CK |
| --- | --- | :---: | --- | --- |
| **[Velociraptor DFIR](velociraptor-integration.md)** | Endpoint forensics, live collection and server audit trail; chained decoders resolve generic-JSON conflicts | 17 | `100400-100419` | T1021.004, T1046, T1059, T1070.004 |
| **[Shuffle SOAR](shuffle-integration.md)** | Workflow orchestration, alert enrichment and automated response paths | -- | `workflow` | T1548.001 |

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
