<!-- soc-banner -->
<p align="center"><img src="assets/banners/banner-authentication.svg" alt="Authentication -- Wazuh SOC" width="100%"></p>

# Authentication

RADIUS-based authentication monitoring: credential attacks, policy decisions and proxy-tier
health.

**2 documented integrations** in this category.
Each guide includes configuration, validated `wazuh-logtest` output, OpenSearch DevTools
queries and dashboard screenshots captured during validation.

---

## Integrations

| Integration | What it detects | Rules | ID range | MITRE ATT&CK |
| --- | --- | :---: | --- | --- |
| **[FreeRADIUS](freeradius-integration.md)** | Authentication accept/reject decisions, credential guessing and account anomalies | 5 | `110010-110204` | T1078, T1110.001 |
| **[Radsecproxy](radsecproxy-integration.md)** | RadSec proxy health, TLS peer failures and relay availability | 7 | `110101-110306` | T1078, T1110, T1499, T1557 |

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
