# Portfolio Metrics — Single Source of Truth

> **Every number quoted anywhere in this repository, in the CV, or on LinkedIn comes from this file.**
> Repository-side counts are produced by `scripts/verify-metrics.sh` and must not be edited by hand.
> Lab-side counts are attested manually against the live host until the rule corpus is published
> (see [`rules/README.md`](rules/README.md)).

**Last verified:** 2026-07-29
**Verification command:** `./scripts/verify-metrics.sh`

---

## 1. Repository-verifiable metrics

These are counted directly from the files in this repository. If the badge and this table
disagree, the script is right and the badge is wrong.

| Metric | Value | How it is counted |
| --- | ---: | --- |
| Documented integrations | **24** | Non-`README` `*.md` files under `integrations/*/`, excluding `ml-research/` |
| Integration categories | **7** | Directories under `integrations/`, excluding `ml-research/` |
| ML research reports | **3** | `ml-research/` guides + `malware-phylogenetics/` |
| Published rule files | *see `rules/`* | `*.xml` under `rules/` |
| Documented playbooks | **2** | Non-`README` `*.md` under `playbooks/` |
| Worked incident reports | **2** | Non-`README`, non-`TEMPLATE` `*.md` under `incident-reports/` |

### Integrations by category

| Category | Count |
| --- | ---: |
| Threat Intelligence & Detection | 8 |
| Network Security | 5 |
| Data Protection | 5 |
| Incident Response & SOAR | 2 |
| Authentication | 2 |
| System Inventory | 1 |
| Vulnerability Management | 1 |
| **Total** | **24** |

---

## 2. Lab-side metrics (attested, not yet repository-verifiable)

These describe the live Wazuh deployment. They **cannot** currently be verified from this
repository because the rule and decoder corpus has not been published. Publishing it is the
top open item in the roadmap.

| Metric | Value | Attestation |
| --- | ---: | --- |
| Custom rules authored | **216** | `grep -c '<rule id' /var/ossec/etc/rules/*.xml` on the live manager |
| Custom decoders authored | **51** | `grep -c '<decoder name' /var/ossec/etc/decoders/*.xml` |
| Active rule files | **17** | `/var/ossec/etc/rules/` |
| Rule ID range | `100049 – 120064` | — |

> **Historical note.** Earlier revisions of this portfolio, the CV and LinkedIn quoted
> **178**, **182** and **188** rules, and 20 integrations. Those figures were hand-maintained
> and drifted. The 2026-07-23 export from the live manager gave **209 rules, 49 decoders,
> 16 rule files, 22 integrations**. The 2026-07-29 export, after adding the Fail2ban
> integration (`local_fail2ban_rules.xml` — 4 rules; `local_fail2ban_decoders.xml` — 2
> decoders; 1 new rule file), gives the current authoritative count:
> **216 rules, 51 decoders, 17 rule files, 23 integrations**. The repository-verifiable
> rule count (counted from `rules/*.xml`) is **212**, four fewer than the manager, because
> the Fail2ban rules and decoders are documented inline in the integration guide rather than
> exported as standalone XML files — consistent with every other integration in this repo.

## 2b. Deployment state

The detection corpus is loaded and active on the manager at all times. The tools that feed it
are brought up per project rather than run concurrently — a single workstation cannot host 23
services at once.

| State | Components |
| --- | --- |
| Continuously running | Wazuh manager / indexer / dashboard, Suricata, UFW, ClamAV |
| Brought up per project | Zeek, Cowrie, Falco, Velociraptor, MISP, CALDERA, OSQuery, FreeRADIUS, Radsecproxy, OpenVAS, SpiderFoot, YARA, WireGuard, Restic, NWIPE, VeraCrypt, Shuffle, Auditd |

Host rebuilt from scratch July 2026; rule corpus and configurations retained and restored.

---

## 3. Platform versions

| Component | Current lab version | Notes |
| --- | --- | --- |
| Wazuh (manager / indexer / dashboard) | **4.14.6** | Upgraded 2026-07-16; validated during the ClamAV integration |
| Ubuntu | 24.04 LTS | Bare metal |
| Suricata | 8.0.6 | Inline IPS via NFQUEUE queue 3 |

### Version policy for integration guides

Individual integration guides record the version **in use at the time that integration was
validated**. They are deliberately *not* rewritten when the platform is upgraded — a validation
report that claims a version it was not run against is worthless.

Every guide therefore carries this header block:

```
> **Current lab version:** Wazuh 4.14.6
> **Validated against:** Wazuh 4.14.4 · Suricata 8.0.4
> **Last revalidated:** 2026-04-16
```

A guide whose `Validated against` trails the current version is **not** stale. It is a dated
report. Guides are revalidated when the integration changes or when a Wazuh minor release
touches the relevant subsystem — not on every patch bump.

Known version spread across guides (expected, not an error):

| Version | Guides validated against it |
| --- | --- |
| 4.14.6 | ClamAV |
| 4.14.5 | Majority of guides |
| 4.14.4 | Suricata, FreeRADIUS, Radsecproxy, YARA (partial) |
| 4.14.2 | CALDERA (partial) |

---

## 4. Where these numbers appear

When a metric changes, update **this file first**, then run `scripts/verify-metrics.sh`, then
propagate to:

- [ ] `README.md` — badges and the "by the numbers" table
- [ ] `integrations/README.md` — catalog header and status table
- [ ] `detection-coverage/attack-coverage.md` — rule totals
- [ ] CV (PDF/DOCX)
- [ ] LinkedIn headline and featured section
