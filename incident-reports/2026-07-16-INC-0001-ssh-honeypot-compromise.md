# INC-0001 — SSH Credential Compromise and Payload Retrieval Attempt

| | |
| --- | --- |
| **Incident ID** | INC-0001 |
| **Classification** | P1 — Critical |
| **Status** | Closed — true positive, contained |
| **Detected** | 2026-07-16 by Wazuh rule `100503` |
| **Affected asset** | `cowrie-hp-01` — SSH/Telnet honeypot (Docker), ports 55222/55223 |
| **MITRE ATT&CK** | T1110.001, T1059, T1105 |
| **Author** | Bruno Flausino |
| **Current lab version** | Wazuh 4.14.6 |
| **Validated against** | Wazuh 4.14.5 |

> **Nature of this report.** This documents a genuine detection chain firing on genuine
> honeypot activity in a self-hosted lab. It is written in the format a managed-service client
> would receive so the reporting discipline is demonstrable, but it is **not** an enterprise
> incident and makes no claim to be one. The affected asset is a deliberately exposed honeypot
> with no production value; "compromise" here means the honeypot did its job. Detection logic,
> timeline construction and reporting format transfer to a production environment. Scale,
> business impact and organisational response do not.

---

## 1. Executive summary

An SSH brute-force attack against the lab honeypot resulted in successful authentication,
followed by command execution and an attempted retrieval of a remote payload. The full attack
chain — from first connection to payload attempt — was detected by the deployed Wazuh ruleset
with no manual discovery required.

The honeypot is an isolated container with no access to other lab systems and no credentials of
value. Containment consisted of blocking the source and preserving the session record. No
lateral movement was observed and none was possible from this asset.

**The finding that matters is not the intrusion.** It is that the detection chain produced a
complete, ordered narrative of attacker behaviour from independent rule firings, without an
analyst having to reconstruct it from raw logs.

---

## 2. Timeline

All times UTC. Reconstructed from indexed Wazuh alerts, not from raw logs.

| Time | Event | Rule | Level | Source |
| --- | --- | :---: | :---: | --- |
| T+00:00 | Session opened to port 55222 | `100501` | 6 | Wazuh |
| T+00:00 | SSH client version banner recorded | `100508` | 6 | Wazuh |
| T+00:02 | Failed authentication — begins credential guessing | `100502` | 8 | Wazuh |
| T+00:02 → T+04:31 | Sustained failed authentication attempts | `100502` | 8 | Wazuh |
| **T+04:47** | **Authentication succeeded** | **`100503`** | **12** | **Wazuh** |
| T+04:52 | Command execution within session | `100504` | 10 | Wazuh |
| **T+05:09** | **Remote payload retrieval attempted** | **`100505`** | **14** | **Wazuh** |
| T+05:14 | Command failure recorded | `100506` | 5 | Wazuh |
| T+06:02 | Session closed | `100507` | 3 | Wazuh |
| T+06:20 | Source blocked, session preserved | — | — | Analyst |

### Detection-to-escalation performance

| Measure | Value | Target |
| --- | ---: | ---: |
| Time to first detection (`100501`) | 0 s | — |
| Time from first failure to compromise alert (`100503`) | 4 m 45 s | — |
| Time from compromise alert to P1 escalation (`100505`) | 22 s | 15 min |
| Time from P1 to containment | 1 m 11 s | 15 min |

The P1 escalation was driven by rule `100505` (level 14), not by analyst judgement. That is the
intended design: payload retrieval after successful authentication should not wait for a human
to notice a pattern.

---

## 3. Analysis

### 3.1 What the attacker did

The chain follows the standard opportunistic-botnet pattern for internet-exposed SSH:

1. **Reconnaissance** — connection and client banner exchange (`100501`, `100508`). The SSH
   client version is a useful fingerprint; automated scanners rarely vary it.
2. **Credential access** (T1110.001) — password guessing against common accounts (`100502`).
   Volume and interval indicate automation rather than interactive attack.
3. **Initial access** — successful authentication (`100503`). Cowrie accepts by design after a
   configured number of attempts; the value is capturing what happens *next*.
4. **Execution** (T1059) — post-access commands (`100504`). This is the highest-value telemetry
   in the whole chain, because it reveals attacker intent rather than attacker capability.
5. **Ingress tool transfer** (T1105) — attempted retrieval of a remote payload (`100505`).

### 3.2 Why the detection worked

The chain is built as parent/child rules, not as six independent detections:

```
100500  base — any Cowrie JSON event (level 3, no alert)
  ├── 100501  session.connect          level 6
  ├── 100502  login.failed             level 8   T1110.001
  ├── 100503  login.success            level 12  T1110.001
  ├── 100504  command input            level 10  T1059
  │     └── 100505  malware download   level 14  T1105
  ├── 100506  command failed           level 5
  ├── 100507  session closed           level 3
  └── 100508  SSH client version       level 6   T1046
```

Two design decisions did the work:

**`100505` is a child of `100504`, not of `100500`.** A download attempt only escalates to level
14 when it occurs inside an established command session. The parent relationship encodes the
context that makes the event critical, so the severity is structural rather than a number
somebody chose.

**The base rule `100500` is level 3 and generates no alert.** It exists purely to give the
children a shared parse. Without it, every child would independently re-match the JSON, and a
change to the log format would require eight edits instead of one.

### 3.3 Evidence query

The timeline in section 2 was produced by this query, not assembled by hand:

```
GET wazuh-alerts-*/_search
{
  "query": { "bool": { "filter": [
    { "terms": { "rule.id": ["100500","100501","100502","100503",
                             "100504","100505","100506","100507","100508"] } },
    { "term":  { "data.srcip": "<SOURCE_IP>" } },
    { "range": { "@timestamp": { "gte": "<T-1h>", "lte": "<T+1h>" } } }
  ]}},
  "sort": [ { "@timestamp": "asc" } ],
  "_source": ["@timestamp","rule.id","rule.level","rule.description",
              "data.srcip","data.input","data.url"],
  "size": 500
}
```

Reproducibility matters more than the screenshot. Any reviewer with the index can regenerate
this timeline exactly.

---

## 4. Impact

| Question | Finding | Confidence |
| --- | --- | --- |
| Did authentication succeed? | Yes, on the honeypot | Confirmed |
| Did commands execute? | Within the Cowrie emulation layer only | Confirmed |
| Was a payload retrieved? | Attempt recorded; retrieval not completed | Confirmed |
| Was any real credential exposed? | No — honeypot credentials are synthetic | Confirmed |
| Was there lateral movement? | None observed | Confirmed via Zeek/Suricata for the window |
| Was any other lab asset affected? | No | Confirmed |
| Was persistence established? | Not applicable — container is ephemeral | Confirmed |

**Business impact: none.** The asset exists to be attacked.

---

## 5. Response

| # | Action | Tier | Time |
| --- | --- | :---: | --- |
| 1 | Session record preserved before any containment | L1 | T+06:14 |
| 2 | Source IP blocked | L2 | T+06:20 |
| 3 | Full command history extracted from Cowrie session log | L2 | T+06:35 |
| 4 | Payload URL checked against MISP and OSINT CDB | L2 | T+07:02 |
| 5 | Container recycled to clean state | L2 | T+07:30 |
| 6 | Detection chain reviewed — no tuning required | L3 | T+1d |

Evidence preservation preceded containment, per the escalation matrix. On a production host
this ordering is what determines whether root cause is recoverable.

---

## 6. Findings and recommendations

### F-01 — Source-IP diversity is not representative *(informational)*

The honeypot listens on high ports (55222/55223) because port 22 is allocated to CALDERA, and
observed source addresses are Docker bridge addresses rather than internet sources. The
detection chain is unaffected, but **frequency-based tuning derived from this data will not
transfer** to an internet-exposed deployment.

*Recommendation:* do not derive rate thresholds from honeypot volume in this configuration.

### F-02 — No automatic case creation *(medium)*

Alerts at level 12+ do not automatically create a case. Timeline reconstruction was manual,
which is acceptable for one analyst and does not scale past a handful of concurrent incidents.

*Recommendation:* re-enable the DFIR-IRIS outbound integration, currently commented out in
`ossec.conf`, and route rules ≥12 to automatic case creation.

### F-03 — Payload URL enrichment is manual *(medium)*

The URL from `100505` was checked against MISP by hand. This is exactly the pattern SOAR
automation exists for.

*Recommendation:* Shuffle workflow triggered on `100505` — extract URL, query MISP, attach the
verdict to the alert before an analyst reads it.

### F-04 — Detection chain performed as designed *(positive)*

No rule tuning was required. The parent/child structure produced a correctly ordered narrative
with no false positives and no gaps in the sequence. Recorded here because reviews that only
list defects give a false picture of detection quality.

---

## 7. Lessons

**What worked.** Chained rules with structural severity. The critical alert fired because of
where the event sat in the chain, not because an analyst spotted a pattern across six separate
notifications.

**What did not.** Enrichment and case creation are manual. Both are already-deployed
capabilities (MISP, Shuffle, DFIR-IRIS) that are not wired into this path. The gap is
integration, not tooling.

**What this exercise cannot show.** Multi-host correlation, business-impact assessment, client
communication under pressure, and how the same chain behaves at production alert volume. Those
require a production SOC and are stated here as limits rather than left for a reader to infer.
