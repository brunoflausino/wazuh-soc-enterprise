# L1 Alert Triage Playbook

> **Scope:** first-line triage of Wazuh alerts in this lab.
> **Audience:** L1 analyst on shift.
> **Current lab version:** Wazuh 4.14.6
> **Last revised:** 2026-07-23

This playbook defines what an L1 analyst does with an alert from the moment it appears in the
dashboard to the moment it is closed or handed to L2. It is written against the detection
content actually deployed in this lab, so every rule ID referenced here exists.

---

## 1. Severity model

Wazuh rule levels map to a four-tier severity scheme. The mapping is deliberate: rule level is
a property of the *detection*, severity is a property of the *situation*.

| Severity | Wazuh level | Meaning | First-response target | Resolution target |
| --- | :---: | --- | :---: | :---: |
| **P1 — Critical** | 13–15 | Confirmed compromise, active data loss, or destructive action in progress | **15 min** | 4 h |
| **P2 — High** | 10–12 | Strong indicator of intrusion; not yet confirmed | **30 min** | 8 h |
| **P3 — Medium** | 7–9 | Suspicious activity requiring analysis | **4 h** | 3 business days |
| **P4 — Low** | 3–6 | Informational, policy, or expected noise | **next business day** | 5 business days |

**Severity is not fixed by level alone.** Promote one tier if any of the following apply:

- The asset is a domain controller, database, or internet-facing service
- The same source has triggered ≥3 distinct rules within 1 hour
- The source IP matches the OSINT CDB list (rules `113100–113103`)
- The activity falls outside the asset's normal maintenance window

Demote one tier only with a documented reason and a named approver. "Looks like noise" is not
a reason. "Matches change ticket CHG-1182, verified with the requester" is.

---

## 2. The triage loop

Every alert goes through the same five questions, in order. Do not skip ahead — most false
positives die at question 2, and analysts who jump to question 4 waste the most time.

### Q1 — Is the detection working correctly?

Before asking whether the *activity* is malicious, ask whether the *rule* fired correctly.

```bash
# Reproduce the decode path on the raw log line
/var/ossec/bin/wazuh-logtest
```

If the rule fired on a log line it was not written for, this is a **detection defect**, not a
security event. Close as `false-positive/rule-defect`, open a tuning item, and move on. Track
these — a rule generating defect closures above ~5% of its volume needs rework, not tuning.

### Q2 — Is this expected activity?

Check, in this order:

1. Change calendar — is there a scheduled job, scan, deployment, or maintenance window?
2. Asset owner — is this host expected to behave this way?
3. Baseline — has this source triggered this rule before, and how was it closed?

```
# OpenSearch DevTools — prior history for this source
GET wazuh-alerts-*/_search
{
  "query": { "bool": { "filter": [
    { "term":  { "data.srcip": "<SOURCE_IP>" } },
    { "range": { "@timestamp": { "gte": "now-30d" } } }
  ]}},
  "aggs": { "by_rule": { "terms": { "field": "rule.id", "size": 20 } } }
}
```

A source with 400 prior alerts all closed as benign is a tuning problem. A source with zero
prior history is far more interesting.

### Q3 — What is the scope?

Never triage a single alert in isolation. Establish:

- **Same source, other rules** — is this one step in a chain?
- **Same rule, other sources** — is this campaign-wide or host-specific?
- **Same time window** — what else happened within ±15 minutes?

The chained rules in this lab exist precisely to answer this. For example, Cowrie rule `100503`
(login success) is only meaningful in the context of `100502` (login failed) volume preceding
it, and `100505` (malware download) following it.

### Q4 — Is there evidence of impact?

Impact, not intent. Ask what actually changed:

| Question | Where to look |
| --- | --- |
| Did anything execute? | Auditd (`110700–110721`), Falco, Cowrie `100504` |
| Did anything get written? | FIM, Auditd, YARA `100301`/`100302` |
| Did anything leave? | Zeek connection logs, Suricata flow records |
| Did credentials get used? | FreeRADIUS, authentication logs, Cowrie `100503` |
| Was persistence established? | Auditd MITRE pack, OSQuery scheduled queries |

No evidence of impact does not mean no impact. It means you have not found it yet, and that
distinction belongs in the ticket.

### Q5 — Escalate, contain, or close?

See [`escalation-matrix.md`](escalation-matrix.md).

---

## 3. Worked triage paths

### 3.1 SSH brute force → compromise (Cowrie)

The most common intrusion chain in this lab, and the clearest illustration of why chained rules
beat isolated ones.

| Stage | Rule | Level | What it means | L1 action |
| --- | --- | :---: | --- | --- |
| Connection | `100501` | 6 | Session opened | Note source; no action alone |
| Failed auth | `100502` | 8 | Credential guessing | P3 if <20 attempts; P2 if sustained |
| **Successful auth** | `100503` | **12** | **Credentials accepted** | **P2 — escalate to L2** |
| Command execution | `100504` | 10 | Post-access activity | Capture full command history |
| **Malware download** | `100505` | **14** | **Payload retrieval attempted** | **P1 — escalate immediately** |
| Recon | `100508` | 6 | Client fingerprinting | Context only |

**Decision rule:** `100503` alone is a P2 escalation. `100503` followed by `100504` or `100505`
within the same session is a P1 and does not wait for L2 availability — invoke the containment
path in the escalation matrix.

**What to collect before escalating:**

```
GET wazuh-alerts-*/_search
{
  "query": { "bool": { "filter": [
    { "terms": { "rule.id": ["100500","100501","100502","100503","100504","100505"] } },
    { "term":  { "data.srcip": "<SOURCE_IP>" } }
  ]}},
  "sort": [ { "@timestamp": "asc" } ],
  "size": 500
}
```

That query is the timeline. Paste it into the ticket, not a screenshot of it.

> **Lab caveat, stated plainly.** Cowrie in this lab listens on high ports (`55222`/`55223`)
> because port 22 is used by CALDERA, and observed source IPs are Docker bridge addresses.
> Source-IP diversity in an internet-exposed deployment would be far higher. The *chain logic*
> transfers; the *volume statistics* do not.

### 3.2 Threat-intelligence match (OSINT CDB)

Rules `113100–113103` match `srcip` and `dstip` against a CDB list built from AlienVault
indicators via FireHOL.

An indicator match is **context, not a verdict.** OSINT feeds carry stale entries, shared
hosting, CDN edges and Tor exits.

| Direction | Interpretation | Default severity |
| --- | --- | --- |
| Inbound (`srcip` match) | Known-bad host contacting us. Usually background scanning. | P3 |
| **Outbound (`dstip` match)** | **An internal host is initiating contact with a known-bad destination.** | **P2 — always** |

Outbound is the one that matters. Inbound scanning is weather; outbound beaconing means
something on the inside chose that destination.

Escalate any outbound match with: the internal host, the process (Auditd/Falco), the flow
volume and duration (Zeek), and whether the pattern is periodic.

### 3.3 Suricata IPS drop (`113000–113005`)

Suricata runs inline via NFQUEUE queue 3, so a drop means the packet was **blocked**, not
merely observed.

- A drop is a *successful control*, not an incident. Do not open a P1 for a blocked packet.
- Rule `113005` fires on 10+ drops from one source within 60 seconds. That is a targeted
  attempt and warrants P3 investigation of what the source was reaching for.
- **The alert that matters is the one that is missing.** If a source generated drops and then
  went quiet, check whether it found a path that was not inspected.

---

## 4. Ticket quality standard

An L2 analyst should be able to act without re-doing your work. Every escalation carries:

```
TITLE      <severity> — <what happened> on <asset>
TIMELINE   UTC timestamps, first to last observed event
SOURCE     IP, geo, ASN, OSINT CDB status, prior 30-day history
ASSET      Hostname, role, owner, exposure
DETECTION  Rule IDs fired, in order, with levels
EVIDENCE   The DevTools query used, not a screenshot of its output
IMPACT     What is confirmed changed. What is confirmed NOT changed.
            What has not been checked yet.
ACTIONS    What you already did, with timestamps
ASK        The specific decision or capability you need from L2
```

The `ASK` line is the one most often omitted and the one L2 most needs. "Escalating for
review" wastes a handoff. "Need EDR memory capture on host X; I lack the permission" does not.

---

## 5. Closure codes

| Code | Use when |
| --- | --- |
| `true-positive/contained` | Malicious, action taken |
| `true-positive/no-impact` | Malicious, control worked, nothing to do |
| `false-positive/rule-defect` | Rule fired on the wrong thing — tuning item required |
| `false-positive/benign-activity` | Rule fired correctly, activity was legitimate |
| `expected/authorised` | Matches a change ticket or scheduled job — reference it |
| `insufficient-data` | Cannot determine — state exactly what evidence was missing |

`insufficient-data` is a legitimate outcome and should be used honestly. A rising rate of it is
a visibility gap, and that is a finding worth reporting.
