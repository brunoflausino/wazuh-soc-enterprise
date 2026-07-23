# Escalation Matrix — L1 / L2 / L3

> **Current lab version:** Wazuh 4.14.6
> **Last revised:** 2026-07-23

Defines who handles what, what each tier is authorised to do without asking, and what triggers
a handoff. Written for a single-analyst lab, but structured the way a multi-tier SOC operates —
the boundaries are the point.

---

## 1. Tier responsibilities

| | **L1 — Triage** | **L2 — Investigation** | **L3 — Engineering & Hunt** |
| --- | --- | --- | --- |
| **Owns** | Alert queue, initial classification, first response SLA | Incident ownership, scope determination, containment | Detection content, root cause, threat hunting |
| **Typical output** | Closed alert or escalation ticket | Incident report, containment decision | New/tuned rules, hunt findings, post-incident review |
| **Authorised without approval** | Query any data source; enrich; close P3/P4; block a source already on the OSINT CDB list via Active Response | Isolate a host; kill a process; disable an account; take forensic images | Modify production rules; change ingestion; alter Active Response |
| **Requires approval** | Anything that changes system state on a non-lab asset | Anything affecting a production service | Anything reducing detection coverage |
| **Never does** | Modify rules; close P1/P2; touch evidence | Close their own incident without review on P1 | Bypass the four-stage validation gate |

---

## 2. Escalation triggers

### L1 → L2 — mandatory

Escalate immediately, do not continue triaging, when any of these are true:

- Severity is **P1 or P2** after the promotion rules in the triage playbook
- **Authentication succeeded** after failed attempts from the same source (Cowrie `100503`)
- **Outbound** connection to an OSINT CDB indicator (`113101`/`113103`)
- Malware download or execution attempt (`100505`, YARA `100301`/`100302`)
- Any alert on a host that already has an open incident
- Persistence mechanism observed (Auditd MITRE pack `110700–110721`)
- L1 has spent **45 minutes** without reaching a classification

That last one is not a failure condition. It is a cost control. An L1 stuck for 45 minutes is
usually missing a capability, not effort.

### L2 → L3 — mandatory

- Root cause not established after containment
- Detection gap identified — the activity was found manually, not by a rule
- Rule change required to contain the incident
- The same incident pattern has occurred **three times** — this is an engineering problem now
- Evidence suggests the detection pipeline itself was affected

### Any tier → out-of-band

Immediately, in parallel with normal escalation:

- Suspected compromise of the SIEM, the manager, or the analyst workstation
- Evidence of log tampering or deletion (`T1070`, `T1070.006`)
- Destructive action in progress

---

## 3. Containment authority

The rule: **the fastest safe containment that does not destroy evidence.**

| Action | L1 | L2 | L3 | Evidence risk |
| --- | :---: | :---: | :---: | --- |
| Block source IP (Active Response `firewall-drop`) | ✅ if already on CDB list | ✅ | ✅ | None |
| Block source IP (arbitrary) | ❌ | ✅ | ✅ | None |
| Isolate host from network | ❌ | ✅ | ✅ | Low — preserves memory |
| Kill process | ❌ | ✅ | ✅ | **High — destroys process memory** |
| Disable account | ❌ | ✅ | ✅ | None |
| Power off host | ❌ | ❌ | ✅ + approval | **Destroys all volatile evidence** |
| Reimage | ❌ | ❌ | ✅ + approval | **Destroys everything** |

**Order of operations for a confirmed compromise:**

1. Capture volatile state **first** — Velociraptor collection before anything else
2. Isolate the network, do not power off
3. Preserve, then contain
4. Only then remediate

Killing the process before the memory capture is the most common irreversible mistake in
incident response. It feels decisive and it deletes the answer.

---

## 4. Active Response in this lab

Two automated responses are live. Both are containment actions taken without human approval,
which means both need explicit boundaries.

| Response | Trigger | Action | Timeout | Risk |
| --- | --- | --- | --- | --- |
| `firewall-drop` | Rule `5763` | Drops source IP | 600 s | Self-inflicted denial of service if an internal or shared-egress IP is matched |
| `yara_linux` | Rules `100301`/`100302` | Scans and quarantines | — | File-integrity impact if a false positive quarantines a live file |

**Never enable Active Response on a rule that can match internal infrastructure.** The
`firewall-drop` timeout exists so a misfire self-heals in ten minutes rather than requiring
console access to a host you just cut yourself off from.

Every Active Response firing is reviewed by L2 the same shift, even when correct. Automation
that nobody audits stops being automation and becomes weather.

---

## 5. Communication

| Severity | Notify | When | Channel |
| --- | --- | --- | --- |
| P1 | L2 + L3 + service owner | Immediately | Voice, then written |
| P2 | L2 + service owner | Within 30 min | Written, acknowledgement required |
| P3 | L2 | Shift handover | Ticket |
| P4 | — | Weekly summary | Report |

**Voice first for P1, always followed in writing.** A phone call that leaves no record did not
happen, and a chat message nobody read is not a notification.

### Shift handover

Every handover transfers, in writing:

- Open incidents with current state and next action
- Alerts deliberately left un-triaged, and why
- Detection changes made during the shift
- Anything degraded: ingestion gaps, agents offline, dashboards broken

The handover note is the only artifact proving continuity across a 24/7 rota. It is not
optional and it is not a formality.
