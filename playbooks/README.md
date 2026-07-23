# SOC Operational Playbooks

Procedures governing how alerts are handled in this lab, written in the format a managed SOC
uses. They exist because detection content alone does not demonstrate operational readiness —
knowing *what* to detect and knowing *what to do at 03:00 when it fires* are different skills,
and only one of them shows up in a rule file.

| Document | Purpose |
| --- | --- |
| [L1 Alert Triage Playbook](L1-triage-playbook.md) | Severity model, SLA targets, the five-question triage loop, worked triage paths for the three highest-volume detection chains, ticket standard, closure codes |
| [Escalation Matrix](escalation-matrix.md) | L1/L2/L3 responsibilities, escalation triggers, containment authority, Active Response boundaries, communication and shift handover |

## Scope and honesty statement

These procedures are written against detection content actually deployed in this lab — every
rule ID referenced exists and is validated. They are structured for a multi-tier 24/7 SOC
because that is the environment they are meant to demonstrate fluency in.

They have **not** been operated under real shift conditions, real client SLAs, or real alert
volume. What they demonstrate is command of SOC procedure, severity reasoning and escalation
discipline. What they cannot demonstrate is having done it at 03:00 with forty alerts queued.
That distinction is stated here rather than left for a reviewer to discover.
