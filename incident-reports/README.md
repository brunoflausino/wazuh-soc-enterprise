# Incident Reports

Worked incident reports in client-deliverable format, produced from real detections in this lab.

| Report | Severity | Detection chain | ATT&CK |
| --- | --- | --- | --- |
| [INC-0001 — SSH credential compromise and payload retrieval](2026-07-16-INC-0001-ssh-honeypot-compromise.md) | P1 | Cowrie `100501–100508` | T1110.001, T1059, T1105 |

Use [`TEMPLATE.md`](TEMPLATE.md) for new reports.

## What these are, and are not

Each report documents a genuine detection firing on genuine activity, written in the format a
managed-service client would receive. The purpose is to demonstrate investigative reasoning,
timeline construction and reporting discipline.

They are lab incidents. Business impact is nil, scale is small, and there is no client on the
other end. Every report states its own limits in a scope note rather than leaving the reader to
work out where the exercise ends.
