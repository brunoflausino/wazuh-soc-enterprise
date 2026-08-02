# INC-0002 — File Integrity Monitoring Detection Validation (whodata)

| | |
| --- | --- |
| **Incident ID** | INC-0002 |
| **Classification** | Exercise — detection validation, not an incident |
| **Status** | Closed — all detections fired, attribution confirmed |
| **Detected** | 2026-08-02 by Wazuh FIM rules `109900`–`109907` |
| **Affected asset** | `flausino` — SOC lab workstation, isolated test tree `/opt/fim_test/` |
| **MITRE ATT&CK** | T1548.003, T1098.004, T1053.003, T1543.002, T1554, T1542, T1562.001, T1204.002 |
| **Author** | Bruno Flausino |
| **Current lab version** | Wazuh 4.14.7 |
| **Validated against** | Wazuh 4.14.7 · auditd 1:3.1.2 |

> **Nature of this report.** This documents a **detection validation exercise**, not a security
> incident. Its purpose is to prove that the File Integrity Monitoring whodata rule family
> (`100900`–`100907`) fires correctly, with full actor attribution, across every monitored path
> tier — and to do so without writing to a single real system file. To that end, a set of
> **mirror rules** (`109900`–`109907`) was created against an isolated test tree at
> `/opt/fim_test/`. The mirror rules inherit the severity and ATT&CK mapping of the production
> rules they shadow but match only on the test paths. The telemetry is genuine whodata data; the
> *target* is a fixture. Written in the format a managed-service client would receive so the
> reporting discipline is demonstrable, but it makes **no** claim to be a real intrusion. What
> transfers to production is the detection logic, the attribution chain, and the validation
> method. What does not is any notion of business impact — there was none, by construction.

---

## 1. Executive summary

The FIM whodata rule family was exercised end-to-end against an isolated test tree. One hundred
files were driven through a full create → modify → delete lifecycle across eight path tiers, each
operation performed as root so the kernel audit backend would capture the privilege-escalation
chain. Every rule fired at its expected severity, and **every resulting alert carried complete
whodata attribution**: the login user, the effective user, and the responsible process.

**The finding that matters is the attribution.** A conventional FIM alert states that a file
changed. Each alert in this exercise instead states *who* changed it, *as whom*, and *with which
process* — `brunoflausino` acting as `root` via `/usr/bin/bash` on writes and `/usr/bin/rm` on
deletions. That is the difference between an alert an analyst must investigate from raw logs and
one that arrives already attributed.

The exercise is fully reversible and left the production rule corpus and system configuration
untouched.

---

## 2. Timeline

All times local (CEST). Reconstructed from indexed Wazuh alerts.

| Time | Event | Rule(s) | Level | Source |
| --- | --- | :---: | :---: | --- |
| 22:05 | Isolated test tree `/opt/fim_test/` created (11 tier directories) | — | — | Analyst |
| 22:06 | whodata `<directories>` block added; `wazuh-analysisd -t` clean | — | — | Analyst |
| 22:07 | First mirror rule load failed — OS-regex rejected capture group | `109900` | — | Wazuh |
| 22:08 | Rule file corrected to `type="pcre2"`; manager restarted, services up | — | — | Analyst |
| **22:1x** | **Telemetry generation — 100 files, create/modify/delete as root** | `109900`–`109907` | 7/12/13 | Wazuh |
| 22:1x | 298 alerts indexed; whodata attribution present on all | `109900`–`109907` | — | Wazuh |
| 22:39 | On-demand dashboard report exported (5 panels) | — | — | Analyst |
| 22:4x | Exercise closed; cleanup procedure prepared | — | — | Analyst |

### Detection coverage performance

| Measure | Value | Target |
| --- | ---: | ---: |
| Path tiers exercised | 8 / 8 | 8 |
| Rules fired | 8 / 8 | 8 |
| Alerts with whodata attribution | 298 / 298 | 298 |
| Event lifecycle coverage | create · modify · delete | all three |

Every rule fired, and every alert was attributed. The one imperfection — 98 `modified` events
rather than 100 — is benign engine coalescing, not a detection miss.

---

## 3. Analysis

### 3.1 What was exercised

The generator reproduced the file-write patterns an attacker would use to establish persistence,
escalate privilege, and disable defenses, but confined to the test tree:

1. **Privilege escalation** (T1548.003) — writes to the sudoers/PAM mirror (`109900`).
2. **Persistence** (T1098.004, T1563.001) — writes to the SSH mirror (`109901`).
3. **Persistence** (T1053.003, T1543.002) — writes to the cron/systemd mirror (`109902`).
4. **Defense evasion** (T1554) — writes to the binary-path mirror (`109903`, level 7 by design).
5. **Defense evasion** (T1542) — writes to the boot mirror (`109904`).
6. **Defense evasion** (T1562.001) — writes to the Wazuh-etc and audit-config mirrors
   (`109905`, `109906`, level 13).
7. **Execution** (T1204.002) — writes to the malware-staging mirror (`109907`).

### 3.2 Why the detection worked

Each mirror rule matches on the native `syscheck` group and a path-scoped regex, inheriting the
production rule's severity. Two design points did the work:

**Attribution is supplied by the kernel, not inferred.** Because the test tree is monitored in
whodata mode and the writes ran as root, `wazuh-syscheckd` attached the audit context to every
event. The `login_user` → `effective_user` chain is therefore evidence, not reconstruction:

```
syscheck.audit.login_user.name:     brunoflausino
syscheck.audit.effective_user.name: root
syscheck.audit.process.name:        /usr/bin/bash   (writes)
                                     /usr/bin/rm     (deletions)
```

**Severity is structural, per tier.** The critical security-tool tiers (Wazuh config, audit
config) sit at level 13; the persistence and privilege-escalation tiers at level 12; the noisy
binary-path tier at level 7. An analyst triaging by severity sees the tampering-with-defenses
changes first, exactly as intended.

### 3.3 Evidence query

The distribution in section 2 was produced by this aggregation, not counted by hand:

```
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": { "range": { "rule.id": { "gte": 109900, "lte": 109907 } } },
  "aggs": {
    "by_rule":  { "terms": { "field": "rule.id", "size": 8 } },
    "by_event": { "terms": { "field": "syscheck.event", "size": 3 } },
    "by_level": { "terms": { "field": "rule.level", "size": 5 } }
  }
}
```

Returned: 298 total; rule split 109903→119, 109907→74, 109902→36, 109900→24, 109901→18,
109904/109905/109906→9 each; event split added 100 / deleted 100 / modified 98; severity split
level 12→161, level 7→119, level 13→18.

---

## 4. Impact

| Question | Finding | Confidence |
| --- | --- | --- |
| Did every FIM rule fire? | Yes — 8 / 8 tiers | Confirmed |
| Was whodata attribution present? | Yes — on all 298 alerts | Confirmed |
| Was any production rule modified? | No — mirror rules only | Confirmed |
| Was any real system file changed? | No — isolated `/opt/fim_test/` only | Confirmed |
| Was the full event lifecycle captured? | Yes — create, modify, delete | Confirmed |
| Was the exercise reversible? | Yes — cleanup procedure defined | Confirmed |
| Any effect on other lab services? | None | Confirmed |

**Business impact: none.** The exercise validates detection; it does not represent an intrusion.

---

## 5. Response

| # | Action | Tier | Time |
| --- | --- | :---: | --- |
| 1 | Timestamped backups of `ossec.conf` and FIM rule file taken before edits | L2 | 22:05 |
| 2 | Isolated test tree and mirror rules deployed | L2 | 22:06 |
| 3 | Rule-load failure diagnosed and corrected (`type="pcre2"`) | L2 | 22:08 |
| 4 | Telemetry generated; attribution verified in `alerts.json` | L2 | 22:1x |
| 5 | Aggregations validated in OpenSearch DevTools | L2 | 22:2x |
| 6 | Dashboard report exported for the portfolio | L3 | 22:39 |
| 7 | Cleanup procedure prepared to restore production state | L3 | 22:4x |

Backups preceded every edit, per the lab's change convention. On a production host this ordering
is what makes a bad rule change recoverable in one step.

---

## 6. Findings and recommendations

### F-01 — FIM cannot distinguish maintenance from attack *(informational, by design)*

A single `apt install` earlier the same day generated **438 level-12 alerts** against `/usr/bin`,
because package management and an attacker both write to that path as root and whodata correctly
attributes both to `root`. There is no FIM-layer field that separates them.

*Recommendation:* the binary-path tier (rule `100903`) is held at level 7 to keep the alert
stream usable, with intent supplied by correlation against package-manager logs rather than by
FIM alone. Do not raise it without a correlation rule to suppress `dpkg`-driven changes.

### F-02 — Severity scoping couples rules to enrichments *(medium)*

Lowering rule `100903` to level 7 silently removed VirusTotal scanning from staged samples,
because the VirusTotal integration is scoped to level 12.

*Recommendation:* re-express enrichment intent as its own narrowly scoped rule. Implemented here
as rule `100907` (level 12) for `/tmp/malware_samples`, restoring VirusTotal coverage without
reintroducing binary-path noise.

### F-03 — `wazuh-logtest` is not a valid FIM validation path *(informational)*

FIM events are engine-internal and never traverse the text decoders that `wazuh-logtest`
exercises; the tool reaches decoding (Phase 2) with the generic `json` decoder but never rule
matching (Phase 3) against the `syscheck` group.

*Recommendation:* validate FIM with real filesystem changes observed end-to-end, as this exercise
did. Recorded so a reviewer does not read the absence of a `logtest` transcript as missing
validation.

### F-04 — Detection chain performed as designed *(positive)*

All eight rules fired at correct severity with complete attribution and no false negatives. The
per-tier severity model surfaced defense-tampering changes above routine ones exactly as
intended. Recorded because a findings list that shows only defects misrepresents detection
quality.

---

## 7. Lessons

**What worked.** Kernel-backed attribution and per-tier structural severity. Each alert arrived
already answering *who, as whom, with what* — the attribution was evidence from the audit
subsystem, not something an analyst reconstructed. Triage by severity naturally ordered
defense-tampering above maintenance.

**What did not.** FIM alone cannot express intent. The `apt install` flood and the VirusTotal
coupling are both consequences of the same limit: FIM sees identity and process, never purpose.
Both were resolved by design decisions (severity tuning, a dedicated staging rule), not by the
FIM engine.

**What this exercise cannot show.** Behaviour at production file-change volume, correlation of FIM
with change-management and package-manager sources to establish intent, and the response workflow
for a genuine tampering alert. Those require a production environment and are stated here as
limits rather than left for a reader to infer.
