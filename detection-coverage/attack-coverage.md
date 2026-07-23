# MITRE ATT&CK Coverage — Enterprise (Linux)

> **Current lab version:** Wazuh 4.14.6
> **Rule corpus:** 188 custom rules across 14 files (see [`METRICS.md`](../METRICS.md))
> **Last assessed:** 2026-07-23

This document states what the deployed detection content covers, at what confidence, and —
more importantly — **what it does not cover.**

A coverage matrix that shows only green is a marketing document. The uncovered half of this
page is the part worth reading, and the part a detection engineer is actually assessed on.

---

## 1. Confidence scale

Coverage is not binary. A rule that fires on the default tooling and nothing else is not
coverage of a technique; it is coverage of a tool.

| Level | Meaning |
| :---: | --- |
| ⬛ **Strong** | Behavioural detection, validated end-to-end, resistant to trivial evasion |
| 🟩 **Partial** | Detects common implementations; evadable by a competent operator |
| 🟨 **Weak** | Telemetry exists, detection is signature-bound or noisy |
| ⬜ **None** | No detection content, or no telemetry at all |

---

## 2. Coverage by tactic

### Reconnaissance (TA0043)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1595 Active Scanning | ⬛ | Suricata `113000–113005`, GNN chain `100631` | Inline IPS; validated against Nmap SYN scan |
| T1590 Gather Victim Network Info | 🟩 | SpiderFoot `113200–113205` | OSINT-derived; detects the reconnaissance record, not the act |
| T1589.001/.002 Gather Identity Info | 🟩 | SpiderFoot `113200–113205` | Same limitation |
| T1596 Search Open Technical Databases | 🟨 | SpiderFoot | Passive; low operational value |

### Initial Access (TA0001)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1110 Brute Force | ⬛ | Cowrie `100501–100503`, FreeRADIUS | Full chain incl. success, not just failures |
| T1110.001 Password Guessing | ⬛ | Cowrie `100502`/`100503` | Validated in INC-0001 |
| T1078 Valid Accounts | 🟨 | Auth logs, FreeRADIUS | **Weak.** No behavioural baselining — a valid login from a new source at an unusual hour is not detected |
| T1190 Exploit Public-Facing App | 🟩 | Suricata + ET ruleset | Signature-bound |
| T1566 Phishing | ⬜ | — | No email telemetry in scope |

### Execution (TA0002)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1059 Command and Scripting Interpreter | 🟩 | Auditd `110700–110721`, Falco, Cowrie `100504` | Broad execution visibility; command-line *content* analysis is thin |
| T1059.004 Unix Shell | 🟩 | Auditd, Falco | |
| T1204 User Execution | ⬜ | — | No endpoint user context |

### Persistence (TA0003)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1136 Create Account | 🟩 | Auditd MITRE pack | |
| T1543 Create/Modify System Process | 🟩 | Auditd, Falco | systemd unit changes |
| T1053 Scheduled Task/Job | 🟨 | Auditd FIM on cron paths | **File-based only.** `systemd` timers and user crontabs are not reliably covered |
| T1546 Event Triggered Execution | ⬜ | — | No coverage |
| T1098 Account Manipulation | 🟨 | Auditd | Modification detected; authorisation context absent |

### Privilege Escalation (TA0004)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1548.001 Setuid/Setgid | 🟩 | Auditd MITRE pack | |
| T1055 Process Injection | 🟨 | Falco (eBPF) | Detects common patterns; ptrace-based injection partially covered |
| T1068 Exploitation for Priv Esc | ⬜ | — | No kernel-exploit detection |

### Defense Evasion (TA0005)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1070 Indicator Removal | 🟩 | Auditd, FIM | |
| T1070.006 Timestomp | 🟩 | Auditd | |
| T1562 Impair Defenses | 🟩 | Auditd, Falco | Covers stopping the agent; **does not cover an attacker who never triggers it** |
| T1027 Obfuscated Files | 🟨 | YARA `100301`/`100302`, ClamAV | Signature-bound |
| T1036 Masquerading | ⬜ | — | No coverage |
| T1620 Reflective Code Loading | ⬜ | — | No coverage |

### Credential Access (TA0006)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1110 Brute Force | ⬛ | Cowrie, FreeRADIUS | |
| T1003 OS Credential Dumping | 🟨 | Auditd on `/etc/shadow` | **File access only.** Memory-based dumping is not detected |
| T1552 Unsecured Credentials | ⬜ | — | No secret-scanning content |
| T1558 Steal/Forge Kerberos | ⬜ | — | No Kerberos or AD in scope |

### Discovery (TA0007)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1046 Network Service Discovery | ⬛ | Suricata `113000–113005`, GNN chain | Best-covered technique in the lab; subject of the ML benchmark |
| T1082 System Information Discovery | 🟩 | Auditd, OSQuery | High false-positive rate — normal admin activity is identical |
| T1083 File and Directory Discovery | 🟨 | Auditd | Very noisy |
| T1018 Remote System Discovery | 🟨 | Zeek | |

### Lateral Movement (TA0008)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1021 Remote Services | 🟩 | Zeek, Suricata, auth logs | |
| T1021.004 SSH | 🟩 | Zeek, auth logs, Cowrie | |
| T1570 Lateral Tool Transfer | 🟨 | Zeek, GNN chain `100635` | |
| T1550 Alternate Auth Material | ⬜ | — | No coverage |

### Collection (TA0009)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1119 Automated Collection | 🟨 | Auditd | |
| T1005 Data from Local System | ⬜ | — | No DLP or data-classification telemetry |

### Command and Control (TA0011)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1071 Application Layer Protocol | 🟩 | Suricata, Zeek, GNN `100632` | |
| T1071.001 Web Protocols | 🟩 | Suricata + ET | |
| T1105 Ingress Tool Transfer | ⬛ | Cowrie `100505`, Suricata, ClamAV | Validated in INC-0001 |
| T1573 Encrypted Channel | 🟨 | Zeek JA3/JA4 | **Metadata only** — no TLS inspection |
| T1090 Proxy | ⬜ | — | Tor/proxy detection limited to OSINT CDB matches |
| T1102 Web Service C2 | 🟨 | OSINT CDB `113100–113103` | Indicator-based; fails on novel infrastructure |
| T1568 Dynamic Resolution | ⬜ | — | DNS telemetry ingested via Zeek, but **no DNS detection rules exist**. See gap G-01 |

### Impact (TA0040)

| Technique | Coverage | Detection source | Notes |
| --- | :---: | --- | --- |
| T1499 Endpoint DoS | 🟩 | Suricata, GNN `100634` | |
| T1486 Data Encrypted for Impact | ⬜ | — | **No ransomware behavioural detection.** See gap G-02 |
| T1490 Inhibit System Recovery | ⬜ | — | No coverage |
| T1485 Data Destruction | ⬜ | — | No coverage |

---

## 3. Coverage summary

| Confidence | Techniques |
| --- | ---: |
| ⬛ Strong | 6 |
| 🟩 Partial | 17 |
| 🟨 Weak | 14 |
| ⬜ None | 14 |

**Read this honestly:** of 51 techniques assessed, only 6 have detection that would resist a
competent operator. The lab has broad *telemetry* and narrow *detection*. That is the normal
state of a young SOC and the correct thing to say out loud.

The assessment covers 51 techniques selected as relevant to a Linux-only, on-premises,
non-identity environment. ATT&CK Enterprise contains far more; the remainder are out of scope
rather than uncovered, and are not counted as either.

---

## 4. Priority gaps

Ordered by detection value per unit of effort, not by severity.

### G-01 — DNS telemetry is collected but not used for detection *(highest priority)*

Zeek `dns.log` is ingested and indexed. DNS is the **largest single event source in the lab at
47.89% of all Zeek events**, ahead of CONN at 47.68%. The dashboards visualise it.

**Not one detection rule reads it.** The most voluminous telemetry in the environment feeds
charts and nothing else.

Uncovered as a result: T1568 dynamic resolution, T1071.004 DNS C2, DGA beaconing, and DNS-based
exfiltration. These are among the cheapest high-value detections available, and the data is
already sitting in the index.

*Remediation:* correlation rules over the existing `dns.log` stream — NXDOMAIN rate per host,
query-name length and entropy distribution, low-TTL patterns, and volume of queries to
newly-observed domains. No new telemetry, no new tooling.

**Cost: one afternoon. Value: the largest coverage gain available in the lab, from data already
being collected.** The gap is analytical, not architectural — which makes it both more
embarrassing and easier to close.

### G-02 — No ransomware behavioural detection *(high)*

T1486 has no coverage. YARA and ClamAV are signature-bound and will miss anything novel.

*Remediation:* Falco rules for rapid sequential file modification, plus a FIM velocity rule
(mass writes to user directories within a short window). Behavioural, not signature-based.

### G-03 — No identity behavioural baseline *(high)*

T1078 valid accounts is weak. Authentication is logged but never compared to normal — a valid
credential used from a new source at an unusual hour looks identical to routine access.

*Remediation:* per-user baselines of source IP, hour-of-day and access pattern, with rules
firing on deviation. This is the most direct application of the author's ML background, and a
far better use of it than the GNN work.

### G-04 — No memory-based credential access detection *(medium)*

T1003 is file-access-only. Process memory access against credential-holding processes is not
monitored.

*Remediation:* Falco rules on `ptrace` and `/proc/*/mem` access targeting authentication
processes.

### G-05 — TLS metadata only *(accepted)*

T1573 is metadata-only via JA3/JA4. Full TLS inspection requires interception infrastructure
that is out of scope for a single-workstation lab.

*Status:* **accepted limitation**, not a remediation item. Documented so its absence is a
decision rather than an oversight.

---

## 5. Method and limitations

**How coverage was assessed.** Each deployed rule was mapped to the technique it references,
then downgraded where the detection depends on default tooling behaviour, a static signature, or
a single evadable indicator. Confidence reflects resistance to evasion, not whether the rule
fires in a test.

**What this assessment does not do:**

- No adversary emulation was run to validate coverage claims. CALDERA is deployed and this is
  the obvious next step: emulate each ⬛ and 🟩 technique and downgrade whatever fails to fire.
  Until that happens, these ratings are **design-time assessments, not empirical ones.**
- Detection *efficacy* is not measured. No true-positive or false-positive rates per technique.
- Coverage is assessed for Linux only. Windows, macOS, cloud and identity are entirely absent —
  a serious limitation for most employers, and one no single-workstation lab can address.
- The 51 techniques assessed were selected by the author. That selection is itself a judgement
  and a source of bias.
