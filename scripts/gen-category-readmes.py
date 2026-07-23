#!/usr/bin/env python3
"""Generate uniform category READMEs for integrations/*/."""
import os, textwrap

ROOT = "integrations"

# category -> (title, tagline, [ (slug, display, what it detects, rules, id range, attack) ])
CATS = {
"threat-intelligence": (
  "Threat Intelligence & Detection",
  "Indicator correlation, adversary emulation, honeypot telemetry and host-level "
  "behavioural detection. The largest category in the lab and the core of its detection content.",
  [
   ("osint-cdb","OSINT CDB","Native Wazuh CDB list of public IPv4 indicators; bidirectional srcip/dstip correlation","4","113100-113103","T1071, T1595"),
   ("misp","MISP","Threat-intel platform integration; IoC lookup and enrichment on alerts","2","100700-100701","T1071"),
   ("spiderfoot","SpiderFoot","OSINT reconnaissance events ingested as JSONL; no custom decoder required","6","113200-113205","T1589, T1590, T1595"),
   ("caldera","MITRE CALDERA","Adversary emulation; validates detection coverage against executed TTPs","3","110500-110502","T1046, T1059.003, T1082"),
   ("cowrie","Cowrie honeypot","SSH/Telnet attack chain: brute force, successful auth, command execution, payload retrieval","9","100500-100508","T1110.001, T1059, T1105"),
   ("falco","Falco (eBPF)","Kernel-level runtime detection of syscall and process anomalies","8","100600-100607","T1055, T1059, T1046"),
   ("auditd","Auditd","Host audit trail with a dedicated MITRE-mapped rule pack","22","110700-110721","T1021, T1055, T1059, T1070"),
   ("yara","YARA","Signature-based file scanning wired to Active Response","3","100300-100302","T1204"),
  ]),
"network-security": (
  "Network Security",
  "Perimeter and network-layer detection: inline prevention, protocol metadata, "
  "encrypted tunnelling and host firewall telemetry.",
  [
   ("suricata","Suricata IDS/IPS","Inline IPS via NFQUEUE queue 3; 7 custom SIDs plus Wazuh correlation with frequency logic","6","113000-113005","T1046, T1071.001, T1021"),
   ("zeek","Zeek NSM","Protocol metadata across 7 log streams: CONN, DNS, HTTP, SSL, FILES, NOTICE, WEIRD","--","native","T1021, T1018, T1573"),
   ("wireguard","WireGuard","VPN tunnel establishment, peer handshakes and session anomalies","12","100200-100222","--"),
   ("ufw","UFW","Host firewall drops, blocked ports and source-IP patterns","9","100100-100108","T1046, T1110, T1499"),
  ]),
"incident-response": (
  "Incident Response & SOAR",
  "Forensic collection and response automation -- the layer that turns an alert into an action.",
  [
   ("velociraptor","Velociraptor DFIR","Endpoint forensics, live collection and server audit trail; chained decoders resolve generic-JSON conflicts","17","100400-100419","T1021.004, T1046, T1059, T1070.004"),
   ("shuffle","Shuffle SOAR","Workflow orchestration, alert enrichment and automated response paths","--","workflow","T1548.001"),
  ]),
"data-protection": (
  "Data Protection",
  "Malware scanning, encryption, secure erasure and backup integrity -- the preventive and "
  "recovery side of the stack.",
  [
   ("clamav","ClamAV","Antivirus scan results and signature-database health","1","52502","T1562.001"),
   ("veracrypt","VeraCrypt","Encrypted volume mount, dismount and access anomalies","5","110200-110211","--"),
   ("nwipe","NWIPE","Secure disk erasure with verified completion events","3","100500-100502","--"),
   ("restic","Restic","Backup job success, failure and repository integrity","--","native","--"),
  ]),
"authentication": (
  "Authentication",
  "RADIUS-based authentication monitoring: credential attacks, policy decisions and "
  "proxy-tier health.",
  [
   ("freeradius","FreeRADIUS","Authentication accept/reject decisions, credential guessing and account anomalies","5","110010-110204","T1078, T1110.001"),
   ("radsecproxy","Radsecproxy","RadSec proxy health, TLS peer failures and relay availability","7","110101-110306","T1078, T1110, T1499, T1557"),
  ]),
"system-inventory": (
  "System Inventory",
  "Endpoint visibility and host posture: continuous inventory, configuration drift and "
  "surface enumeration rather than threat detection.",
  [
   ("osquery","OSQuery","Scheduled queries over processes, packages, users, cron and container images","2","24010 / 100000","T1053.003, T1098.004, T1136, T1547.006"),
  ]),
"vulnerability-scan": (
  "Vulnerability Management",
  "Authenticated and unauthenticated scanning, with findings routed into the SIEM for "
  "triage alongside detection alerts.",
  [
   ("openvas","OpenVAS / GVM","CVE findings by host and severity, feeding a critical-triage queue","5","100205-100209","--"),
  ]),
}

BANNER = ('<!-- soc-banner -->\n<p align="center">'
          '<img src="assets/banners/banner-{slug}.svg" alt="{title} -- Wazuh SOC" width="100%"></p>\n')

for slug,(title,tagline,items) in CATS.items():
    rows = "\n".join(
        f"| **[{d}]({s}-integration.md)** | {w} | {r} | `{i}` | {a} |"
        for s,d,w,r,i,a in items)
    body = f"""{BANNER.format(slug=slug, title=title)}
# {title}

{textwrap.fill(tagline, 92)}

**{len(items)} documented integration{'s' if len(items)!=1 else ''}** in this category.
Each guide includes configuration, validated `wazuh-logtest` output, OpenSearch DevTools
queries and dashboard screenshots captured during validation.

---

## Integrations

| Integration | What it detects | Rules | ID range | MITRE ATT&CK |
| --- | --- | :---: | --- | --- |
{rows}

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
"""
    path = os.path.join(ROOT, slug, "README.md")
    open(path,"w").write(body)
    print(f"  wrote {path}  ({len(items)} integrations)")
