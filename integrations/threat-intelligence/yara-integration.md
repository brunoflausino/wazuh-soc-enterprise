# YARA Malware Detection Integration

## Overview

This document records the validated YARA malware detection integration implemented for Wazuh SIEM.

The integration provides:

- real-time malware scanning of files added to or modified in a monitored directory
- automatic triggering through Wazuh File Integrity Monitoring (FIM) and Active Response
- YARA result logging and Wazuh decoding
- centralized alert generation through custom Wazuh rules
- OpenSearch indexing for search, aggregation, and dashboarding
- visualization through the YARA Malware Detection Dashboard

---

## Environment

OS: Ubuntu 24.04 LTS  
Wazuh: 4.14.2  
YARA: 4.5.0  

Monitored path: /tmp/malware_samples  
Rules path: /opt/yara/rules/yara_rules.yar  
Log path: /opt/yara/logs/yara.log  

Rule IDs: 100300, 100301, 100302  

---

## Detection Architecture

FIM -> Active Response -> YARA -> Log -> Decoder -> Rule -> OpenSearch -> Dashboard

---

## Installation

Packages:

sudo apt update  
sudo apt install -y yara jq  

Directories:

sudo mkdir -p /opt/yara/rules  
sudo mkdir -p /opt/yara/logs  
sudo mkdir -p /tmp/malware_samples  

Permissions:

sudo chown -R root:wazuh /opt/yara  
sudo chmod -R 750 /opt/yara  

---

## Ruleset

rule test_malware {
    strings:
        $a = "MALWARE" nocase
    condition:
        $a
}

---

## Wazuh Configuration

Syscheck:

<directories realtime="yes">/tmp/malware_samples</directories>

Active Response:

command: yara_linux  
rules_id: 100301,100302  

---

## Decoder

Fields extracted:

- yara.rule  
- yara.target  
- yara.match  

---

## Custom Rules

100300: detection  
100301: modified  
100302: added  

---

## Validation

wazuh-logtest input:

YARA_MATCH rule=test_malware target=/tmp/malware_samples/test.bin match="Detected"

Expected:

rule 100300  
level 12  

---

## OpenSearch Validation

The following queries were used during validation and may vary in production environments.

GET wazuh-alerts-*/_search

Observed during validation:

Total hits: 11 (validation dataset)

---

## Dashboard

Alert Summary Metrics  
assets/yara/yara-alert-summary-metrics.png  

Detections by Rule ID  
assets/yara/yara-detections-by-rule-id.png  

Malware Rules Triggered  
assets/yara/yara-malware-rules-triggered.png  

Infected Files  
assets/yara/yara-infected-files-detected.png  

Detection Timeline  
assets/yara/yara-detection-timeline.png  

---

## Conclusion

YARA integration is fully operational and validated with real detection events.

