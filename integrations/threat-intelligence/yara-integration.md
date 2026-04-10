# YARA Malware Detection Integration

## Overview

This document records a fully validated YARA malware detection integration implemented in Wazuh SIEM.

The integration provides:

- real-time malware scanning
- automated triggering via File Integrity Monitoring (FIM)
- Active Response execution
- structured alert generation
- OpenSearch indexing
- dashboard visualization

---

## Environment

Operating system: Ubuntu 24.04 LTS  
Wazuh version: 4.14.2  
YARA version: 4.5.0  

Monitored directory: /tmp/malware_samples  
Rules file: /opt/yara/rules/yara_rules.yar  
Log file: /opt/yara/logs/yara.log  

Rule IDs: 100300, 100301, 100302  

---

## Detection Architecture

Flow:

File event -> FIM -> Rule -> Active Response -> YARA -> Log -> Decoder -> Rule -> OpenSearch -> Dashboard

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

## Active Response

Script path:

/var/ossec/active-response/bin/yara_scan.sh

Execution logic:

- receives JSON input from Wazuh
- extracts file path
- validates existence
- runs YARA scan
- writes detection to log
- triggers alert pipeline

---

## Decoder

Extracted fields:

- yara.rule  
- yara.target  
- yara.match  

---

## Custom Rules

100300: confirmed malware detection (level 12)  
100301: file modified trigger  
100302: file added trigger  

---

## Validation

wazuh-logtest input:

YARA_MATCH rule=test_malware target=/tmp/malware_samples/test.bin match="Detected"

Expected result:

rule.id: 100300  
level: 12  

---

## OpenSearch Validation

Query used:

GET wazuh-alerts-*/_search

Validation dataset result:

Total hits: 11  

Aggregation:

100302 -> 7  
100300 -> 3  
100301 -> 1  

---

## Dashboard

### Alert Summary Metrics
![metrics](assets/yara/yara-alert-summary-metrics.png)

### Detections by Rule ID
![rule-id](assets/yara/yara-detections-by-rule-id.png)

### Malware Rules Triggered
![rules](assets/yara/yara-malware-rules-triggered.png)

### Infected Files
![files](assets/yara/yara-infected-files-detected.png)

### Detection Timeline
![timeline](assets/yara/yara-detection-timeline.png)

---

## Troubleshooting

Resolved issues:

- decoder parsing failure
- missing log_format
- Active Response not triggering
- XML syntax errors
- permission issues in /opt/yara

---

## Conclusion

The YARA integration is fully operational, validated, and production-ready.

