#!/bin/bash
# modelscan_scan.sh — Wazuh Active Response for ML model security scanning
# Triggered by FIM events on /opt/model-scan-lab/incoming/
# Scans the model with ModelScan; quarantines on CRITICAL/HIGH findings.
#
# Exit codes from modelscan: 0=clean, 1=issues found, 2=error, 4=path not found
#
# Deploy to: /var/ossec/active-response/bin/modelscan_scan.sh
# Ownership : root:wazuh   Permissions: 750

MODELSCAN_BIN="/opt/modelscan/venv/bin/modelscan"
LAB_DIR="/opt/model-scan-lab"
QUARANTINE_DIR="${LAB_DIR}/quarantine"
LOG_FILE="${LAB_DIR}/logs/modelscan-events.json"
TMP_REPORT="/tmp/modelscan_ar_$$.json"

# --- Read the Wazuh AR input from stdin ---
read -r INPUT_JSON

# Extract the file path that triggered FIM
FILE_PATH=$(echo "$INPUT_JSON" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('parameters',{}).get('alert',{}).get('syscheck',{}).get('path',''))" \
  2>/dev/null)

# Guard: no path, nothing to do
if [ -z "$FILE_PATH" ] || [ ! -f "$FILE_PATH" ]; then
    exit 0
fi

# Guard: only scan model file extensions
case "$FILE_PATH" in
    *.pkl|*.pickle|*.pt|*.pth|*.h5|*.hdf5|*.bin|*.joblib|*.dill) ;;
    *) exit 0 ;;
esac

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
FILE_HASH=$(sha256sum "$FILE_PATH" 2>/dev/null | awk '{print $1}')
FILE_SIZE=$(stat -c%s "$FILE_PATH" 2>/dev/null)

# --- Run ModelScan ---
"$MODELSCAN_BIN" --path "$FILE_PATH" \
                 --reporting-format json \
                 --output-file "$TMP_REPORT" >/dev/null 2>&1
SCAN_EXIT=$?

# --- Parse the report and emit NDJSON (one object per line) ---
# The `modelscan_event` field name deliberately avoids `event_type`, which
# would collide with Wazuh's built-in Suricata rule 86600.
python3 << PYEOF >> "$LOG_FILE" 2>/dev/null
import json, sys

timestamp   = "$TIMESTAMP"
file_path   = "$FILE_PATH"
file_hash   = "$FILE_HASH"
file_size   = "$FILE_SIZE"
scan_exit   = $SCAN_EXIT
quarantined = False

try:
    with open("$TMP_REPORT") as f:
        report = json.load(f)
except Exception:
    print(json.dumps({
        "integration": "modelscan",
        "modelscan_event": "scan_error",
        "timestamp": timestamp,
        "file_path": file_path,
        "scan_exit_code": scan_exit,
        "error": "report_unreadable"
    }))
    sys.exit(0)

summary  = report.get("summary", {})
issues   = report.get("issues", [])
by_sev   = summary.get("total_issues_by_severity", {})
critical = by_sev.get("CRITICAL", 0)
high     = by_sev.get("HIGH", 0)

quarantined = (critical > 0 or high > 0)

# One line per issue
for issue in issues:
    print(json.dumps({
        "integration": "modelscan",
        "modelscan_event": "issue",
        "timestamp": timestamp,
        "file_path": file_path,
        "file_hash": file_hash,
        "file_size": file_size,
        "severity": issue.get("severity"),
        "operator": issue.get("operator"),
        "module": issue.get("module"),
        "description": issue.get("description"),
        "scanner": issue.get("scanner"),
        "quarantined": quarantined
    }))

# One summary line
print(json.dumps({
    "integration": "modelscan",
    "modelscan_event": "scan_summary",
    "timestamp": timestamp,
    "file_path": file_path,
    "file_hash": file_hash,
    "file_size": file_size,
    "modelscan_version": summary.get("modelscan_version"),
    "total_issues": summary.get("total_issues", 0),
    "critical": critical,
    "high": high,
    "medium": by_sev.get("MEDIUM", 0),
    "low": by_sev.get("LOW", 0),
    "scan_exit_code": scan_exit,
    "quarantined": quarantined
}))
PYEOF

# --- Quarantine on CRITICAL or HIGH ---
if [ "$SCAN_EXIT" -eq 1 ]; then
    SEVERITY_HIT=$(python3 -c \
      "import json; r=json.load(open('$TMP_REPORT')); s=r['summary']['total_issues_by_severity']; print(1 if (s.get('CRITICAL',0)>0 or s.get('HIGH',0)>0) else 0)" \
      2>/dev/null)
    if [ "$SEVERITY_HIT" = "1" ]; then
        mkdir -p "$QUARANTINE_DIR"
        QUARANTINE_NAME="$(basename "$FILE_PATH").$(date +%Y%m%d_%H%M%S).quarantined"
        mv "$FILE_PATH" "${QUARANTINE_DIR}/${QUARANTINE_NAME}" 2>/dev/null
        chmod 000 "${QUARANTINE_DIR}/${QUARANTINE_NAME}" 2>/dev/null
    fi
fi

rm -f "$TMP_REPORT"
exit 0
