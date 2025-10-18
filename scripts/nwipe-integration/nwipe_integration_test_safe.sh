#!/usr/bin/env bash
# nwipe_integration_test_safe.sh — Generates test JSON events for Wazuh
# - Does NOT execute nwipe
# - Does NOT access /dev/*

set -Eeuo pipefail

LOG="/var/log/nwipe/wazuh_events.log"

info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$*"; }
err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || err "Run as root (sudo)."
[[ -f "$LOG" ]] || err "File $LOG does not exist. Run integration first."

ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

write_event() {
    # $1=level $2=msg $3=extra_json
    printf '{"ts":"%s","component":"nwipe-wrapper","level":"%s","msg":"%s","extra":%s}\n' \
        "$(ts)" "$1" "$2" "$3" >> "$LOG"
}

info "Writing test events to $LOG ..."

write_event "info" "INICIO" '{"device":"/dev/TEST","args":"--method dodshort --verify last","runlog":"/var/log/nwipe/nwipe_TEST.log"}'
sleep 1

write_event "info" "FIM" '{"device":"/dev/TEST","rc":0}'
sleep 1

write_event "error" "FIM" '{"device":"/dev/TEST_FAIL","rc":1,"error":"simulado"}'

info "Completed."
