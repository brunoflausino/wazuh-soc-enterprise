#!/usr/bin/env bash
# setup_wazuh_integration_safe_v4.sh — Secure nwipe-Wazuh integration
# - Does NOT execute nwipe
# - Does NOT access /dev/*
# - Configures JSON collection in /var/log/nwipe/wazuh_events.log and local rules

set -Eeuo pipefail

log() { printf "\033[0;32m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

ROLE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --role) ROLE="$2"; shift 2;;
        --role=*) ROLE="${1#*=}"; shift;;
        *) warn "Ignored parameter: $1"; shift;;
    esac
done

OSSEC_DIR="/var/ossec"
CONF_PATH="${OSSEC_DIR}/etc/ossec.conf"
LOCAL_RULES="${OSSEC_DIR}/etc/rules/local_rules.xml"
TARGET_LOG_DIR="/var/log/nwipe"
TARGET_LOG_FILE="${TARGET_LOG_DIR}/wazuh_events.log"

# Discover correct group using /var/ossec owner (e.g., 'wazuh')
detect_ossec_group() {
    [[ -d "${OSSEC_DIR}" ]] || die "Directory ${OSSEC_DIR} not found. Install Wazuh first."
    OSSEC_GRP="$(stat -c %G "${OSSEC_DIR}" 2>/dev/null || echo wazuh)"
    getent group "${OSSEC_GRP}" >/dev/null || OSSEC_GRP="root"
    log "Using group '${OSSEC_GRP}' for permissions."
}

service_exists() {
    local svc="$1"
    systemctl status "$svc" >/dev/null 2>&1 && return 0
    systemctl list-units --all | grep -qE "^${svc}\b" && return 0
    systemctl list-unit-files | grep -qE "^${svc}\b" && return 0
    [[ -e "/etc/systemd/system/${svc}" || -e "/lib/systemd/system/${svc}" || -e "/usr/lib/systemd/system/${svc}" ]] && return 0
    return 1
}

# Detect Wazuh role
detect_wazuh_role() {
    if [[ -n "${ROLE}" ]]; then
        case "${ROLE}" in
            manager) SERVICE="wazuh-manager";;
            agent) SERVICE="wazuh-agent";;
            *) die "Invalid value for --role (use 'manager' or 'agent').";;
        esac
        log "Role forced via parameter: ${ROLE} (service ${SERVICE})"
        return
    fi
    
    if service_exists "wazuh-agent.service"; then
        SERVICE="wazuh-agent"; ROLE="agent"; log "Detected Wazuh agent."; return
    fi
    if service_exists "wazuh-manager.service"; then
        SERVICE="wazuh-manager"; ROLE="manager"; log "Detected Wazuh manager."; return
    fi
    
    SERVICE=""; ROLE="unknown"
    warn "Wazuh service not detected. Will apply configurations; restart manually later."
}

# Create log path and logrotate
prepare_log_path() {
    log "Preparing ${TARGET_LOG_FILE}"
    install -d -m 0750 -o root -g "${OSSEC_GRP}" "${TARGET_LOG_DIR}"
    
    if [[ ! -e "${TARGET_LOG_FILE}" ]]; then
        install -m 0640 -o root -g "${OSSEC_GRP}" /dev/null "${TARGET_LOG_FILE}"
    else
        chown root:"${OSSEC_GRP}" "${TARGET_LOG_FILE}" || true
        chmod 0640 "${TARGET_LOG_FILE}"
    fi
    
    # logrotate
    local lr="/etc/logrotate.d/nwipe"
    if [[ ! -f "${lr}" ]]; then
        cat > "${lr}" <<ROT
/var/log/nwipe/*.log {
    daily
    rotate 14
    missingok
    compress
    delaycompress
    notifempty
    create 0640 root ${OSSEC_GRP}
}
ROT
        log "Logrotate configured in ${lr}."
    else
        sed -i "s/^\s*create\s\+0640\s\+root\s\+.*$/ create 0640 root ${OSSEC_GRP}/" "${lr}" || true
    fi
}

backup_conf() {
    [[ -f "${CONF_PATH}" ]] || die "ossec.conf not found."
    local ts; ts="$(date +'%Y%m%d_%H%M%S')"
    cp -a "${CONF_PATH}" "${CONF_PATH}.bak_${ts}"
    log "Backup created: ${CONF_PATH}.bak_${ts}"
}

# Add <localfile> json
ensure_localfile_json() {
    if grep -Fq "${TARGET_LOG_FILE}" "${CONF_PATH}"; then
        log "<localfile> entry already exists."
        return
    fi
    
    log "Inserting <localfile> (json) block in ossec.conf..."
    local SNIP tmpfile
    read -r -d '' SNIP <<EOSNIP
  <localfile>
    <location>${TARGET_LOG_FILE}</location>
    <log_format>json</log_format>
  </localfile>
EOSNIP
    
    tmpfile="$(mktemp)"
    awk -v snip="$SNIP" '
        /<\/ossec_config>/ && !x { print snip; x=1 }
        { print }
    ' "${CONF_PATH}" > "${tmpfile}"
    
    install -m 0640 -o root -g "${OSSEC_GRP}" "${tmpfile}" "${CONF_PATH}"
    rm -f "${tmpfile}"
    log "<localfile> block added."
}

# Add rules to local_rules.xml
ensure_local_rules() {
    install -d -m 0750 -o root -g "${OSSEC_GRP}" "$(dirname "${LOCAL_RULES}")"
    
    if [[ ! -f "${LOCAL_RULES}" ]]; then
        cat > "${LOCAL_RULES}" <<'XML'
<group name="local,">
</group>
XML
        chown root:"${OSSEC_GRP}" "${LOCAL_RULES}" || true
        chmod 0640 "${LOCAL_RULES}"
    fi
    
    if grep -Fq '<group name="nwipe,' "${LOCAL_RULES}"; then
        log "Rule group 'nwipe' already exists."
        return
    fi
    
    log "Adding 'nwipe' rule group to local_rules.xml..."
    cat >> "${LOCAL_RULES}" <<'XML'
<group name="nwipe,">
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="component">^nwipe-wrapper$</field>
    <field name="msg">^INICIO$</field>
    <description>NWipe: start execution</description>
    <options>no_full_log</options>
  </rule>

  <rule id="100501" level="3">
    <decoded_as>json</decoded_as>
    <field name="component">^nwipe-wrapper$</field>
    <field name="msg">^FIM$</field>
    <field name="level">^info$</field>
    <description>NWipe: successful completion</description>
    <options>no_full_log</options>
  </rule>

  <rule id="100502" level="10">
    <decoded_as>json</decoded_as>
    <field name="component">^nwipe-wrapper$</field>
    <field name="msg">^FIM$</field>
    <field name="level">^error$</field>
    <description>NWipe: completion with error</description>
  </rule>
</group>
XML
    chown root:"${OSSEC_GRP}" "${LOCAL_RULES}" || true
    chmod 0640 "${LOCAL_RULES}"
    log "'nwipe' rules added."
}

apply_wazuh() {
    if [[ -z "${SERVICE}" ]]; then
        warn "Wazuh service not detected automatically. Restart manually when desired."
        return 0
    fi
    
    log "Restarting ${SERVICE}..."
    if systemctl is-active --quiet "${SERVICE}"; then
        systemctl restart "${SERVICE}"
    else
        systemctl start "${SERVICE}" || true
    fi
    systemctl --no-pager --full status "${SERVICE}" -l --no-legend || true
}

main() {
    require_root
    detect_ossec_group
    detect_wazuh_role
    prepare_log_path
    backup_conf
    ensure_localfile_json
    ensure_local_rules
    apply_wazuh
    
    log "Integration completed safely."
    warn "No destructive actions executed. nwipe was NOT started."
}

main "$@"
