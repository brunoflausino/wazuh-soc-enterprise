# nwipe-Wazuh Integration: Complete Installation and Integration Methodology

## Abstract

This report provides a comprehensive, reproducible methodology for installing and integrating **nwipe** (a secure disk erasure tool forked from dwipe) with **Wazuh**, an open-source Security Information and Event Management (SIEM) system, on Ubuntu 24.04. The process ensures complete traceability of erasure operations through JSON logging while prioritizing safety by avoiding destructive actions during setup and testing.

## Key Features

- **Safety-first approach**: No destructive actions during setup or testing
- **Modular scripts**: Complete, ready-to-use scripts for each phase
- **JSON logging**: Structured event collection with proper Wazuh integration
- **Community-ready**: Fully reproducible with detailed troubleshooting

## Environment and Prerequisites

### System Requirements

- **Operating System**: Ubuntu 24.04 (x86_64 architecture)
- **Wazuh Components**: Version 4.12, including:
  - Manager (log analysis)
  - Indexer (OpenSearch-based storage)  
  - Dashboard (visualization)
- **Privileges**: All commands executed with `sudo`

### External Dependencies

| Package | Role in Methodology |
|---------|-------------------|
| `git` | Clones the nwipe repository from GitHub |
| `build-essential` | Provides build tools (gcc, make) for nwipe compilation |
| `autoconf` | Generates configuration scripts during build |
| `automake` | Automates makefile creation |
| `libtool` | Manages library dependencies |
| `pkg-config` | Handles compile/link flags for libraries |
| `libparted-dev` | Supports disk partitioning functionality in nwipe |
| `libncurses-dev` | Enables text-based UI components in nwipe |

## Complete Methodology

The process is divided into four independent phases using dedicated Bash scripts to prevent inadvertent destructive actions and enable modular replication.

### Phase 1: Safe Installation of nwipe

#### Script: `install_nwipe_safe.sh`

This script installs nwipe without executing it or accessing block devices. It attempts installation via APT, falling back to source compilation if necessary.

```bash
#!/usr/bin/env bash
# install_nwipe_safe.sh — Installs nwipe only on Ubuntu 22.04/24.04
# - Does NOT execute nwipe
# - Does NOT access /dev/sdX / nvme*
# - Does NOT perform destructive tests

set -Eeuo pipefail

log() { printf "\033[0;32m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }

cleanup() {
    [[ -n "${TMPDIR_CREATED:-}" && -d "${TMPDIR_CREATED}" ]] && rm -rf "${TMPDIR_CREATED}" || true
}
trap cleanup EXIT

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

check_os() {
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        case "${ID}-${VERSION_ID}" in
            ubuntu-24.04|ubuntu-22.04) ;;
            *) warn "Detected distribution: ${PRETTY_NAME:-unknown}. Proceeding anyway...";;
        esac
    fi
}

apt_update() {
    log "Updating APT indexes..."
    apt-get update -y
}

install_via_apt() {
    log "Attempting to install 'nwipe' via APT..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nwipe; then
        log "nwipe installed via APT."
        return 0
    else
        warn "nwipe package unavailable or failed via APT. Falling back to compilation."
        return 1
    fi
}

install_build_deps() {
    log "Installing build dependencies..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential git autoconf automake libtool pkg-config \
        libparted-dev libncurses-dev
}

build_from_source() {
    local url dir
    url="${NWIPE_REPO:-https://github.com/martijnvanbrummelen/nwipe.git}"
    dir="$(mktemp -d)"
    TMPDIR_CREATED="${dir}"
    
    log "Cloning repository: ${url}"
    git clone --depth=1 "${url}" "${dir}/nwipe"
    cd "${dir}/nwipe"
    
    [[ -x ./autogen.sh ]] && ./autogen.sh
    ./configure --prefix=/usr
    make -j"$(nproc)"
    make install
    
    log "nwipe compiled and installed in /usr/bin/nwipe"
}

verify_install() {
    command -v nwipe >/dev/null || die "nwipe not found in PATH after installation."
    log "Installed version (safe call):"
    nwipe --version || true
}

main() {
    require_root
    check_os
    apt_update
    
    if ! install_via_apt; then
        install_build_deps
        build_from_source
    fi
    
    verify_install
    log "INSTALLATION COMPLETED SUCCESSFULLY."
    warn "This script DID NOT execute 'nwipe' and DID NOT touch any block device."
}

main "$@"
```

**Execution:**
```bash
sudo ./install_nwipe_safe.sh
```

**Outcome:** nwipe installed in `/usr/bin/nwipe` without risks.

### Phase 2: Wazuh Integration Configuration

#### Script: `setup_wazuh_integration_safe_v4.sh`

This script configures JSON log collection and integrates nwipe with Wazuh. It detects the Wazuh role, sets up log format, enables logrotate, and adds custom rules.

```bash
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
    read -r -d '' SNIP <<EOF
  <localfile>
    <location>${TARGET_LOG_FILE}</location>
    <log_format>json</log_format>
  </localfile>
EOF
    
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
```

**Execution:**
```bash
sudo ./setup_wazuh_integration_safe_v4.sh --role=manager
```

**Outcome:** Log file and rules configured; Wazuh restarted if detected.

### Phase 3: Test Event Generation

#### Script: `nwipe_integration_test_safe.sh`

This script generates simulated nwipe events in JSON format to test integration without performing any erasure operations.

```bash
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
```

**Execution:**
```bash
sudo ./nwipe_integration_test_safe.sh
```

**Sample Generated Events:**
```json
{"ts":"2025-10-18T06:16:00Z","component":"nwipe-wrapper","level":"info","msg":"INICIO","extra":{"device":"/dev/TEST","args":"--method dodshort --verify last","runlog":"/var/log/nwipe/nwipe_TEST.log"}}
{"ts":"2025-10-18T06:16:01Z","component":"nwipe-wrapper","level":"info","msg":"FIM","extra":{"device":"/dev/TEST","rc":0}}
{"ts":"2025-10-18T06:16:02Z","component":"nwipe-wrapper","level":"error","msg":"FIM","extra":{"device":"/dev/TEST_FAIL","rc":1,"error":"simulado"}}
```

### Phase 4: Rule Adjustment and Validation

#### Critical Configuration Corrections

Initial implementation encountered decoder issues that required the following corrections:

| Rule ID | Original Issue | Correction | Alert Level |
|---------|---------------|------------|-------------|
| 100500 | `<if_decoder>json</if_decoder>`, `data.component` | `<decoded_as>json</decoded_as>`, `component` | 3: Nwipe start execution |
| 100501 | Same, plus `data.level` | Same, `level=info` | 3: Nwipe successful completion |
| 100502 | Same, `data.level=error` | Same, `level=error` | 10: Nwipe completion with error |

#### Validation with wazuh-logtest

Test the rules using the Wazuh log testing tool:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Input sample JSON:
```json
{"ts":"2025-09-15T10:25:00Z","component":"nwipe-wrapper","level":"info","msg":"FIM","extra":{"device":"/dev/TEST","rc":0}}
```

This should resolve decoder errors (2106/7311) and confirm proper rule triggering.

## Required Wazuh Configuration

### Essential ossec.conf Settings

1. **JSON Log Format**: Ensure `<log_format>json</log_format>` is set in `<localfile>` blocks
2. **Complete Event Archiving**: Enable `<logall_json>yes</logall_json>` in the `<global>` section for comprehensive event archiving in `/var/ossec/logs/archives/archives.json`

### Example Configuration Snippet

```xml
<ossec_config>
  <global>
    <logall_json>yes</logall_json>
  </global>
  
  <localfile>
    <location>/var/log/nwipe/wazuh_events.log</location>
    <log_format>json</log_format>
  </localfile>
</ossec_config>
```

## Results and Verification

### Installation Success
- nwipe successfully installed in `/usr/bin/nwipe` via APT or source compilation
- No block device access during installation
- Version verification with `nwipe --version`

### Integration Verification
- JSON log file configured with proper permissions
- Wazuh monitoring `/var/log/nwipe/wazuh_events.log`
- Custom rules loaded in `local_rules.xml`

### Event Processing Confirmation
Test events successfully processed with alerts confirming:
- **Rule 100500** (level 3) for "INICIO"
- **Rule 100501** (level 3) for "FIM" with `level=info`
- **Rule 100502** (level 10) for "FIM" with `level=error`

Events are visible in:
- `/var/ossec/logs/archives/archives.json`
- `/var/ossec/logs/alerts/alerts.json`
- Wazuh dashboard

## Troubleshooting

### Common Issues

1. **Rule Syntax Errors**: Use `<decoded_as>json</decoded_as>` instead of `<if_decoder>json</if_decoder>`
2. **Missing Events**: Ensure `<logall_json>yes</logall_json>` is enabled in `<global>` section
3. **Permission Issues**: Verify log file permissions match Wazuh group (usually `wazuh`)
4. **Service Restart**: Always restart Wazuh manager after configuration changes

### Debug Commands

```bash
# Test log parsing
sudo /var/ossec/bin/wazuh-logtest

# Check rule loading
sudo /var/ossec/bin/wazuh-analysisd -t

# Monitor log ingestion
sudo tail -f /var/ossec/logs/archives/archives.json

# Check alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

## Security Considerations

- **No Data Loss Risk**: All scripts prevent accidental data erasure
- **Comprehensive Auditing**: Complete event traceability through Wazuh
- **Access Control**: Proper file permissions and group assignments
- **Safe Testing**: Simulated events for validation without real disk operations

## Best Practices

1. **Phase Segregation**: Execute scripts in order, one phase at a time
2. **Backup Configurations**: Always backup `ossec.conf` before modifications
3. **Test Rules**: Use `wazuh-logtest` to validate rule syntax and matching
4. **Monitor Storage**: Enable log rotation to manage disk usage with `logall_json`
5. **Verify Integration**: Run test events to confirm proper log flow

## Conclusion

This methodology provides a complete, safe, and auditable integration of nwipe with Wazuh. The modular script approach ensures community replication while maintaining operational security. Key benefits include comprehensive logging, real-time monitoring, and complete audit trails for secure data erasure operations.

## References

- [Wazuh Documentation - localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Wazuh Documentation - global](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html)
- [Wazuh Documentation - Event logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [nwipe GitHub Repository](https://github.com/martijnvanbrummelen/nwipe)

---

**Note**: This integration focuses on monitoring and auditing secure data erasure operations. Always follow your organization's data protection policies and ensure proper authorization before performing any disk erasure operations.
