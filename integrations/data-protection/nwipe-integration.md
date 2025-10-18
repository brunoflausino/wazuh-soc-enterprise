# Nwipe Integration with Wazuh Monitoring

This document details a secure and reproducible methodology for installing the `nwipe` disk erasure tool on Ubuntu 24.04 and integrating its operational logs with the Wazuh SIEM platform.

## Overview

[cite_start]Secure data erasure using tools like `nwipe` is critical but potentially destructive[cite: 368, 369]. [cite_start]This integration aims to provide **auditing and traceability** for `nwipe` operations without executing dangerous commands during setup[cite: 370].

The methodology involves:
1.  Safely installing `nwipe` (via APT or source compilation).
2.  Configuring a dedicated JSON log file (`/var/log/nwipe/wazuh_events.log`) for `nwipe` events.
3.  [cite_start]Configuring the Wazuh manager to monitor this JSON log file using `<log_format>json</log_format>`[cite: 373, 483].
4.  [cite_start]Enabling full event archiving (`<logall_json>yes</logall_json>`) for verification[cite: 375, 483, 764].
5.  Implementing custom Wazuh rules to generate alerts for `nwipe` start, success, and error events.
6.  [cite_start]Using a safe test script to generate simulated JSON events for validation without running `nwipe` itself[cite: 691, 693].

## Prerequisites

* [cite_start]**OS:** Ubuntu 24.04 LTS (x86_64) [cite: 377, 2163]
* [cite_start]**Wazuh:** Version 4.12+ (Manager, Indexer, Dashboard installed) [cite: 372, 378, 2164, 2165]
* [cite_start]**Privileges:** Sudo/root access is required for all commands[cite: 379, 2166].
* [cite_start]**Dependencies:** `git`, `build-essential`, `autoconf`, `automake`, `libtool`, `pkg-config`, `libparted-dev`, `libncurses-dev` (needed if compiling `nwipe` from source)[cite: 380, 2170].

---

## 1. Safe Installation of Nwipe

This step installs the `nwipe` binary **without executing it or accessing any block devices**.

1.  **Run the Safe Installation Script:**
    Save the following script as `install_nwipe_safe.sh` and execute it with `sudo`. [cite_start]It attempts to install via APT first and falls back to compiling from source if the package isn't available[cite: 387, 2177].

    ```bash
    #!/usr/bin/env bash
    # install_nwipe_safe.sh
    # Installs nwipe only on Ubuntu 22.04/24.04
    # Does NOT execute nwipe
    # Does NOT access /dev/sdX / nvme*
    # Does NOT perform destructive tests
    set -Eeuo pipefail

    log() { printf "\033[0;32m[INFO]\033[0m %s\n" "$*"; }
    warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
    err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*" >&2; }
    die() { err "$*"; exit 1; }

    # Clean up temporary directory on exit
    cleanup() { [[ -n "${TMPDIR_CREATED:-}" && -d "${TMPDIR_CREATED}" ]] && rm -rf "${TMPDIR_CREATED}" || true; }
    trap cleanup EXIT

    require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

    # Check OS (optional but recommended)
    check_os() {
      if [[ -r /etc/os-release ]]; then
        source /etc/os-release
        case "${ID}-${VERSION_ID}" in
          ubuntu-24.04|ubuntu-22.04) log "Detected compatible OS: ${PRETTY_NAME}";;
          *) warn "Detected distro: ${PRETTY_NAME:-unknown}. Proceeding anyway...";;
        esac
      else
        warn "Could not read /etc/os-release to verify OS."
      fi
    }

    apt_update() { log "Updating APT indexes..."; sudo apt-get update -y; }

    # Try installing via APT first
    install_via_apt() {
      log "Attempting to install 'nwipe' via APT..."
      if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nwipe; then
        log "nwipe installed via APT."
        return 0 # Success
      else
        warn "nwipe package unavailable or failed via APT. Falling back to compilation."
        return 1 # Failure
      fi
    }

    # Install build dependencies if needed
    install_build_deps() {
      log "Installing build dependencies..."
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential git autoconf automake libtool pkg-config \
        libparted-dev libncurses-dev
    }

    # Compile from source
    build_from_source() {
      local url dir
      url="${NWIPE_REPO:-[https://github.com/martijnvanbrummelen/nwipe.git](https://github.com/martijnvanbrummelen/nwipe.git)}"
      dir="$(mktemp -d)"
      TMPDIR_CREATED="${dir}" # Register for cleanup
      log "Cloning repository: ${url}"
      git clone --depth=1 "${url}" "${dir}/nwipe"
      cd "${dir}/nwipe"
      log "Configuring build..."
      [[ -x ./autogen.sh ]] && ./autogen.sh
      ./configure --prefix=/usr
      log "Compiling..."
      make -j"$(nproc)"
      log "Installing..."
      sudo make install
      log "nwipe compiled and installed in /usr/bin/nwipe"
      cd / # Change out of temp dir before cleanup
    }

    # Verify nwipe is installed and in PATH
    verify_install() {
      command -v nwipe >/dev/null || die "nwipe not found in PATH after installation."
      log "Installed version (safe call):"
      nwipe --version || true # Use '|| true' to prevent script exit if --version fails for some reason
    }

    # Main execution flow
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
    [cite_start][cite: 389-479]

2.  **Execute the script:**
    ```bash
    chmod +x install_nwipe_safe.sh
    sudo ./install_nwipe_safe.sh
    ```

3.  [cite_start]**Outcome:** The `nwipe` binary is installed at `/usr/bin/nwipe`[cite: 460, 2220].

---

## 2. Wazuh Integration Configuration

This script configures the Wazuh manager to monitor the `nwipe` JSON log file and adds custom rules.

1.  **Run the Integration Setup Script:**
    Save the following script as `setup_wazuh_integration_safe.sh` and execute it with `sudo`. [cite_start]Specify `--role=manager` since `nwipe` operations are typically performed on the server itself in this context[cite: 2249].

    ```bash
    #!/usr/bin/env bash
    # setup_wazuh_integration_safe.sh
    # Secure nwipe-Wazuh integration
    # Does NOT execute nwipe
    # Does NOT access /dev/*
    # Configures JSON collection in /var/log/nwipe/wazuh_events.log and local rules
    set -Eeuo pipefail

    log() { printf "\033[0;32m[INFO]\033[0m %s\n" "$*"; }
    warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
    err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*" >&2; }
    die() { err "$*"; exit 1; }

    require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

    ROLE=""
    # Parse --role argument
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --role) ROLE="$2"; shift 2;;
        --role=*) ROLE="${1#*=}"; shift;;
        *) warn "Ignoring unknown parameter: $1"; shift;;
      esac
    done

    OSSEC_DIR="/var/ossec"
    CONF_PATH="${OSSEC_DIR}/etc/ossec.conf"
    LOCAL_RULES="${OSSEC_DIR}/etc/rules/local_rules.xml"
    TARGET_LOG_DIR="/var/log/nwipe"
    TARGET_LOG_FILE="${TARGET_LOG_DIR}/wazuh_events.log"

    # Detect the group owner of OSSEC_DIR (usually 'wazuh' or 'ossec')
    detect_ossec_group() {
      [[ -d "${OSSEC_DIR}" ]] || die "Directory ${OSSEC_DIR} not found. Install Wazuh first."
      OSSEC_GRP="$(stat -c %G "${OSSEC_DIR}" 2>/dev/null || echo wazuh)"
      # Fallback to root if group doesn't exist
      getent group "${OSSEC_GRP}" >/dev/null || OSSEC_GRP="root"
      log "Using group '${OSSEC_GRP}' for permissions."
    }

    # Check if a systemd service exists
    service_exists() { systemctl status "$1" >/dev/null 2>&1; }

    # Detect Wazuh role (manager/agent) based on running services or argument
    detect_wazuh_role() {
      # Use provided role if specified
      if [[ -n "${ROLE}" ]]; then
        case "${ROLE}" in
          manager) SERVICE="wazuh-manager";;
          agent) SERVICE="wazuh-agent";;
          *) die "Invalid value for --role (use 'manager' or 'agent').";;
        esac
        log "Role forced via parameter: ${ROLE} (service ${SERVICE})"
        return
      fi

      # Auto-detect role
      if service_exists "wazuh-agent.service"; then
        SERVICE="wazuh-agent"; ROLE="agent"; log "Detected Wazuh agent."; return
      fi
      if service_exists "wazuh-manager.service"; then
        SERVICE="wazuh-manager"; ROLE="manager"; log "Detected Wazuh manager."; return
      fi

      SERVICE=""; ROLE="unknown"
      warn "Wazuh service not detected. Applying configurations; restart manually later."
    }

    # Create log directory, file, and logrotate config
    prepare_log_path() {
      log "Preparing ${TARGET_LOG_FILE}"
      sudo install -d -m 0750 -o root -g "${OSSEC_GRP}" "${TARGET_LOG_DIR}"
      if [[ ! -e "${TARGET_LOG_FILE}" ]]; then
          sudo install -m 0640 -o root -g "${OSSEC_GRP}" /dev/null "${TARGET_LOG_FILE}"
      else
          # Ensure correct ownership/permissions if file exists
          sudo chown root:"${OSSEC_GRP}" "${TARGET_LOG_FILE}" || true
          sudo chmod 0640 "${TARGET_LOG_FILE}"
      fi

      # Configure logrotate
      local lr_conf="/etc/logrotate.d/nwipe"
      log "Configuring logrotate in ${lr_conf}"
      sudo tee "${lr_conf}" > /dev/null << ROT
/var/log/nwipe/*.log {
    daily
    rotate 14
    missingok
    compress
    delaycompress
    notifempty
    create 0640 root ${OSSEC_GRP}
    su root ${OSSEC_GRP}
}
ROT
    }

    # Backup ossec.conf
    backup_conf() {
      [[ -f "${CONF_PATH}" ]] || die "ossec.conf not found at ${CONF_PATH}."
      local ts; ts="$(date +%Y%m%d_%H%M%S)"
      sudo cp -a "${CONF_PATH}" "${CONF_PATH}.bak_${ts}"
      log "Backup created: ${CONF_PATH}.bak_${ts}"
    }

    # Add <localfile> block for JSON log if not present
    ensure_localfile_json() {
      if sudo grep -Fq "${TARGET_LOG_FILE}" "${CONF_PATH}"; then
        log "<localfile> entry for ${TARGET_LOG_FILE} already exists."
        return
      fi

      log "Inserting <localfile> block (json) into ossec.conf..."
      local SNIP
      # Define the XML snippet to insert
      read -r -d '' SNIP << EOF
  <localfile>
    <location>${TARGET_LOG_FILE}</location>
    <log_format>json</log_format>
  </localfile>

EOF
      # Insert the snippet before the closing </ossec_config> tag using awk
      local tmpfile; tmpfile="$(mktemp)"
      sudo awk -v snip="$SNIP" '
        /<\/ossec_config>/ && !inserted { print snip; inserted=1 }
        { print }
      ' "${CONF_PATH}" > "${tmpfile}"

      # Replace original with modified file, setting correct permissions
      sudo install -m 0640 -o root -g "${OSSEC_GRP}" "${tmpfile}" "${CONF_PATH}"
      rm -f "${tmpfile}"
      log "<localfile> block added."
    }

    # Ensure <logall_json> is enabled for debugging/verification
    ensure_logall_json() {
        log "Ensuring <logall_json> is set to yes in <global> section..."
        if sudo grep -q '<logall_json>yes</logall_json>' "${CONF_PATH}"; then
            log "<logall_json> already enabled."
            return
        fi

        # Add or modify <logall_json>
        if sudo grep -q '<logall_json>' "${CONF_PATH}"; then
            # Modify existing tag
            sudo sed -i 's|<logall_json>.*</logall_json>|<logall_json>yes</logall_json>|' "${CONF_PATH}"
        else
            # Add tag inside <global> section (simple approach: insert after <global>)
            sudo sed -i '/<global>/a \ \ <logall_json>yes</logall_json>' "${CONF_PATH}"
        fi
        log "<logall_json> set to yes. Manager restart needed."
    }


    # Add custom rules to local_rules.xml if not present
    ensure_local_rules() {
      # Create rules directory if needed
      sudo install -d -m 0750 -o root -g "${OSSEC_GRP}" "$(dirname "${LOCAL_RULES}")"
      # Create basic local_rules.xml if it doesn't exist
      if [[ ! -f "${LOCAL_RULES}" ]]; then
        log "Creating ${LOCAL_RULES}..."
        sudo tee "${LOCAL_RULES}" > /dev/null << 'XML'
<group name="local,">
</group>
XML
        sudo chown root:"${OSSEC_GRP}" "${LOCAL_RULES}" || true
        sudo chmod 0640 "${LOCAL_RULES}"
      fi

      # Check if nwipe rules already exist
      if sudo grep -Fq '<group name="nwipe,">' "${LOCAL_RULES}"; then
        log "Nwipe rule group already exists in ${LOCAL_RULES}."
        return
      fi

      log "Appending 'nwipe' rule group to ${LOCAL_RULES}..."
      # Use sed to insert rules before the final </group> tag
      sudo sed -i -e "/^<\/group>/i \
<group name=\"nwipe,\">\n\
  \n\
  <rule id=\"100500\" level=\"3\">\n\
    <decoded_as>json</decoded_as>\n\
    <field name=\"component\">^nwipe-wrapper$</field>\n\
    <field name=\"msg\">^INICIO$</field>\n\
    <description>NWipe: Execution started</description>\n\
    <options>no_full_log</options>\n\
  </rule>\n\
  \n\
  <rule id=\"100501\" level=\"3\">\n\
    <decoded_as>json</decoded_as>\n\
    <field name=\"component\">^nwipe-wrapper$</field>\n\
    <field name=\"msg\">^FIM$</field>\n\
    <field name=\"level\">^info$</field>\n\
    <description>NWipe: Execution finished successfully</description>\n\
    <options>no_full_log</options>\n\
  </rule>\n\
  \n\
  <rule id=\"100502\" level=\"10\">\n\
    <decoded_as>json</decoded_as>\n\
    <field name=\"component\">^nwipe-wrapper$</field>\n\
    <field name=\"msg\">^FIM$</field>\n\
    <field name=\"level\">^error$</field>\n\
    <description>NWipe: Execution finished with error</description>\n\
  </rule>\n\
</group>\n" "${LOCAL_RULES}"

      # Correct permissions after modification
      sudo chown root:"${OSSEC_GRP}" "${LOCAL_RULES}" || true
      sudo chmod 0640 "${LOCAL_RULES}"
      log "Nwipe rules added."
    }

    # Restart the appropriate Wazuh service
    apply_wazuh() {
      if [[ -z "${SERVICE}" ]]; then
        warn "Wazuh service not detected automatically. Restart manually when desired."; return 0
      fi
      log "Restarting ${SERVICE}..."
      if sudo systemctl is-active --quiet "${SERVICE}"; then
          sudo systemctl restart "${SERVICE}"
      else
          sudo systemctl start "${SERVICE}" || true # Attempt to start if not active
      fi
      # Display status briefly
      sudo systemctl --no-pager status "${SERVICE}" -n 5 || true
    }

    # Main execution flow
    main() {
      require_root
      detect_ossec_group
      detect_wazuh_role
      prepare_log_path
      backup_conf
      ensure_localfile_json
      ensure_logall_json # Ensure archiving is enabled
      ensure_local_rules
      apply_wazuh
      log "Integration configuration completed safely."
      warn "No destructive actions were executed. Nwipe was NOT started."
    }

    main "$@"
    ```
    [cite_start][cite: 492-687]

2.  **Execute the script:**
    ```bash
    chmod +x setup_wazuh_integration_safe.sh
    sudo ./setup_wazuh_integration_safe.sh --role=manager
    ```

3.  **Outcome:**
    * [cite_start]`/var/log/nwipe/wazuh_events.log` is created with correct permissions[cite: 487].
    * [cite_start]A `<localfile>` block monitoring this file with `log_format` set to `json` is added to `/var/ossec/etc/ossec.conf`[cite: 488, 2160].
    * [cite_start]`<logall_json>yes</logall_json>` is enabled in the `<global>` section of `ossec.conf`[cite: 483, 2161].
    * [cite_start]Custom rules (100500, 100501, 100502) are added to `/var/ossec/etc/rules/local_rules.xml`[cite: 489, 2299].
    * [cite_start]The `wazuh-manager` service is restarted[cite: 490].

---

## 3. Generation of Test Events (Safe Simulation)

This script writes **simulated** `nwipe` events to the JSON log file to test Wazuh ingestion and rule matching **without actually running `nwipe`**.

1.  **Run the Test Event Generation Script:**
    Save the following script as `nwipe_integration_test_safe.sh` and execute it with `sudo`.

    ```bash
    #!/usr/bin/env bash
    # nwipe_integration_test_safe.sh
    # Generates test JSON events for Wazuh
    # Does NOT execute nwipe
    # Does NOT access /dev/*
    set -Eeuo pipefail

    LOG="/var/log/nwipe/wazuh_events.log"

    info() { printf "\033[0;32m[INFO]\033[0m %s\n" "$*"; }
    err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*" >&2; exit 1; }

    [[ $EUID -eq 0 ]] || err "Run as root (sudo)."
    [[ -f "$LOG" ]] || err "Log file $LOG does not exist. Run the integration setup script first."

    # Function to get current timestamp in ISO 8601 format (UTC)
    ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

    # Function to write a JSON event to the log file
    # $1: log level (info, error)
    # $2: message (INICIO, FIM)
    # $3: extra JSON payload (e.g., '{"device":"/dev/TEST","rc":0}')
    write_event() {
      printf '{"ts":"%s","component":"nwipe-wrapper","level":"%s","msg":"%s","extra":%s}\n' \
        "$(ts)" "$1" "$2" "$3" | sudo tee -a "$LOG" > /dev/null
    }

    info "Writing test events to $LOG..."

    # Simulate Nwipe start event
    write_event "info" "INICIO" '{"device":"/dev/TEST", "args":"--method dodshort --verify last", "runlog":"/var/log/nwipe/nwipe_TEST.log"}'
    sleep 1

    # Simulate Nwipe successful finish event
    write_event "info" "FIM" '{"device":"/dev/TEST", "rc":0}'
    sleep 1

    # Simulate Nwipe failed finish event
    write_event "error" "FIM" '{"device":"/dev/TEST_FAIL", "rc":1, "error":"simulated"}'

    info "Test events written successfully."
    info "Check Wazuh archives and alerts."
    ```
    [cite_start][cite: 694-726]

2.  **Execute the script:**
    ```bash
    chmod +x nwipe_integration_test_safe.sh
    sudo ./nwipe_integration_test_safe.sh
    ```

3.  [cite_start]**Outcome:** Three JSON lines simulating `nwipe` start, success, and failure are appended to `/var/log/nwipe/wazuh_events.log`[cite: 727, 2282].

---

## 4. Verification

Verify that the simulated events were correctly ingested and triggered the appropriate alerts.

1.  **Check the Log File:**
    Confirm the JSON lines were written.
    ```bash
    sudo tail /var/log/nwipe/wazuh_events.log
    ```

2.  **Check Wazuh Archives (`archives.json`):**
    Because `<logall_json>yes</logall_json>` is enabled, all ingested events (even those not matching high-level rules) should appear here. This confirms Wazuh is reading the file. Check on the Wazuh Manager.
    ```bash
    # Grep for the component name in today's archive file (adjust path if needed)
    sudo grep '"component":"nwipe-wrapper"' /var/ossec/logs/archives/$(date +%Y)/$(date +%b)/ossec-archive-$(date +%d).json
    ```
    You should see JSON entries like:
    ```json
    {"timestamp":"2025-10-18T06:16:00Z", "component":"nwipe-wrapper", "level": "info","msg": "INICIO", "extra": {"device": "/dev/TEST", ...}}
    {"timestamp":"2025-10-18T06:16:01Z", "component":"nwipe-wrapper", "level":"info","msg": "FIM", "extra": {"device": "/dev/TEST", "rc":0}}
    {"timestamp":"2025-10-18T06:16:02Z", "component":"nwipe-wrapper", "level": "error", "msg": "FIM", "extra": {"device": "/dev/TEST_FAIL", "rc": 1, ...}}
    ```
    [cite_start][cite: 2306-2313]

3.  **Check Wazuh Alerts (`alerts.json`):**
    Check if the custom rules generated alerts. Check on the Wazuh Manager.
    ```bash
    sudo tail -f /var/ossec/logs/alerts/alerts.json | grep '"rule":{"id":"1005'
    ```
    You should see alerts corresponding to:
    * [cite_start]Rule **100500** (Level 3) for the "INICIO" event[cite: 2315].
    * [cite_start]Rule **100501** (Level 3) for the successful "FIM" event (level=info)[cite: 2316].
    * [cite_start]Rule **100502** (Level 10) for the failed "FIM" event (level=error)[cite: 2317].

4.  **(Optional) Use `wazuh-logtest`:**
    [cite_start]You can manually test rules against a sample JSON event using `wazuh-logtest` on the manager[cite: 743].
    ```bash
    sudo /var/ossec/bin/wazuh-logtest
    ```
    Paste one of the JSON lines (e.g., `{"ts":"...", "component":"nwipe-wrapper", "level":"error", "msg":"FIM", ...}`) and verify it triggers rule 100502.

---

## 5. Troubleshooting and Best Practices

* [cite_start]**Rule Syntax:** Ensure custom rules use `<decoded_as>json</decoded_as>` and match against the top-level fields extracted from the JSON event (e.g., `component`, `msg`, `level`)[cite: 756, 2285, 2321].
* [cite_start]**Log Visibility:** Enabling `<logall_json>yes</logall_json>` is crucial for debugging, as it shows all events Wazuh ingests, even if they don't trigger alerts[cite: 729, 764, 777, 2322]. [cite_start]Be mindful of potential disk usage increase[cite: 2328].
* [cite_start]**Permissions:** Ensure the log file (`/var/log/nwipe/wazuh_events.log`) is readable by the `wazuh` (or `ossec`) group[cite: 562, 564, 579]. The setup script handles this.
* [cite_start]**Configuration Backups:** Always back up `/var/ossec/etc/ossec.conf` and `/var/ossec/etc/rules/local_rules.xml` before making changes[cite: 780, 2327]. The setup script creates backups.
* [cite_start]**Phase Segregation:** Using separate scripts for installation, configuration, and testing minimizes the risk of accidental data destruction[cite: 775, 2325, 2337].
