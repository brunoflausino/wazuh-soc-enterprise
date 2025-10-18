# nwipe-Wazuh Integration: Secure Installation and Log Monitoring

## Abstract

This report outlines a comprehensive methodology for installing and integrating **nwipe** (a secure disk erasure tool forked from dwipe) with **Wazuh**, an open-source Security Information and Event Management (SIEM) system, on Ubuntu 24.04. The process ensures complete traceability of erasure operations through JSON logging while prioritizing safety by avoiding destructive actions during setup and testing.

## Introduction

Secure data erasure is a critical requirement in sensitive computing environments to prevent unauthorized data recovery. **nwipe** is a powerful utility for securely wiping physical disks using methods like DoD 5220.22-M or zero-filling, making data irrecoverable. In monitored environments, auditing such operations is essential for compliance and traceability.

**Wazuh**, a robust SIEM platform, supports this by collecting and analyzing logs from diverse sources. This study details a safe, reproducible method to install nwipe, integrate its logs with Wazuh (manager, indexer, and dashboard), and verify the setup using simulated events.

### Key Features

- **Safety-first approach**: No destructive actions during setup
- **Modular scripts**: Segregated installation, configuration, and testing phases
- **JSON logging**: Structured event collection for better analysis
- **Community-ready**: Reproducible methodology with detailed documentation

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

## Methodology

The process is divided into independent phases using dedicated Bash scripts to prevent inadvertent destructive actions and enable modular replication. Each script includes safety checks (`set -Eeuo pipefail`) and is idempotent where possible.

### Phase 1: Safe Installation of nwipe

The script `install_nwipe_safe.sh` installs nwipe without executing it or accessing block devices (`/dev/sd*`). It attempts installation via APT, falling back to source compilation from the official GitHub repository if necessary.

**Key Safety Features:**
- No execution of nwipe during installation
- No access to block devices
- No destructive tests
- Comprehensive error handling and cleanup

**Execution:**
```bash
sudo ./install_nwipe_safe.sh
```

**Outcome:** nwipe installed in `/usr/bin/nwipe` without risks.

### Phase 2: Log Configuration and Integration with Wazuh

The script `setup_wazuh_integration_safe_v4.sh` configures a JSON log file (`/var/log/nwipe/wazuh_events.log`) and integrates it with Wazuh. 

**Key Configuration Elements:**

1. **JSON Log Format**: Sets `<log_format>json</log_format>` in `<localfile>` blocks
2. **Complete Event Archiving**: Enables `<logall_json>yes</logall_json>` in the `<global>` section for comprehensive event archiving in `/var/ossec/logs/archives/archives.json`
3. **Custom Rules**: Adds rules to `local_rules.xml` using `<decoded_as>json</decoded_as>`
4. **Logrotate Configuration**: Implements log rotation for space management

**Execution:**
```bash
sudo ./setup_wazuh_integration_safe_v4.sh --role=manager
```

**Outcome:** Log file and rules configured; Wazuh restarted if detected.

### Phase 3: Generation of Test Events

The script `nwipe_integration_test_safe.sh` simulates nwipe events (start, success, error) in JSON format to test integration without erasure.

**Test Event Types:**
- **INICIO**: Start of nwipe operation
- **FIM (info)**: Successful completion
- **FIM (error)**: Completion with errors

**Sample JSON Event:**
```json
{
  "ts": "2025-10-18T06:16:00Z",
  "component": "nwipe-wrapper",
  "level": "info",
  "msg": "INICIO",
  "extra": {
    "device": "/dev/TEST",
    "args": "--method dodshort --verify last",
    "runlog": "/var/log/nwipe/nwipe_TEST.log"
  }
}
```

**Execution:**
```bash
sudo ./nwipe_integration_test_safe.sh
```

**Outcome:** Test events written to the log without any destructive actions.

### Phase 4: Rule Adjustment and Validation

Initial implementation encountered decoder issues that required refinement:

#### Original Issues and Corrections

| Rule ID | Original Issue | Correction | Alert Level |
|---------|---------------|------------|-------------|
| 100500 | `<if_decoder>json</if_decoder>`, `data.component` | `<decoded_as>json</decoded_as>`, `component` | 3: Nwipe start execution |
| 100501 | Same, plus `data.level` | Same, `level=info` | 3: Nwipe successful completion |
| 100502 | Same, `data.level=error` | Same, `level=error` | 10: Nwipe completion with error |

#### Validation Process

Testing with `wazuh-logtest` using sample JSON resolved decoder errors (2106/7311) and confirmed proper rule triggering.

## Results

### Installation Success

The `install_nwipe_safe.sh` script successfully installed nwipe in `/usr/bin/nwipe` via APT on Ubuntu 24.04, avoiding block device access. Verification with `nwipe --version` confirmed the installation.

### Integration Verification

The `setup_wazuh_integration_safe_v4.sh` script configured `/var/log/nwipe/wazuh_events.log` with `<log_format>json</log_format>`. The `<global>` section includes `<logall_json>yes</logall_json>`, ensuring all events are archived in `/var/ossec/logs/archives/archives.json`.

### Event Processing Confirmation

Test events generated at 08:16 AM CEST (18/10/2025) were successfully visible in `archives.json`. Alerts in `alerts.json` confirmed rule triggering:

- **Rule 100500** (level 3) for "INICIO"
- **Rule 100501** (level 3) for "FIM" with `level=info`
- **Rule 100502** (level 10) for "FIM" with `level=error`

**No destructive actions occurred**, and logs were fully auditable via the Wazuh dashboard.

## Challenges and Solutions

### Technical Challenges

1. **Rule Syntax Issues**: Initial `<if_decoder>json</if_decoder>` caused errors, resolved by using `<decoded_as>json</decoded_as>` and top-level fields
2. **Log Visibility**: Enabling `<logall_json>yes` was critical for archiving, though it increases storage demands
3. **Process Suspension**: Earlier nwipe executions resulted in suspended processes, addressed by manual termination

### Best Practices Identified

1. **Phase Segregation**: Separate installation, configuration, and testing phases
2. **JSON Structured Logging**: Use JSON for structured logging and ensure full event visibility
3. **Configuration Management**: Maintain backups and test rules with `wazuh-logtest`
4. **Resource Monitoring**: Monitor disk usage with `logall_json` enabled

## Security Considerations

- **No Data Loss Risk**: All scripts designed to prevent accidental data erasure
- **Comprehensive Auditing**: Complete event traceability through Wazuh
- **Access Control**: Proper file permissions and group assignments
- **Safe Testing**: Simulated events for validation without real disk operations

## Future Enhancements

Consider implementing:
- Custom decoders for nested JSON processing
- API-based alerting for real-time notifications
- Integration with external compliance systems
- Automated reporting capabilities

## Scripts Overview

### Core Scripts

1. **`install_nwipe_safe.sh`**: Safe nwipe installation without execution
2. **`setup_wazuh_integration_safe_v4.sh`**: Wazuh configuration and rule setup
3. **`nwipe_integration_test_safe.sh`**: Test event generation for validation

### Safety Features

- Error handling with `set -Eeuo pipefail`
- Comprehensive cleanup procedures
- Idempotent operations where possible
- Detailed logging and progress indicators

## Conclusion

This methodology provides a secure, auditable integration of nwipe with Wazuh, with scripts enabling community replication. Key lessons learned include the importance of phase segregation, JSON logging, full event visibility, careful rule management, and configuration backups.

The framework supports reliable experimentation in operational security environments while maintaining complete safety and audit trails. The modular approach ensures that each phase can be executed independently, reducing risk and improving maintainability.

## References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [nwipe GitHub Repository](https://github.com/martijnvanbrummelen/nwipe)
- SIEM Best Practices (Palo Alto Networks, SentinelOne)

---

**Note**: This integration focuses on monitoring and auditing secure data erasure operations. Always follow your organization's data protection policies and ensure proper authorization before performing any disk erasure operations.
