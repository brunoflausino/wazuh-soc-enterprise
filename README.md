# 🛡️ Enterprise SOC Platform with Wazuh SIEM/XDR

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange)](https://ubuntu.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.13.1-blue)](https://wazuh.com)
[![Tools](https://img.shields.io/badge/Integrated%20Tools-20%2B-green)](integrations/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)]()

## Overview

Complete enterprise-grade Security Operations Center (SOC) platform built on Ubuntu 24.04 LTS bare metal server, featuring Wazuh SIEM/XDR as the core with 20+ integrated security tools for comprehensive threat detection, incident response, and security orchestration.

## 🚀 Quick Navigation

- 📚 **[Full Integration Catalog](integrations/)** - All 20+ tool integrations
- 🔒 **[Network Security Tools](integrations/network-security/)** - IDS/IPS, VPN, Firewall
- 🎯 **[Threat Intelligence](integrations/threat-intelligence/)** - MITRE ATT&CK, OSINT, Honeypots
- 🚨 **[Incident Response](integrations/incident-response/)** - DFIR, SOAR, Forensics
- 🔐 **[Authentication](integrations/authentication/)** - RADIUS, 802.1X
- 💾 **[Data Protection](integrations/data-protection/)** - Encryption, AV, Backup

## 📊 Integrated Security Stack

| Category | Tools | Status |
|----------|-------|--------|
| **Core SIEM** | Wazuh Manager, Indexer, Dashboard, Filebeat | ✅ Operational |
| **Network Security** | Suricata, Zeek, WireGuard, UFW | ✅ Operational |
| **Threat Intelligence** | CALDERA, SpiderFoot, Conpot | ✅ Operational |
| **Incident Response** | DFIR-IRIS, GRR, Shuffle SOAR | ✅ Operational |
| **Authentication** | FreeRADIUS, Radsecproxy | ✅ Operational |
| **Data Protection** | ClamAV, VeraCrypt, NWIPE, Restic | ✅ Operational |

## 🖥️ System Requirements

- **Operating System**: Ubuntu 24.04 LTS (bare metal)
- **RAM**: 32GB minimum (64GB recommended)
- **CPU**: 8+ cores (16 recommended)
- **Storage**: 500GB+ SSD
- **Network**: Static IP, 1Gbps+ connection

## 🌐 Service Access Points

| Service | URL | Default Port |
|---------|-----|--------------|
| Wazuh Dashboard | https://localhost | 443 |
| CALDERA C2 | http://localhost:8888 | 8888 |
| Shuffle SOAR | https://localhost:3443 | 3443 |
| DFIR-IRIS | http://localhost:9094 | 9094 |
| GRR Response | http://localhost:9008 | 9008 |
| SpiderFoot | http://127.0.0.1:5001 | 5001 |

## 📈 Project Status

- ✅ Core platform deployed
- ✅ All 20+ tools integrated
- 🚧 Documentation in progress (framework complete)
- 🚧 Integration guides being added weekly
- 📝 Automation scripts coming soon

## 🤝 Contributing

This project is actively being documented. Check back regularly for updates or star the repository to be notified of new content.

## 📄 License

MIT License - see [LICENSE](LICENSE) file

---

**Note**: This is a real, operational SOC platform running on bare metal. Documentation is being migrated from internal notes to public guides.
