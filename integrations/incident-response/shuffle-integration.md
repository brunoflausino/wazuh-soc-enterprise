# Comprehensive Technical Report: Shuffle SOAR Integration with Wazuh SIEM on Bare-Metal Ubuntu 24.04

**Date:** October 20, 2025
**Environment:** Ubuntu 24.04 LTS (Bare Metal)
**IP Address:** 192.168.1.130
**Objective:** Complete integration of Shuffle SOAR platform with Wazuh SIEM for automated security orchestration and incident response

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Prerequisites and System Requirements](#2-prerequisites-and-system-requirements)
3. [Initial System Configuration](#3-initial-system-configuration)
4. [Shuffle Installation](#4-shuffle-installation)
5. [Shuffle Web Interface Setup](#5-shuffle-web-interface-setup)
6. [Wazuh Integration Configuration](#6-wazuh-integration-configuration)
7. [Verification and Testing](#7-verification-and-testing)
8. [Post-Installation Testing Methodology](#8-post-installation-testing-methodology)
9. [Configuration Files Reference](#9-configuration-files-reference)
10. [Troubleshooting Reference](#10-troubleshooting-reference)
11. [Maintenance and Operations](#11-maintenance-and-operations)
12. [Security Considerations](#12-security-considerations)
13. [Appendix: Complete Script Collection](#13-appendix-complete-script-collection)
14. [Conclusion](#14-conclusion)

**Addendum:** [SSL Certificate Verification Error Resolution](#addendum-ssl-certificate-verification-error-resolution)

---

## 1. Introduction

This report documents the complete methodology for integrating Shuffle SOAR (Security Orchestration, Automation, and Response) with Wazuh SIEM on a bare-metal Ubuntu 24.04 system. Shuffle provides workflow automation capabilities that enhance Wazuh's detection capabilities with automated response actions.

### 1.1 Architecture Overview

* **Wazuh Manager:** Generates security alerts based on log analysis and detection rules
* **Shuffle Backend:** Orchestrates workflows and manages integrations
* **Shuffle Frontend:** Provides web interface for workflow design
* **OpenSearch:** Database backend for Shuffle
* **Webhook:** Communication channel from Wazuh to Shuffle

### 1.2 Network Configuration

* Host IP: `192.168.1.130`
* Shuffle Frontend HTTP: Port `3002`
* Shuffle Frontend HTTPS: Port `3443`
* Shuffle Backend API: Port `5001`
* OpenSearch: Port `9201` (host) → `9200` (container)
* Wazuh Manager: Standard ports (`1514`, `1515`)

---

## 2. Prerequisites and System Requirements

### 2.1 Minimum Hardware Requirements

* CPU: 4 cores minimum (8 cores recommended)
* RAM: 8GB minimum (16GB recommended for production)
* Disk: 50GB free space
* Network: Static IP or DHCP reservation

### 2.2 Software Requirements

* Ubuntu 24.04 LTS
* Docker Engine 24.x or later
* Docker Compose v2.x (plugin method)
* Git
* Existing Wazuh Manager installation

### 2.3 Verify Prerequisites

```bash
# Check Ubuntu version
lsb_release -a
# Check available memory
free -h
# Check disk space
df -h /
# Check if Docker is installed
docker --version
docker compose version
# Check if Wazuh is running
sudo systemctl status wazuh-manager
```

---

## 3. Initial System Configuration

### 3.1 Kernel Configuration for OpenSearch

```bash
# Configure vm.max_map_count (required for OpenSearch)
sudo sysctl -w vm.max_map_count=262144
# Make it permanent
sudo nano /etc/sysctl.conf
```

Add the following line to the file:

```text
vm.max_map_count=262144
```

Save and exit nano.

```bash
# Apply changes
sudo sysctl -p
# Verify
sysctl -n vm.max_map_count
```

Expected output:

```text
262144
```

---

### 3.2 Disable Swap (Recommended for OpenSearch)

```bash
# Disable swap temporarily
sudo swapoff -a
# Verify swap is disabled
swapon --show
```

> To disable swap permanently, comment out swap entries in `/etc/fstab`.

---

### 3.3 Verify Port Availability

```bash
# Check if ports are available
sudo netstat -tulpn | grep -E ":(3002|3443|5001|9201)"
# If ports are in use, identify the process
sudo lsof -i :3443
```

---

## 4. Shuffle Installation

### 4.1 Create Base Directory Structure

```bash
cd ~
mkdir -p ~/Shuffle
cd ~/Shuffle
```

---

### 4.2 Clone Shuffle Repository

```bash
git clone https://github.com/Shuffle/Shuffle.git .
ls -la
```

Expected files:

* `docker-compose.yml`
* `backend/`
* `frontend/`
* `.env` (will be created)

---

### 4.3 Create Environment Configuration File

```bash
cat > .env << 'EOF'
# Frontend Ports
FRONTEND_PORT=3002
FRONTEND_PORT_HTTPS=3443
# Backend
BACKEND_HOSTNAME=shuffle-backend
BACKEND_PORT=5001
OUTER_HOSTNAME=shuffle-backend
# Locations (relative paths)
DB_LOCATION=./shuffle-database
SHUFFLE_APP_HOTLOAD_LOCATION=./shuffle-apps
SHUFFLE_FILE_LOCATION=./shuffle-files
# OpenSearch
SHUFFLE_OPENSEARCH_URL=https://shuffle-opensearch:9200
SHUFFLE_OPENSEARCH_USERNAME=admin
SHUFFLE_OPENSEARCH_PASSWORD=<your-strong-password>
OPENSEARCH_INITIAL_ADMIN_PASSWORD=<your-strong-password>
SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true
# App SDK
SHUFFLE_APP_SDK_TIMEOUT=300
SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY=7
# General Configurations
SHUFFLE_SKIPSSL_VERIFY=true
SHUFFLE_DEBUG=true
SHUFFLE_LOGS_DISABLED=false
TZ=Europe/Madrid
# Orborus
ENVIRONMENT_NAME=Shuffle
ORG_ID=Shuffle
BASE_URL=http://shuffle-backend:5001
DOCKER_API_VERSION=1.40
SHUFFLE_STATS_DISABLED=false
SHUFFLE_SWARM_CONFIG=run
SHUFFLE_WORKER_IMAGE=ghcr.io/shuffle/shuffle-worker:latest
EOF
```

---

### 4.4 Create Required Directories with Proper Permissions

```bash
cd ~/Shuffle
mkdir -p shuffle-database shuffle-apps shuffle-files
sudo chown -R 1000:1000 shuffle-database
chmod -R 755 shuffle-apps shuffle-files
ls -ln | grep shuffle-
```

Expected output for shuffle-database:

```text
drwxr-xr-x 2 1000 1000 4096 Oct 20 09:11 shuffle-database
```

---

### 4.5 Modify docker-compose.yml for Port Mapping

```bash
cd ~/Shuffle
sed -i 's/- 9200:9200/- 9201:9200/' docker-compose.yml
grep "9201:9200" docker-compose.yml
```

Expected output:

```text
- 9201:9200
```

---

### 4.6 Pull Docker Images

```bash
cd ~/Shuffle
docker compose pull
```

This downloads:

* ghcr.io/shuffle/shuffle-frontend:latest
* ghcr.io/shuffle/shuffle-backend:latest
* ghcr.io/shuffle/shuffle-orborus:latest
* opensearchproject/opensearch:3.2.0

---

### 4.7 Start Shuffle Services

```bash
cd ~/Shuffle
docker compose up -d opensearch
sleep 90
curl -k -u admin:<your-strong-password> https://localhost:9201/_cluster/health?pretty
docker compose up -d backend orborus
sleep 60
docker compose up -d frontend
sleep 30
docker compose ps
```

Expected output:

```text
NAME                 STATUS
shuffle-opensearch   Up
shuffle-backend      Up
shuffle-orborus      Up
shuffle-frontend     Up
```

---

### 4.8 Verify OpenSearch Cluster Health

```bash
curl -k -u admin:<your-strong-password> https://localhost:9201/_cluster/health?pretty
```

Expected output:

```json
{
  "cluster_name" : "shuffle-cluster",
  "status" : "green",
  "number_of_nodes" : 1,
  "active_primary_shards" : 3,
  "active_shards" : 3
}
```

---

## 5. Shuffle Web Interface Setup

### 5.1 Access Shuffle Interface

* Open: [https://192.168.1.130:3443](https://192.168.1.130:3443)
* Accept SSL warning due to self-signed certificate.

---

### 5.2 Create Administrator Account

* On first access, go to `/adminsetup`.
* Fill in:

  * **Email:** `<your-email>`
  * **Username:** `admin`
  * **Password:** `<your-admin-password>`

---

### 5.3 Create Wazuh Integration Workflow

1. Log in → Click **Workflows**
2. Click **New Workflow**
3. Name: `Wazuh-Shuffle`
4. Drag **Webhook** trigger onto canvas
5. Click Webhook node → Copy **Webhook URI**
6. Click **Save**

Your Webhook URL:
`<your-shuffle-webhook-url>`

---

## 6. Wazuh Integration Configuration

### 6.1 Backup Existing Configuration

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup-$(date +%Y%m%d-%H%M%S)
ls -lh /var/ossec/etc/ossec.conf*
```

---

### 6.2 Add Shuffle Integration to ossec.conf

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add before the closing `</ossec_config>`:

```xml
<!-- ============================================== -->
<!-- INTEGRATIONS -->
<!-- ============================================== -->
<!-- Shuffle SOAR Integration -->
<integration>
  <name>shuffle</name>
  <hook_url><your-shuffle-webhook-url></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

---

### 6.3 Validate XML Syntax

```bash
sudo xmllint --noout /var/ossec/etc/ossec.conf
```

No output = XML is valid.

---

### 6.4 Restart Wazuh Services

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
sudo systemctl restart wazuh-dashboard   # optional
sudo systemctl restart wazuh-indexer     # optional
```

Expected status output:

```text
● wazuh-manager.service - Wazuh manager
   Active: active (running)
   ...
   ├─ wazuh-integratord
   ...
```

---

### 6.5 Monitor Integration Logs

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

---

## 7. Verification and Testing

### 7.1 Test Webhook Connectivity

```bash
curl -k -X POST "<your-shuffle-webhook-url>" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "manual_test",
    "message": "Testing Shuffle webhook connectivity",
    "severity": 5,
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  }'
```

Expected response:

```json
{
  "success": true,
  "execution_id": "...",
  "authorization": "..."
}
```

---

### 7.2 Verify in Shuffle Interface

1. Go to Shuffle: [https://192.168.1.130:3443](https://192.168.1.130:3443)
2. Click **Executions**
3. Test execution appears
4. Click to view the received data

---

## 8. Post-Installation Testing Methodology

### 8.1 Generate SSH Brute Force Alert

```bash
for i in {1..5}; do
  sudo logger -p authpriv.warning "sshd[$$]: Failed password for root from 192.168.1.100 port 22 ssh2"
  sleep 2
done
```

Expected: Wazuh generates alert (Rule ID: 5551), alert sent to Shuffle.

---

### 8.2 Generate File Integrity Monitoring Alert

```bash
sudo mkdir -p /tmp/malware_samples
sudo touch /tmp/malware_samples/suspicious_file.sh
sudo nano /tmp/malware_samples/suspicious_file.sh
```

Add:

```bash
#!/bin/bash
echo "Potential malicious script"
```

Save, then:

```bash
sudo chmod +x /tmp/malware_samples/suspicious_file.sh
```

Expected: Wazuh detects FIM event, forwards alert to Shuffle.

---

### 8.3 Generate EICAR Malware Test

```bash
curl -o /tmp/eicar.com 'https://secure.eicar.org/eicar.com'
```

Or create manually:

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_manual.txt
```

---

### 8.4 Monitor Integration Logs

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Expected:

```text
INFO: Sending alert to integration: shuffle
INFO: Alert sent successfully to <your-shuffle-webhook-url>
```

---

### 8.5 Verify Alerts in Shuffle

* Open Shuffle: [https://192.168.1.130:3443](https://192.168.1.130:3443)
* Navigate to **Executions**
* View: alert JSON, timestamp, alert details

---

### 8.6 Verify Alerts in Wazuh Dashboard

* Open Wazuh Dashboard: [https://192.168.1.130](https://192.168.1.130)
* Go to **Security Events**
* Filter recent alerts and cross-reference with Shuffle executions

---

## 9. Configuration Files Reference

### 9.1 Complete .env File

Location: `/home/brunoflausino/Shuffle/.env`

```env
# Frontend Ports
FRONTEND_PORT=3002
FRONTEND_PORT_HTTPS=3443
# Backend
BACKEND_HOSTNAME=shuffle-backend
BACKEND_PORT=5001
OUTER_HOSTNAME=shuffle-backend
# Locations (relative paths)
DB_LOCATION=./shuffle-database
SHUFFLE_APP_HOTLOAD_LOCATION=./shuffle-apps
SHUFFLE_FILE_LOCATION=./shuffle-files
# OpenSearch
SHUFFLE_OPENSEARCH_URL=https://shuffle-opensearch:9200
SHUFFLE_OPENSEARCH_USERNAME=admin
SHUFFLE_OPENSEARCH_PASSWORD=<your-strong-password>
OPENSEARCH_INITIAL_ADMIN_PASSWORD=<your-strong-password>
SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true
# App SDK
SHUFFLE_APP_SDK_TIMEOUT=300
SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY=7
# General Configurations
SHUFFLE_SKIPSSL_VERIFY=true
SHUFFLE_DEBUG=true
SHUFFLE_LOGS_DISABLED=false
TZ=Europe/Madrid
# Orborus
ENVIRONMENT_NAME=Shuffle
ORG_ID=Shuffle
BASE_URL=http://shuffle-backend:5001
DOCKER_API_VERSION=1.40
SHUFFLE_STATS_DISABLED=false
SHUFFLE_SWARM_CONFIG=run
SHUFFLE_WORKER_IMAGE=ghcr.io/shuffle/shuffle-worker:latest
```

---

### 9.2 Wazuh Integration Block (ossec.conf)

Add this section to `/var/ossec/etc/ossec.conf` before `</ossec_config>`:

```xml
<!-- Shuffle SOAR Integration -->
<integration>
  <name>shuffle</name>
  <hook_url><your-shuffle-webhook-url></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

---

## 10. Troubleshooting Reference

### 10.1 Common Issues and Solutions

**"Waiting for the Shuffle database to become available"**

```bash
docker logs shuffle-opensearch --tail 50
curl -k -u admin:<your-strong-password> https://localhost:9201/_cluster/health
cd ~/Shuffle
docker compose restart opensearch
```

**Containers not starting**

```bash
free -h
ls -ln ~/Shuffle/ | grep shuffle-database
sudo chown -R 1000:1000 ~/Shuffle/shuffle-database
```

**Wazuh not sending alerts**

```bash
sudo systemctl status wazuh-manager | grep integratord
sudo tail -50 /var/ossec/logs/integrations.log
sudo xmllint --noout /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

**Port conflicts**

```bash
sudo lsof -i :9201
```

Change port mapping or kill conflicting process.

---

### 10.2 Diagnostic Commands

```bash
#!/bin/bash
# Shuffle-Wazuh Integration Diagnostic
echo "=== SHUFFLE DIAGNOSTIC ==="
echo "Date: $(date)"
echo
echo "1. Docker Containers:"
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "shuffle|opensearch"
echo
echo "2. OpenSearch Health:"
curl -k -u admin:<your-strong-password> https://localhost:9201/_cluster/health 2>/dev/null | jq '.'
echo
echo "3. Shuffle Backend Logs (last 20 lines):"
docker logs shuffle-backend --tail 20
echo
echo "4. Wazuh Integration Status:"
sudo systemctl status wazuh-manager | grep -A5 integratord
echo
echo "5. Recent Integration Logs:"
sudo tail -20 /var/ossec/logs/integrations.log
echo
echo "6. System Resources:"
echo "Memory:"
free -h
echo "Disk:"
df -h /
echo
echo "=== DIAGNOSTIC
```


COMPLETE ==="

````

---

## 11. Maintenance and Operations

### 11.1 Starting/Stopping Shuffle

```bash
cd ~/Shuffle
docker compose down       # Stop all Shuffle services
docker compose up -d      # Start all services
docker compose restart backend   # Restart a specific service
docker compose logs -f backend  # View logs
````

---

### 11.2 Updating Shuffle

```bash
cd ~/Shuffle
docker compose down
docker compose pull
docker compose up -d
```

---

### 11.3 Backing Up Shuffle Data

```bash
sudo tar -czf shuffle-backup-$(date +%Y%m%d).tar.gz ~/Shuffle/shuffle-database
cp ~/Shuffle/.env ~/shuffle-env-backup-$(date +%Y%m%d)
cp ~/Shuffle/docker-compose.yml ~/shuffle-compose-backup-$(date +%Y%m%d)
```

---

### 11.4 Monitoring Shuffle Health

```bash
docker compose ps
docker stats shuffle-opensearch shuffle-backend shuffle-frontend
docker compose logs -f
```

---

## 12. Security Considerations

### 12.1 Production Hardening Recommendations

1. **Change Default Passwords:**

   * OpenSearch admin password
   * Shuffle admin account password

2. **Enable Firewall Rules:**

   ```bash
   sudo ufw allow 3443/tcp
   sudo ufw allow from <wazuh-ip> to any port 3443
   ```

3. **Use Valid SSL Certificates:**

   * Use Let's Encrypt or corporate CA

4. **Restrict Network Access:**

   * Limit Shuffle access to specific IP ranges
   * Use VPN for remote access

5. **Enable Authentication:**

   * Strong password policies
   * Enable 2FA if available

6. **Regular Updates:**

   * Keep Docker images updated

---

## 13. Appendix: Complete Script Collection

### 13.1 Complete Installation Script

```bash
#!/bin/bash
# Complete Shuffle Installation Script
# Run as regular user (will prompt for sudo when needed)
set -e
echo "=== Shuffle Installation Script ==="
echo "Starting at: $(date)"
echo
# 1. System Configuration
echo "Step 1: Configuring system..."
sudo sysctl -w vm.max_map_count=262144
sudo nano /etc/sysctl.conf  # Add vm.max_map_count=262144 and save
sudo sysctl -p
sudo swapoff -a
# 2. Create directory structure
echo "Step 2: Creating directories..."
mkdir -p ~/Shuffle
cd ~/Shuffle
# 3. Clone repository
echo "Step 3: Cloning Shuffle repository..."
if [ -d ".git" ]; then
  echo "Repository already exists, pulling latest changes..."
  git pull
else
  git clone https://github.com/Shuffle/Shuffle.git .
fi
# 4. Create .env file
echo "Step 4: Creating configuration..."
cat > .env << 'EOF'
FRONTEND_PORT=3002
FRONTEND_PORT_HTTPS=3443
BACKEND_HOSTNAME=shuffle-backend
BACKEND_PORT=5001
OUTER_HOSTNAME=shuffle-backend
DB_LOCATION=./shuffle-database
SHUFFLE_APP_HOTLOAD_LOCATION=./shuffle-apps
SHUFFLE_FILE_LOCATION=./shuffle-files
SHUFFLE_OPENSEARCH_URL=https://shuffle-opensearch:9200
SHUFFLE_OPENSEARCH_USERNAME=admin
SHUFFLE_OPENSEARCH_PASSWORD=<your-strong-password>
OPENSEARCH_INITIAL_ADMIN_PASSWORD=<your-strong-password>
SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true
SHUFFLE_APP_SDK_TIMEOUT=300
SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY=7
SHUFFLE_SKIPSSL_VERIFY=true
SHUFFLE_DEBUG=true
SHUFFLE_LOGS_DISABLED=false
TZ=Europe/Madrid
ENVIRONMENT_NAME=Shuffle
ORG_ID=Shuffle
BASE_URL=http://shuffle-backend:5001
DOCKER_API_VERSION=1.40
SHUFFLE_STATS_DISABLED=false
SHUFFLE_SWARM_CONFIG=run
SHUFFLE_WORKER_IMAGE=ghcr.io/shuffle/shuffle-worker:latest
EOF
# 5. Create directories and set permissions
echo "Step 5: Creating data directories..."
mkdir -p shuffle-database shuffle-apps shuffle-files
sudo chown -R 1000:1000 shuffle-database
chmod -R 755 shuffle-apps shuffle-files
# 6. Modify docker-compose.yml for port
echo "Step 6: Modifying port mapping..."
sed -i 's/- 9200:9200/- 9201:9200/' docker-compose.yml
# 7. Pull images
echo "Step 7: Pulling Docker images..."
docker compose pull
# 8. Start services
echo "Step 8: Starting Shuffle services..."
docker compose up -d opensearch
echo "Waiting for OpenSearch (90 seconds)..."
sleep 90
docker compose up -d backend orborus
echo "Waiting for Backend (60 seconds)..."
sleep 60
docker compose up -d frontend
echo "Waiting for Frontend (30 seconds)..."
sleep 30
# 9. Verify
echo "Step 9: Verifying installation..."
docker compose ps
echo
echo "=== Installation Complete ==="
echo "Access Shuffle at: https://192.168.1.130:3443"
echo "Create admin account at: https://192.168.1.130:3443/adminsetup"
echo
```

---

### 13.2 Alert Testing Script

```bash
#!/bin/bash
# Wazuh-Shuffle Alert Testing Script
echo "=== Wazuh-Shuffle Alert Testing ==="
echo
# Test 1: SSH Brute Force
echo "Test 1: Generating SSH brute force alerts..."
for i in {1..5}; do
  sudo logger -p authpriv.warning "sshd[$$]: Failed password for root from 192.168.1.100 port 22 ssh2"
  sleep 2
done
echo "✓ SSH brute force alerts generated"
echo
# Test 2: File Integrity Monitoring
echo "Test 2: Triggering FIM alert..."
sudo mkdir -p /tmp/malware_samples
sudo touch /tmp/malware_samples/test_file_$(date +%s).txt
sudo nano /tmp/malware_samples/test_file_$(date +%s).txt  # Add "Suspicious content" and save
echo "✓ FIM alert triggered"
echo
# Test 3: Privilege Escalation Attempt
echo "Test 3: Simulating privilege escalation..."
sudo logger -p authpriv.warning "sudo: testuser : command not allowed ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
echo "✓ Privilege escalation alert generated"
echo
# Test 4: Direct webhook test
echo "Test 4: Testing webhook directly..."
curl -k -X POST "<your-shuffle-webhook-url>" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "test_script",
    "message": "Direct webhook test",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "severity": 5
  }' 2>/dev/null
echo
echo "✓ Direct webhook test completed"
echo
echo "=== Testing Complete ==="
echo "Check Shuffle executions at: https://192.168.1.130:3443/workflows"
echo "Monitor Wazuh logs: sudo tail -f /var/ossec/logs/integrations.log"
```

---

## 14. Conclusion

This integration successfully connects Wazuh SIEM with Shuffle SOAR, enabling automated incident response workflows. All alerts from Wazuh with severity level 3 or higher are automatically forwarded to Shuffle via webhook, where custom automation workflows can be triggered.

**Key Success Indicators:**

* ✓ All Docker containers running healthy
* ✓ OpenSearch cluster status: green
* ✓ Wazuh Manager active with integratord running
* ✓ Webhook connectivity verified
* ✓ Test alerts successfully received in Shuffle

**Personal Credentials (For Reference):**

* Email: `<your-email>`
* Password: `<your-admin-password>`
* Webhook URL: `<your-shuffle-webhook-url>`

**Next Steps:**

1. Design custom workflow automations in Shuffle
2. Configure automated response actions (blocking IPs, quarantining files, etc.)
3. Integrate with additional security tools (VirusTotal, MISP, threat intelligence feeds)
4. Set up email/Slack notifications for critical alerts
5. Create dashboards for monitoring automation effectiveness

---

**Report End**
*Last Updated: October 20, 2025*
*Environment: Ubuntu 24.04 LTS (192.168.1.130)*
*Status: Fully Operational*

---

## Addendum: SSL Certificate Verification Error Resolution

**Date:** October 20, 2025
**Issue:** Wazuh-Shuffle integration failing with SSL certificate verification errors
**Status:** Resolved

### Problem Description

After successfully installing Shuffle and configuring the Wazuh integration, alerts were being generated but failing to reach Shuffle with the following error:

```
HTTPSConnectionPool(host='192.168.1.130', port=3443): Max retries exceeded with url: /api/v1/hooks/webhook_cdf495b6-f6aa-4c44-a7d3-8a97bf2feb56 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1007)')))
```

**Root Cause:** Wazuh's integration script uses Python's requests library, which by default verifies SSL certificates. Shuffle uses a self-signed certificate, which fails standard verification.

---

### Solution: Modify Wazuh Integration Script

**Step 1: Backup Original Script**

```bash
sudo cp /var/ossec/integrations/shuffle.py /var/ossec/integrations/shuffle.py.backup
```

**Step 2: Identify the Script to Modify**

* `/var/ossec/integrations/shuffle` – Shell wrapper (no changes)
* `/var/ossec/integrations/shuffle.py` – Python script (requires modification)

**Step 3: Locate the Critical Line**

```bash
sudo nano /var/ossec/integrations/shuffle.py
```

**Find the function (line 237 or similar):**

```python
def send_msg(msg: str, url: str) -> None:
    """Send the message to the API
    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the integration.
    """
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    debug('# Response received: %s' % res.json)
```

**Modified code (add `verify=False`):**

```python
def send_msg(msg: str, url: str) -> None:
    """Send the message to the API
    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the integration.
    """
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, timeout=10, verify=False)
    debug('# Response received: %s' % res.json)
```

*Change:* Add `, verify=False` to the `requests.post()` call.

---

**Step 4: Save and Restart Services**

```bash
# Restart Wazuh Manager to apply changes
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

---

### Verification

**Monitor Integration Logs**

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Expected Output (Success):

```text
# Sending message {...} to Shuffle server
# Response received: <bound method Response.json of <Response [200]>>
```

HTTP 200 status confirms successful delivery.

**Verify in Shuffle Interface**

* Access Shuffle: [https://192.168.1.130:3443](https://192.168.1.130:3443)
* Go to **Executions**
* Click any execution to view full alert JSON from Wazuh

**Test Alert Generation**

```bash
for i in {1..5}; do
  sudo logger -p authpriv.warning "sshd[$$]: Failed password for root from 192.168.1.100 port 22 ssh2"
  sleep 2
done

sudo mkdir -p /tmp/malware_samples
sudo nano /tmp/malware_samples/test_file.sh  # Add #!/bin/bash and save
sudo chmod +x /tmp/malware_samples/test_file.sh

curl -o /tmp/eicar.com 'https://secure.eicar.org/eicar.com'
```

---

### Security Considerations

*Disabling SSL verification (verify=False) bypasses certificate validation. Acceptable for:*

* Lab/development environments
* Self-signed certs in trusted networks
* Same-host communications

*Production:*

1. Use valid SSL certificates from Let's Encrypt or corporate CA
2. Add Shuffle's certificate to system trust store:

```bash
openssl s_client -connect 192.168.1.130:3443 -showcerts </dev/null 2>/dev/null | openssl x509 -outform PEM > /tmp/shuffle-cert.pem
sudo cp /tmp/shuffle-cert.pem /usr/local/share/ca-certificates/shuffle.crt
sudo update-ca-certificates
```

Remove `verify=False` from shuffle.py, restart Wazuh.

3. Use HTTP for localhost if encryption not needed.

---

### Troubleshooting

**Changes not taking effect**

```bash
sudo grep "verify=False" /var/ossec/integrations/shuffle.py
sudo systemctl stop wazuh-manager
sleep 5
sudo systemctl start wazuh-manager
sudo systemctl status wazuh-manager | grep integratord
```

**Still seeing SSL errors**

```bash
sudo cp /var/ossec/integrations/shuffle.py.backup /var/ossec/integrations/shuffle.py
sudo nano /var/ossec/integrations/shuffle.py  # Manually add verify=False on line 237
sudo systemctl restart wazuh-manager
```

---

### Configuration Files Summary

**Modified File:**
`/var/ossec/integrations/shuffle.py` – Added `verify=False` on requests.post()

**Unchanged Configuration:**
`/var/ossec/etc/ossec.conf`
Integration block remains HTTPS:

```xml
<integration>
  <name>shuffle</name>
  <hook_url><your-shuffle-webhook-url></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

---

### Final Status

* **Integration Status:** Operational
* **Protocol:** HTTPS (self-signed cert accepted)
* **Alert Types Forwarded:** Privilege escalation, PAM session, service status, etc.

**Verification Command:**

```bash
curl -k -X POST "<your-shuffle-webhook-url>" \
  -H "Content-Type: application/json" \
  -d '{"test": "connectivity_check"}'
```

Expected Response:

```json
{"success": true, "execution_id": "..."}
```

---

**End of Addendum**
**Author:** Bruno Flausino
