# Comprehensive Technical Report: Shuffle SOAR Integration with Wazuh SIEM on Bare-Metal Ubuntu 24.04

**Author:** Bruno Flausino

**Date:** October 20, 2025

**Environment:** Ubuntu 24.04 LTS (Bare Metal)

**IP Address:** 192.168.1.130

**Objective:** Complete integration of Shuffle SOAR platform with Wazuh SIEM for automated security orchestration and incident response

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

## 1. Introduction

This report documents the complete methodology for integrating Shuffle SOAR (Security Orchestration, Automation, and Response) with Wazuh SIEM on a bare-metal Ubuntu 24.04 system. Shuffle provides workflow automation capabilities that enhance Wazuh's detection capabilities with automated response actions.

### 1.1 Architecture Overview

The integration consists of:

- Wazuh Manager: Generates security alerts based on log analysis and detection rules
- Shuffle Backend: Orchestrates workflows and manages integrations
- Shuffle Frontend: Provides web interface for workflow design
- OpenSearch: Database backend for Shuffle
- Webhook: Communication channel from Wazuh to Shuffle

### 1.2 Network Configuration

- Host IP: 192.168.1.130
- Shuffle Frontend HTTP: Port 3002
- Shuffle Frontend HTTPS: Port 3443
- Shuffle Backend API: Port 5001
- OpenSearch: Port 9201 (host) → 9200 (container)
- Wazuh Manager: Standard ports (1514, 1515)

## 2. Prerequisites and System Requirements

### 2.1 Minimum Hardware Requirements

- CPU: 4 cores minimum (8 cores recommended)
- RAM: 8GB minimum (16GB recommended for production)
- Disk: 50GB free space
- Network: Static IP or DHCP reservation

### 2.2 Software Requirements

- Ubuntu 24.04 LTS
- Docker Engine 24.x or later
- Docker Compose v2.x (plugin method)
- Git
- Existing Wazuh Manager installation

### 2.3 Verify Prerequisites

Before starting, verify your system meets requirements:

Check Ubuntu version:

```bash
lsb_release -a
```

Check available memory:

```bash
free -h
```

Check disk space:

```bash
df -h /
```

Check if Docker is installed:

```bash
docker --version
```

```bash
docker compose version
```

Check if Wazuh is running:

```bash
sudo systemctl status wazuh-manager
```

## 3. Initial System Configuration

### 3.1 Kernel Configuration for OpenSearch

OpenSearch requires specific kernel parameters to function properly.

Configure vm.max_map_count (required for OpenSearch):

```bash
sudo sysctl -w vm.max_map_count=262144
```

Make it permanent:

```bash
sudo nano /etc/sysctl.conf
```

Add the following line to the file:

vm.max_map_count=262144

Save and exit nano.

Apply changes:

```bash
sudo sysctl -p
```

Verify:

```bash
sysctl -n vm.max_map_count
```

Expected output: 262144

### 3.2 Disable Swap (Recommended for OpenSearch)

Disable swap temporarily:

```bash
sudo swapoff -a
```

Verify swap is disabled:

```bash
swapon --show
```

Note: To disable swap permanently, comment out swap entries in /etc/fstab

### 3.3 Verify Port Availability

Ensure required ports are not in use.

Check if ports are available:

```bash
sudo netstat -tulpn | grep -E ":(3002|3443|5001|9201)"
```

If ports are in use, identify the process:

```bash
sudo lsof -i :3443
```

## 4. Shuffle Installation

### 4.1 Create Base Directory Structure

Navigate to home directory:

```bash
cd ~
```

Create Shuffle directory:

```bash
mkdir -p ~/Shuffle
```

Change to Shuffle directory:

```bash
cd ~/Shuffle
```

### 4.2 Clone Shuffle Repository

Clone official Shuffle repository:

```bash
git clone https://github.com/Shuffle/Shuffle.git .
```

Verify clone was successful:

```bash
ls -la
```

Expected files:

- docker-compose.yml
- backend/
- frontend/
- .env (will be created)

### 4.3 Create Environment Configuration File

Create .env file with complete configuration:

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

### 4.4 Create Required Directories with Proper Permissions

Change to Shuffle directory:

```bash
cd ~/Shuffle
```

Create directories:

```bash
mkdir -p shuffle-database shuffle-apps shuffle-files
```

Set correct permissions for OpenSearch (UID 1000):

```bash
sudo chown -R 1000:1000 shuffle-database
```

Set permissions for other directories:

```bash
chmod -R 755 shuffle-apps shuffle-files
```

Verify permissions:

```bash
ls -ln | grep shuffle-
```

Expected output for shuffle-database:

drwxr-xr-x 2 1000 1000 4096 Oct 20 09:11 shuffle-database

### 4.5 Modify docker-compose.yml for Port Mapping

The default docker-compose.yml maps OpenSearch to port 9200. Modify it to use port 9201 to avoid conflicts with Wazuh's OpenSearch.

Change to Shuffle directory:

```bash
cd ~/Shuffle
```

Change OpenSearch port mapping from 9200 to 9201:

```bash
sed -i 's/- 9200:9200/- 9201:9200/' docker-compose.yml
```

Verify the change:

```bash
grep "9201:9200" docker-compose.yml
```

Expected output:

- 9201:9200

### 4.6 Pull Docker Images

Change to Shuffle directory:

```bash
cd ~/Shuffle
```

Pull all required images:

```bash
docker compose pull
```

This will download:

- ghcr.io/shuffle/shuffle-frontend:latest
- ghcr.io/shuffle/shuffle-backend:latest
- ghcr.io/shuffle/shuffle-orborus:latest
- opensearchproject/opensearch:3.2.0

### 4.7 Start Shuffle Services

Start services in specific order to ensure proper initialization.

Change to Shuffle directory:

```bash
cd ~/Shuffle
```

Start OpenSearch first:

```bash
docker compose up -d opensearch
```

Wait for OpenSearch to initialize:

```bash
sleep 90
```

Verify OpenSearch health:

```bash
curl -k -u admin:<your-strong-password> https://localhost:9201/_cluster/health?pretty
```

Start backend and orborus:

```bash
docker compose up -d backend orborus
```

Wait for backend initialization:

```bash
sleep 60
```

Start frontend:

```bash
docker compose up -d frontend
```

Wait for frontend startup:

```bash
sleep 30
```

Verify all containers are running:

```bash
docker compose ps
```

Expected output from docker compose ps:

NAME                 STATUS
shuffle-opensearch   Up
shuffle-backend      Up
shuffle-orborus      Up
shuffle-frontend     Up

### 4.8 Verify OpenSearch Cluster Health

```bash
curl -k -u admin:<your-strong-password> https://localhost:9201/_cluster/health?pretty
```

Expected output:

{
  "cluster_name" : "shuffle-cluster",
  "status" : "green",
  "number_of_nodes" : 1,
  "active_primary_shards" : 3,
  "active_shards" : 3
}

## 5. Shuffle Web Interface Setup

### 5.1 Access Shuffle Interface

Open your web browser and navigate to:

https://192.168.1.130:3443

Note: You will see an SSL certificate warning because Shuffle uses a self-signed certificate. This is expected - proceed by accepting the security exception.

### 5.2 Create Administrator Account

On first access, you'll be redirected to /adminsetup. Create your administrator account with the following credentials:

- Email: <your-email>
- Username: admin
- Password: <your-admin-password>

Important: Store these credentials securely. They are required for all future logins.

### 5.3 Create Wazuh Integration Workflow

1. After logging in, click "Workflows" in the left sidebar
2. Click "New Workflow"
3. Name it: Wazuh-Shuffle
4. In the workflow canvas, click "Triggers" on the left
5. Drag the "Webhook" trigger to the canvas
6. Click on the Webhook node
7. On the right panel, note the Webhook URI field
8. Click the copy icon to copy the webhook URL

Your Webhook URL:

<your-shuffle-webhook-url>

9. Click "Save" at the top right to save the workflow

## 6. Wazuh Integration Configuration

### 6.1 Backup Existing Configuration

Always backup before making changes:

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup-$(date +%Y%m%d-%H%M%S)
```

Verify backup was created:

```bash
ls -lh /var/ossec/etc/ossec.conf*
```

### 6.2 Add Shuffle Integration to ossec.conf

Edit the Wazuh configuration file:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add the following integration block before the closing </ossec_config> tag:

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

Configuration Parameters Explained:

- <name>shuffle</name>: Identifier for this integration
- <hook_url>: Your Shuffle webhook URL
- <level>3</level>: Only alerts with severity level ≥3 will be sent
- <alert_format>json</alert_format>: Alerts are sent in JSON format

### 6.3 Validate XML Syntax

Before restarting Wazuh, validate the XML configuration:

```bash
sudo xmllint --noout /var/ossec/etc/ossec.conf
```

If no output, the XML is valid. If there are errors, they will be displayed.

### 6.4 Restart Wazuh Services

Restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
```

Verify service is running:

```bash
sudo systemctl status wazuh-manager
```

Restart Wazuh Dashboard (optional, for UI consistency):

```bash
sudo systemctl restart wazuh-dashboard
```

Restart Wazuh Indexer (optional):

```bash
sudo systemctl restart wazuh-indexer
```

Expected status output:

● wazuh-manager.service - Wazuh manager
   Active: active (running)
   ...
   ├─ wazuh-integratord
   ...

Important: Verify that wazuh-integratord process is running in the CGroup list.

### 6.5 Monitor Integration Logs

Open a terminal and monitor integration logs in real-time:

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Keep this terminal open to see when alerts are sent to Shuffle.

## 7. Verification and Testing

### 7.1 Test Webhook Connectivity

Test that Shuffle can receive data from external sources:

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

{
  "success": true,
  "execution_id": "...",
  "authorization": "..."
}

### 7.2 Verify in Shuffle Interface

1. Go to Shuffle interface: https://192.168.1.130:3443
2. Click "Executions" in left sidebar
3. You should see your test execution listed
4. Click on it to see the received data

## 8. Post-Installation Testing Methodology

### 8.1 Generate SSH Brute Force Alert

Simulate failed SSH login attempts:

```bash
for i in {1..5}; do
  sudo logger -p authpriv.warning "sshd[$$]: Failed password for root from 192.168.1.100 port 22 ssh2"
  sleep 2
done
```

Expected Result:

Wazuh generates alert for brute force attack (Rule ID: 5551)

Alert is sent to Shuffle webhook

Execution appears in Shuffle interface

### 8.2 Generate File Integrity Monitoring Alert

Create and modify a monitored file:

Create test directory if it doesn't exist:

```bash
sudo mkdir -p /tmp/malware_samples
```

Add file:

```bash
sudo touch /tmp/malware_samples/suspicious_file.sh
```

Modify file to trigger FIM alert:

```bash
sudo nano /tmp/malware_samples/suspicious_file.sh
```

Add the following content:

#!/bin/bash

echo "Potential malicious script"

Save and exit nano.

Make executable:

```bash
sudo chmod +x /tmp/malware_samples/suspicious_file.sh
```

Expected Result:

Wazuh detects file creation/modification via syscheck

Alert level ≥3 triggers integration

Alert forwarded to Shuffle

### 8.3 Generate EICAR Malware Test

Download EICAR test file to trigger malware detection:

```bash
curl -o /tmp/eicar.com 'https://secure.eicar.org/eicar.com'
```

Alternative: Create EICAR string manually:

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_manual.txt
```

Expected Result:

ClamAV or Wazuh detects EICAR signature

High-severity alert generated

Alert forwarded to Shuffle

### 8.4 Monitor Integration Logs

In the terminal monitoring logs, you should see:

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Expected log entries:

INFO: Sending alert to integration: shuffle

INFO: Alert sent successfully to <your-shuffle-webhook-url>

### 8.5 Verify Alerts in Shuffle

1. Open Shuffle: https://192.168.1.130:3443
2. Navigate to Executions
3. You should see new executions for each alert
4. Click on an execution to view:

- Complete alert JSON from Wazuh
- Timestamp
- Alert details (rule ID, description, agent info)

### 8.6 Verify Alerts in Wazuh Dashboard

1. Open Wazuh Dashboard: https://192.168.1.130 (or your Wazuh dashboard URL)
2. Navigate to Security Events
3. Filter by recent time range
4. Verify the test alerts are visible
5. Cross-reference with Shuffle executions

## 9. Configuration Files Reference

### 9.1 Complete .env File

Location: /home/brunoflausino/Shuffle/.env

```bash
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

### 9.2 Wazuh Integration Block (ossec.conf)

Add this section to /var/ossec/etc/ossec.conf before </ossec_config>:

```xml
<!-- Shuffle SOAR Integration -->
<integration>
  <name>shuffle</name>
  <hook_url><your-shuffle-webhook-url></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

## 10. Troubleshooting Reference

### 10.1 Common Issues and Solutions

**Issue:** "Waiting for the Shuffle database to become available"

**Cause:** OpenSearch not accessible or not started properly

**Solution:**

Check OpenSearch logs:

```bash
docker logs shuffle-opensearch --tail 50
```

Verify OpenSearch health:

```bash
curl -k -u admin:<your-strong-password> https://localhost:9201/_cluster/health
```

Restart if needed:

```bash
cd ~/Shuffle
```

```bash
docker compose restart opensearch
```

**Issue:** Containers not starting

**Cause:** Insufficient memory or wrong permissions

**Solution:**

Check available memory:

```bash
free -h
```

Verify permissions:

```bash
ls -ln ~/Shuffle/ | grep shuffle-database
```

Should show: 1000 1000

Fix permissions if needed:

```bash
sudo chown -R 1000:1000 ~/Shuffle/shuffle-database
```

**Issue:** Wazuh not sending alerts to Shuffle

**Cause:** Integration not configured correctly or wazuh-integratord not running

**Solution:**

Verify integratord is running:

```bash
sudo systemctl status wazuh-manager | grep integratord
```

Check integration logs:

```bash
sudo tail -50 /var/ossec/logs/integrations.log
```

Verify XML syntax:

```bash
sudo xmllint --noout /var/ossec/etc/ossec.conf
```

Restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

**Issue:** Port conflicts

**Cause:** Another service using required ports

**Solution:**

Identify what's using the port:

```bash
sudo lsof -i :9201
```

Kill the process or change Shuffle's port mapping in docker-compose.yml

### 10.2 Diagnostic Commands

Complete diagnostic script:

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
echo "=== DIAGNOSTIC COMPLETE ==="
```

## 11. Maintenance and Operations

### 11.1 Starting/Stopping Shuffle

Stop all Shuffle services:

```bash
cd ~/Shuffle
```

```bash
docker compose down
```

Start all services:

```bash
docker compose up -d
```

Restart a specific service:

```bash
docker compose restart backend
```

View logs:

```bash
docker compose logs -f backend
```

### 11.2 Updating Shuffle

```bash
cd ~/Shuffle
```

Stop services:

```bash
docker compose down
```

Pull latest images:

```bash
docker compose pull
```

Start with new images:

```bash
docker compose up -d
```

### 11.3 Backing Up Shuffle Data

Backup Shuffle database:

```bash
sudo tar -czf shuffle-backup-$(date +%Y%m%d).tar.gz ~/Shuffle/shuffle-database
```

Backup configuration:

```bash
cp ~/Shuffle/.env ~/shuffle-env-backup-$(date +%Y%m%d)
```

```bash
cp ~/Shuffle/docker-compose.yml ~/shuffle-compose-backup-$(date +%Y%m%d)
```

### 11.4 Monitoring Shuffle Health

Check all containers:

```bash
docker compose ps
```

Check resource usage:

```bash
docker stats shuffle-opensearch shuffle-backend shuffle-frontend
```

Monitor logs in real-time:

```bash
docker compose logs -f
```

## 12. Security Considerations

### 12.1 Production Hardening Recommendations

1. Change Default Passwords:
   - OpenSearch admin password
   - Shuffle admin account password

2. Enable Firewall Rules:

```bash
sudo ufw allow 3443/tcp  # Shuffle HTTPS
```

```bash
sudo ufw allow from <wazuh-ip> to any port 3443
```

3. Use Valid SSL Certificates:
   - Replace self-signed certificates with Let's Encrypt or corporate CA

4. Restrict Network Access:
   - Limit Shuffle access to specific IP ranges
   - Use VPN for remote access

5. Enable Authentication:
   - Configure strong password policies
   - Enable 2FA if available

6. Regular Updates:
   - Keep Docker images updated
   - Monitor security advisories for Shuffle and OpenSearch

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
sudo bash -c 'echo "vm.max_map_count=262144" >> /etc/sysctl.conf'
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
sudo bash -c 'echo "Suspicious content" >> /tmp/malware_samples/test_file_$(date +%s).txt'
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

## 14. Conclusion

This integration successfully connects Wazuh SIEM with Shuffle SOAR, enabling automated incident response workflows. All alerts from Wazuh with severity level 3 or higher are automatically forwarded to Shuffle via webhook, where custom automation workflows can be triggered.

Key Success Indicators:

✓ All Docker containers running healthy

✓ OpenSearch cluster status: green

✓ Wazuh Manager active with integratord running

✓ Webhook connectivity verified

✓ Test alerts successfully received in Shuffle

Personal Credentials (For Reference):

- Email: <your-email>
- Password: <your-admin-password>

Webhook URL: <your-shuffle-webhook-url>

Next Steps:

1. Design custom workflow automations in Shuffle
2. Configure automated response actions (blocking IPs, quarantining files, etc.)
3. Integrate with additional security tools (VirusTotal, MISP, threat intelligence feeds)
4. Set up email/Slack notifications for critical alerts
5. Create dashboards for monitoring automation effectiveness

Report End

Last Updated: October 20, 2025

Environment: Ubuntu 24.04 LTS (192.168.1.130)

Status: Fully Operational

## Addendum: SSL Certificate Verification Error Resolution

**Date:** October 20, 2025

**Issue:** Wazuh-Shuffle integration failing with SSL certificate verification errors

**Status:** Resolved

### Problem Description

After successfully installing Shuffle and configuring the Wazuh integration, alerts were being generated but failing to reach Shuffle with the following error:

HTTPSConnectionPool(host='192.168.1.130', port=3443): Max retries exceeded with url: /api/v1/hooks/webhook_cdf495b6-f6aa-4c44-a7d3-8a97bf2feb56 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1007)')))

Root Cause: Wazuh's integration script uses Python's requests library, which by default verifies SSL certificates. Shuffle uses a self-signed certificate, which fails standard verification.

### Solution: Modify Wazuh Integration Script

Step 1: Backup Original Script

```bash
sudo cp /var/ossec/integrations/shuffle.py /var/ossec/integrations/shuffle.py.backup
```

Step 2: Identify the Script to Modify

The integration consists of two files:

- /var/ossec/integrations/shuffle - Shell wrapper (no changes needed)
- /var/ossec/integrations/shuffle.py - Python script (requires modification)

Step 3: Locate the Critical Line

Open the Python script:

```bash
sudo nano /var/ossec/integrations/shuffle.py
```

Navigate to line 237 (in the send_msg function):

Original code:

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

Modified code (add verify=False):

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

Change: Add , verify=False parameter to requests.post() call on line 237.

Step 4: Save and Restart Services

Save the file (Ctrl+O, Enter, Ctrl+X in nano)

Restart Wazuh Manager to apply changes:

```bash
sudo systemctl restart wazuh-manager
```

Verify service is running:

```bash
sudo systemctl status wazuh-manager
```

### Verification

Monitor Integration Logs

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Expected Output (Success):

# Sending message {...} to Shuffle server
# Response received: <bound method Response.json of <Response [200]>>

HTTP 200 status confirms successful delivery.

Verify in Shuffle Interface

1. Access Shuffle: https://192.168.1.130:3443
2. Navigate to Executions (left sidebar)
3. Observe multiple workflow executions
4. Click any execution to view full alert JSON from Wazuh

Test Alert Generation

Generate test alerts to confirm integration:

SSH brute force simulation:

```bash
for i in {1..5}; do
  sudo logger -p authpriv.warning "sshd[$$]: Failed password for root from 192.168.1.100 port 22 ssh2"
  sleep 2
done
```

File integrity monitoring:

```bash
sudo mkdir -p /tmp/malware_samples
```

```bash
sudo nano /tmp/malware_samples/test_file.sh
```

Add content:

#!/bin/bash

Save and exit.

```bash
sudo chmod +x /tmp/malware_samples/test_file.sh
```

EICAR test file:

```bash
curl -o /tmp/eicar.com 'https://secure.eicar.org/eicar.com'
```

Monitor logs to confirm alerts reach Shuffle with HTTP 200 responses.

### Security Considerations

Important: Disabling SSL verification (verify=False) bypasses certificate validation. This is acceptable for:

- Lab/development environments
- Self-signed certificates in trusted networks
- Same-host communications (localhost/127.0.0.1)

For production environments, consider:

1. Use valid SSL certificates from Let's Encrypt or corporate CA
2. Add Shuffle's certificate to system trust store:

Extract certificate:

```bash
openssl s_client -connect 192.168.1.130:3443 -showcerts </dev/null 2>/dev/null | openssl x509 -outform PEM > /tmp/shuffle-cert.pem
```

Install certificate:

```bash
sudo cp /tmp/shuffle-cert.pem /usr/local/share/ca-certificates/shuffle.crt
```

```bash
sudo update-ca-certificates
```

Remove verify=False from shuffle.py

Restart Wazuh Manager

3. Use HTTP for same-host communications (port 3002) if encryption is not required

### Troubleshooting

**Issue:** Changes not taking effect

Verify modification is present:

```bash
sudo grep "verify=False" /var/ossec/integrations/shuffle.py
```

Force restart:

```bash
sudo systemctl stop wazuh-manager
```

```bash
sleep 5
```

```bash
sudo systemctl start wazuh-manager
```

Check if integratord process is running:

```bash
sudo systemctl status wazuh-manager | grep integratord
```

**Issue:** Still seeing SSL errors

Restore backup and reapply changes:

```bash
sudo cp /var/ossec/integrations/shuffle.py.backup /var/ossec/integrations/shuffle.py
```

```bash
sudo nano /var/ossec/integrations/shuffle.py
```

Manually add verify=False on line 237

```bash
sudo systemctl restart wazuh-manager
```

### Configuration Files Summary

**Modified File**

File: /var/ossec/integrations/shuffle.py

Line: 237

Change: Added verify=False parameter to requests.post()

**Unchanged Configuration**

File: /var/ossec/etc/ossec.conf

Integration block remains HTTPS:

```xml
<integration>
  <name>shuffle</name>
  <hook_url><your-shuffle-webhook-url></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

### Final Status

Integration Status: Operational

Protocol: HTTPS (self-signed certificate accepted)

Alert Types Successfully Forwarded:

- Rule 5402: Privilege escalation (sudo to root)
- Rule 17101: Non-business hours login
- Rule 5502: PAM session events
- Rule 502: Service status changes

Verification Command:

```bash
curl -k -X POST "<your-shuffle-webhook-url>" \
  -H "Content-Type: application/json" \
  -d '{"test": "connectivity_check"}'
```

Expected Response:

{"success": true, "execution_id": "..."}

End of Addendum
