# Shuffle SOAR Integration with Wazuh

[cite_start]This document provides a comprehensive, end-to-end methodology for installing the Shuffle SOAR platform on a bare-metal Ubuntu 24.04 server and integrating it with a Wazuh SIEM installation for automated incident response. [cite: 1562, 1567, 1580]

[cite_start]The objective is to configure Wazuh to forward alerts to Shuffle via a webhook, enabling Shuffle to orchestrate automated security workflows. [cite: 1581, 1588]

[cite_start]This guide includes the full installation of Shuffle using Docker Compose, the configuration of the Wazuh manager, and the critical troubleshooting step required to bypass SSL verification for Shuffle's self-signed certificate. [cite: 2246, 2247]

## 1. Prerequisites and System Preparation

### [cite_start]1.1 System Requirements [cite: 1596-1605]

* [cite_start]**OS:** Ubuntu 24.04 LTS [cite: 1602]
* [cite_start]**CPU:** 4 cores minimum (8 recommended) [cite: 1597]
* [cite_start]**RAM:** 8GB minimum (16GB recommended) [cite: 1598]
* [cite_start]**Disk:** 50GB free space [cite: 1599]
* [cite_start]**Software:** Docker, Docker Compose v2+, Git [cite: 1603, 1604]
* [cite_start]**Existing Wazuh Manager** [cite: 1605]

### 1.2 Kernel Configuration (for OpenSearch)

[cite_start]OpenSearch, Shuffle's database, requires a higher `vm.max_map_count` value. [cite: 1621]

1.  Set the value temporarily:
    ```bash
    sudo sysctl -w vm.max_map_count=262144
    ```
    [cite_start][cite: 1622]
2.  Make the change permanent:
    ```bash
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
    ```
    [cite_start][cite: 1624]
3.  Apply and verify the change:
    ```bash
    sudo sysctl -p
    sysctl -n vm.max_map_count
    ```
    [cite_start][cite: 1626, 1628] (Expected output: 262144) [cite_start][cite: 1629]

### 1.3 Disable Swap (Recommended)

[cite_start]Disabling swap is recommended for OpenSearch performance. [cite: 1630]

1.  Disable swap:
    ```bash
    sudo swapoff -a
    ```
    [cite_start][cite: 1633]
2.  [cite_start](Optional) To disable permanently, comment out the swap line in `/etc/fstab`. [cite: 1635]

---

## 2. Shuffle Installation (Docker Compose)

### 2.1 Create Directory Structure

1.  Create the base directory for Shuffle:
    ```bash
    mkdir -p ~/Shuffle
    cd ~/Shuffle
    ```
    [cite_start][cite: 1645, 1646]

### 2.2 Clone Repository

1.  Clone the official Shuffle repository into the current directory:
    ```bash
    git clone [https://github.com/Shuffle/Shuffle.git](https://github.com/Shuffle/Shuffle.git) .
    ```
    [cite_start][cite: 1649]

### 2.3 Create `.env` Configuration File

Create the `.env` file that defines all configuration variables for the Docker containers.

```bash
cat > ~/Shuffle/.env << 'EOF'
# Frontend Ports
[cite_start]FRONTEND_PORT=3002 [cite: 1663]
[cite_start]FRONTEND_PORT_HTTPS=3443 [cite: 1664]
# Backend
[cite_start]BACKEND_HOSTNAME=shuffle-backend [cite: 1666]
[cite_start]BACKEND_PORT=5001 [cite: 1667]
[cite_start]OUTER_HOSTNAME=shuffle-backend [cite: 1668]
# Locations (relative paths)
[cite_start]DB_LOCATION=./shuffle-database [cite: 1670]
[cite_start]SHUFFLE_APP_HOTLOAD_LOCATION=./shuffle-apps [cite: 1671]
[cite_start]SHUFFLE_FILE_LOCATION=./shuffle-files [cite: 1672]
# OpenSearch
[cite_start]SHUFFLE_OPENSEARCH_URL=https://shuffle-opensearch:9200 [cite: 1674]
[cite_start]SHUFFLE_OPENSEARCH_USERNAME=admin [cite: 1675]
[cite_start]SHUFFLE_OPENSEARCH_PASSWORD=StrongShufflePassword321! [cite: 1676]
[cite_start]OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongShufflePassword321! [cite: 1677]
[cite_start]SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true [cite: 1678]
# App SDK
[cite_start]SHUFFLE_APP_SDK_TIMEOUT=300 [cite: 1680]
[cite_start]SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY=7 [cite: 1681]
# General Settings
[cite_start]SHUFFLE_SKIPSSL_VERIFY=true [cite: 1683]
[cite_start]SHUFFLE_DEBUG=true [cite: 1684]
[cite_start]SHUFFLE_LOGS_DISABLED=false [cite: 1685]
[cite_start]TZ=Europe/Madrid [cite: 1686]
# Orborus
[cite_start]ENVIRONMENT_NAME=Shuffle [cite: 1688]
[cite_start]ORG_ID=Shuffle [cite: 1689]
[cite_start]BASE_URL=http://shuffle-backend:5001 [cite: 1690]
[cite_start]DOCKER_API_VERSION=1.40 [cite: 1691]
[cite_start]SHUFFLE_STATS_DISABLED=false [cite: 1692]
[cite_start]SHUFFLE_SWARM_CONFIG=run [cite: 1693]
[cite_start]SHUFFLE_WORKER_IMAGE=ghcr.io/shuffle/shuffle-worker:latest [cite: 1694]
EOF
````

### 2.4 Create Directories and Set Permissions

This step is critical for OpenSearch, which runs under user ID `1000`.

1.  Create the data directories defined in the `.env` file:
    ```bash
    cd ~/Shuffle
    mkdir -p shuffle-database shuffle-apps shuffle-files
    ```
    [cite\_start][cite: 1700]
2.  Set the correct ownership for the OpenSearch database directory:
    ```bash
    sudo chown -R 1000:1000 shuffle-database
    ```
    [cite\_start][cite: 1701]
3.  Set permissions for the other directories:
    ```bash
    chmod -R 755 shuffle-apps shuffle-files
    ```
    [cite\_start][cite: 1702]

### 2.5 Modify `docker-compose.yml` Port Mapping

[cite\_start]To avoid conflicts with the Wazuh Indexer (which also uses port 9200), map Shuffle's OpenSearch to host port `9201`. [cite: 1708]

1.  Use `sed` to modify the port mapping in the compose file:
    ```bash
    cd ~/Shuffle
    sed -i 's/- "9200:9200"/- "9201:9200"/' docker-compose.yml
    ```
    [cite\_start][cite: 1711]

### 2.6 Pull Docker Images

1.  Download all required container images:
    ```bash
    cd ~/Shuffle
    docker compose pull
    ```
    [cite\_start][cite: 1720]

### 2.7 Start Shuffle Services (Staged Start)

Start the services in the correct order to ensure the database is initialized before the backend tries to connect.

1.  Start OpenSearch first:
    ```bash
    cd ~/Shuffle
    docker compose up -d opensearch
    ```
    [cite\_start][cite: 1730]
2.  Wait 90 seconds for OpenSearch to initialize:
    ```bash
    echo "Waiting 90 seconds for OpenSearch to initialize..."
    sleep 90
    ```
    [cite\_start][cite: 1731]
3.  Start the backend and orborus (worker):
    ```bash
    docker compose up -d backend orborus
    ```
    [cite\_start][cite: 1735]
4.  Wait 60 seconds for the backend to initialize:
    ```bash
    echo "Waiting 60 seconds for Backend to initialize..."
    sleep 60
    ```
    [cite\_start][cite: 1736]
5.  Start the frontend:
    ```bash
    docker compose up -d frontend
    ```
    [cite\_start][cite: 1738]

### 2.8 Verify Installation

1.  Check that all containers are running:

    ```bash
    docker compose ps
    ```

    [cite\_start][cite: 1740] (Expected status `Up` for all services) [cite\_start][cite: 1744, 1746, 1748, 1750, 1752]

2.  Verify the OpenSearch cluster health (using the password from `.env`):

    ```bash
    curl -ku admin:StrongShufflePassword321! https://localhost:9201/_cluster/health?pretty
    ```

    [cite\_start][cite: 1754]
    (Expected output should include `"status": "green"`) [cite\_start][cite: 1759]

-----

## 3\. Shuffle Web Interface Setup

### 3.1 Access the Interface and Create Admin Account

1.  Open a web browser and navigate to your server's IP on port 3443:
    [cite\_start]`https://192.168.1.130:3443` [cite: 1766]
2.  You will see an SSL warning. This is expected as Shuffle uses a self-signed certificate. [cite\_start]Accept the risk and proceed. [cite: 1767, 1768]
3.  You will be redirected to `/adminsetup`. [cite\_start]Create your administrator account. [cite: 1770]
      * [cite\_start]**Email:** `brunoflausino@gmx.com` [cite: 1772]
      * [cite\_start]**Username:** `admin` [cite: 1773]
      * [cite\_start]**Password:** `Atx@5-4pT#56` [cite: 1774]

### 3.2 Create Wazuh Webhook Workflow

1.  Log in to Shuffle with your new admin account.
2.  [cite\_start]In the left sidebar, click **"Workflows"** and then **"New Workflow"**. [cite: 1777, 1778]
3.  [cite\_start]Name the workflow `Wazuh-Shuffle`. [cite: 1779]
4.  [cite\_start]From the "Triggers" menu on the left, drag the **"Webhook"** trigger onto the canvas. [cite: 1780, 1781]
5.  Click the Webhook node. [cite\_start]On the right-hand panel, find the **"Webhook URI"** field and click the copy icon. [cite: 1782, 1784]
6.  Save this URL. It will look similar to this:
    [cite\_start]`https://192.168.1.130:3443/api/v1/hooks/webhook_cdf495b6-f6aa-4c44-a7d3-8a97bf2feb56` [cite: 1786]
7.  [cite\_start]Click **"Save"** in the top-right corner. [cite: 1787]

-----

## 4\. Wazuh Integration Configuration

### 4.1 Configure Wazuh Manager `ossec.conf`

1.  Back up your existing Wazuh configuration:

    ```bash
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup-$(date +%Y%m%d-%H%M%S)
    ```

    [cite\_start][cite: 1791]

2.  Edit the Wazuh manager configuration:

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

    [cite\_start][cite: 1797]

3.  Add the following `<integration>` block before the closing `</ossec_config>` tag. **Use the exact Webhook URL you copied from the Shuffle UI.**

    ```xml
    <integration>
      <name>shuffle</name>
      [cite_start]<hook_url>[https://192.168.1.130:3443/api/v1/hooks/webhook_cdf495b6-f6aa-4c44-a7d3-8a97bf2feb56](https://192.168.1.130:3443/api/v1/hooks/webhook_cdf495b6-f6aa-4c44-a7d3-8a97bf2feb56)</hook_url> [cite: 1807, 1808]
      [cite_start]<level>3</level> [cite: 1809]
      [cite_start]<alert_format>json</alert_format> [cite: 1810]
    </integration>
    ```

      * [cite\_start]`<level>3</level>`: Sends all alerts with severity level 3 or higher to Shuffle. [cite: 1815]

### 4.2 Address SSL Certificate Error (Required Step)

[cite\_start]Wazuh's `integratord` will fail to send alerts because it validates SSL certificates, and Shuffle's is self-signed. [cite: 2246, 2247] You must modify the integration script to disable this verification.

1.  Back up the original Python integration script:
    ```bash
    sudo cp /var/ossec/integrations/shuffle.py /var/ossec/integrations/shuffle.py.backup
    ```
    [cite\_start][cite: 2250]
2.  Edit the Python script (`shuffle.py`), **not** the shell wrapper:
    ```bash
    sudo nano /var/ossec/integrations/shuffle.py
    ```
    [cite\_start][cite: 2254, 2257]
3.  [cite\_start]Find the `send_msg` function (around line 237). [cite: 2258]
4.  Locate this line:
    ```python
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    ```
    [cite\_start][cite: 2268]
5.  Modify the line by adding `verify=False`:
    ```python
    res = requests.post(url, data=msg, headers=headers, timeout=10, verify=False)
    ```
    [cite\_start][cite: 2279, 2280]
6.  Save the file and exit the editor.

### 4.3 Restart Wazuh Manager

1.  Restart the `wazuh-manager` to apply all changes (both `ossec.conf` and the script fix):
    ```bash
    sudo systemctl restart wazuh-manager
    ```
    [cite\_start][cite: 1825, 2284]
2.  Verify the manager and `integratord` are running:
    ```bash
    sudo systemctl status wazuh-manager
    ```
    [cite\_start][cite: 1827] (Ensure `wazuh-integratord` is listed as active)[cite\_start]. [cite: 1836]

-----

## 5\. End-to-End Validation and Testing

### 5.1 Monitor Integration Logs

Open a new terminal to monitor the integration logs in real-time. This is how you will confirm success.

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

[cite\_start][cite: 1839, 1901]

### 5.2 Test 1: Manual Webhook Test (`curl`)

Manually send a test JSON to your webhook to confirm Shuffle is receiving data.

```bash
curl -k -X POST "[https://192.168.1.130:3443/api/v1/hooks/webhook_cdf495b6-f6aa-4c44-a7d3-8a97bf2feb56](https://192.168.1.130:3443/api/v1/hooks/webhook_cdf495b6-f6aa-4c44-a7d3-8a97bf2feb56)" \
-H "Content-Type: application/json" \
-d '{
    "source": "manual_test",
    "message": "Testing Shuffle webhook connectivity",
    "severity": 5
}'
```

[cite\_start][cite: 1845-1852]

  * [cite\_start]**Expected Response:** You should see a JSON response with `"success": true`. [cite: 1856]
  * **Shuffle UI:** Check the **"Executions"** page in Shuffle. [cite\_start]You will see this manual test listed. [cite: 1861, 1862]

### 5.3 Test 2: Generate Live Wazuh Alerts

Simulate attacks to generate real alerts from Wazuh.

1.  **SSH Brute Force Simulation:**
    ```bash
    for i in $(seq 1 5); do
      sudo logger -p authpriv.warning "sshd[$$]: Failed password for root from 192.168.1.100 port 22 ssh2"
    done
    ```
    [cite\_start][cite: 1868-1870]
2.  **File Integrity Monitoring (FIM) Alert:**
    ```bash
    sudo mkdir -p /tmp/malware_samples
    sudo touch /tmp/malware_samples/suspicious_file.sh
    echo "malicious content" | sudo tee -a /tmp/malware_samples/suspicious_file.sh
    ```
    [cite\_start][cite: 1878, 1880, 1882]
3.  **EICAR Malware Test:**
    ```bash
    curl -o /tmp/eicar.com '[https://secure.eicar.org/eicar.com](https://secure.eicar.org/eicar.com)'
    ```
    [cite\_start][cite: 1891]

### 5.4 Verify Results

1.  **Check `integrations.log`:**
    In your monitoring terminal, you should see logs confirming successful delivery for each alert:

    ```
    [cite_start]INFO: Sending alert to integration: shuffle [cite: 1903]
    [cite_start]INFO: Alert sent successfully to [https://192.168.1.130:3443/api/v1/hooks/webhook](https://192.168.1.130:3443/api/v1/hooks/webhook)_... [cite: 1904, 1905]
    ```

    The addendum also confirms a successful log message looks like:
    [cite\_start]`Response received: <bound method Response.json of <Response [200]>>` [cite: 2292]

2.  **Check Shuffle UI:**

      * [cite\_start]Navigate to the **"Executions"** page in the Shuffle UI. [cite: 1908]
      * [cite\_start]You will see a new execution for each Wazuh alert that met the level 3+ threshold. [cite: 1909]
      * [cite\_start]Click on any execution to see the full JSON alert data sent from Wazuh. [cite: 1911]

3.  **Check Wazuh Dashboard:**

      * Navigate to your Wazuh Dashboard.
      * [cite\_start]Go to **Security Events** and verify that the simulated alerts (SSH Brute Force, FIM, EICAR) were generated. [cite: 1916, 1918]

<!-- end list -->
