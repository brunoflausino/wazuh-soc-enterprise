# **GRR Integration with Wazuh**

## **1. Overview**

This guide provides a comprehensive, step-by-step methodology for installing **Google Rapid Response (GRR)** using Docker and integrating it with a **Wazuh 4.x** SIEM platform running on **Ubuntu 24.04**.

The integration allows Wazuh alerts (specifically File Integrity Monitoring - FIM/syscheck events in this example) to automatically trigger forensic actions in GRR, such as initiating an "Interrogate" flow on the affected endpoint. This process utilizes Wazuh's `integratord` component and a custom Python script to interact with the GRR API, following established best practices and official documentation.

**Integration Workflow:**

1.  GRR Server is deployed using Docker Compose for ease of management.
2.  A custom Python script (`custom-grr`) is placed on the Wazuh Manager.
3.  Wazuh Manager's `integratord` is configured to execute this script when specific alerts (e.g., FIM alerts level 5+) are generated.
4.  The script receives alert details from Wazuh.
5.  The script authenticates to the GRR API using credentials stored in Wazuh's configuration.
6.  The script searches for the GRR client matching the hostname from the Wazuh alert.
7.  If the client is found, the script triggers a predefined GRR flow (e.g., "Interrogate") on that client via the API.
8.  Execution success or failure is logged by the script to Wazuh's `integrations.log`.

This guide prioritizes clarity and safety, breaking down configurations into manageable steps and explaining the rationale behind critical configurations like API interaction and Wazuh settings.

## **2. System Environment**

  * **Host Operating System:** Ubuntu 24.04 LTS (Machine running Docker and Wazuh Manager)
  * **Wazuh:** Manager, Indexer, Dashboard (v4.x, assumed bare-metal installation)
  * **GRR:** Docker image `grrdocker/grr:v3.4.6.0` (latest stable at time of reports)
  * **Networking:**
      * Host IP for GRR: `192.168.1.130` (Replace with your host's actual IP accessible *from* the Wazuh Manager if they are different machines, although this guide assumes they are the same).
      * GRR UI Port (Host): `127.0.0.1:9008` (Local access only)
      * GRR Client Polling Port (Host): `127.0.0.1:9009` (Local access only)
  * **Privileges:** All commands require `sudo`.

-----

## **3. Part 1: GRR Installation (Docker Compose)**

This section covers deploying the GRR server using the recommended Docker Compose method.

### **3.1 Install Docker and Docker Compose**

Ensure Docker Engine and the Docker Compose plugin are installed on your host machine.

```bash
# Update package list
sudo apt update

# Install Docker prerequisites
sudo apt install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up the Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine, CLI, Containerd, and Compose plugin
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Enable and start Docker service
sudo systemctl enable --now docker

# Add your current user to the docker group (Requires logout/login to take effect)
sudo usermod -aG docker ${USER}
echo "Docker installed. Please log out and log back in for group changes."

# Verify installation (run after logging back in)
docker --version
docker compose version
```

*You must log out and log back in for your user to run `docker` commands without `sudo`.*

### **3.2 Create Docker Compose Configuration**

1.  **Create a Directory:**

    ```bash
    mkdir ~/grr-install
    cd ~/grr-install
    ```

2.  **Create `docker-compose.yml` File:**
    Use `nano` or your preferred editor to create the configuration file.

    ```bash
    nano docker-compose.yml
    ```

3.  **Paste Configuration:**
    Copy and paste the following YAML content into the editor. **Crucially, change `EXTERNAL_HOSTNAME` to your host's IP address** and **replace the default `ADMIN_PASSWORD` (`password`) with a strong, unique password.**

    ```yaml
    services:
      grr:
        image: grrdocker/grr:v3.4.6.0 # Specifies the GRR version
        container_name: grr          # Assigns a fixed name to the container
        restart: always              # Ensures the container restarts automatically
        environment:
          # IMPORTANT: Set this to the IP or DNS name GRR clients will use to reach the server.
          - EXTERNAL_HOSTNAME=192.168.1.130
          # IMPORTANT: Set the initial password for the 'admin' user. CHANGE THIS!
          - ADMIN_PASSWORD=password
        ports:
          # Maps Host Port 9008 (localhost only) -> Container Port 8000 (GRR UI)
          - "127.0.0.1:9008:8000"
          # Maps Host Port 9009 (localhost only) -> Container Port 8080 (GRR Client Polling)
          - "127.0.0.1:9009:8080"
        ulimits: # Recommended resource limits for GRR server stability
          nofile:
            soft: 1048576
            hard: 1048576
        volumes:
          # Creates a persistent named volume 'grr-data' to store GRR's state.
          - grr-data:/usr/share/grr-server/install_data

    volumes:
      grr-data: # Declares the named volume used above.
    ```

      * **Explanation:**
          * `image`: Specifies the official GRR Docker image and version.
          * `environment`: Sets variables inside the container. `EXTERNAL_HOSTNAME` is vital for client communication; `ADMIN_PASSWORD` sets the initial admin credential.
          * `ports`: Maps ports from your host machine to the container. We bind to `127.0.0.1` to restrict access to the local machine only. Container port `8000` is the GRR UI, `8080` is for client connections.
          * `ulimits`: Increases file descriptor limits, often needed by GRR.
          * `volumes`: Ensures GRR data (configs, database, logs) persists across container restarts using a named Docker volume `grr-data`.

4.  **Save and Close:** Press `Ctrl+O`, `Enter`, `Ctrl+X`.

### **3.3 Launch GRR Container**

Use Docker Compose to download the image (if not present) and start the GRR container.

```bash
cd ~/grr-install # Make sure you are in the correct directory

# Download/update the image if necessary
docker compose pull grr

# Start the GRR service in the background (-d)
# --force-recreate ensures changes to the compose file are applied
docker compose up -d --force-recreate

# Check the status - should show 'running'
docker compose ps

# View the initial startup logs (optional, helpful for first run)
echo "Waiting a few moments for GRR to initialize..."
sleep 15
docker logs grr --tail 100
```

### **3.4 Initial GRR Access and Password Change**

1.  **Access Web UI:** Open your web browser and navigate to `http://127.0.0.1:9008/`.
2.  **Login:** Use the username `admin` and the password you set for `ADMIN_PASSWORD` in the `docker-compose.yml` file.
3.  **IMPORTANT: Change Admin Password Immediately:**
      * Click the settings icon (gear) in the top right.
      * Go to "User Settings".
      * Enter a new, strong password and save it.

-----

## **4. Part 2: Wazuh Integration Configuration (Manager)**

Configure the Wazuh Manager to execute the custom Python script when relevant alerts occur.

### **4.1 Create the Integration Script (`custom-grr`)**

This script handles the logic of receiving a Wazuh alert, querying the GRR API, and triggering a GRR flow.

1.  **Create the Script File:**
    Use `nano` to create the script in the correct Wazuh integrations directory. The name **must** start with `custom-`.

    ```bash
    sudo nano /var/ossec/integrations/custom-grr
    ```

2.  **Paste the Script Code:**
    Copy the entire Python script below and paste it into the `nano` editor.

    ```python
    #!/var/ossec/framework/python/bin/python3
    # -*- coding: utf-8 -*-
    # Wazuh -> GRR Integration Script
    # Author: Bruno Flausino Teixeira (Based on community examples)
    # Purpose: Receives a Wazuh alert, finds the corresponding agent in GRR
    #          by hostname, and triggers the 'Interrogate' flow.

    import sys
    import json
    import requests
    import socket
    import logging

    # --- Configuration ---
    LOG_FILE = '/var/ossec/logs/integrations.log'
    LOG_FORMAT = '%(asctime)s %(levelname)s: %(name)s: %(message)s'
    SCRIPT_NAME = 'custom-grr'
    GRR_XSSI_PREFIX = ")]}'"
    GRR_API_TIMEOUT = 15
    GRR_FLOW_TO_RUN = "Interrogate" # The name of the GRR flow to trigger

    # --- Logging Setup ---
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format=LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(SCRIPT_NAME)

    # --- Suppress SSL Warnings (Use Caution) ---
    try:
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        log.debug("SSL warnings suppressed. Set verify=True in production with valid certs.")
    except ImportError:
        log.warning("Could not import InsecureRequestWarning; SSL warnings may appear.")

    # --- Main Function ---
    def main():
        """ Parses args, reads alert, calls GRR API, triggers flow. """
        log.info("Integration script started.")

        # --- 1. Argument Parsing ---
        if len(sys.argv) != 4:
            log.error(f"Incorrect number of arguments. Expected 4, got {len(sys.argv)}.")
            log.error(f"Usage: {sys.argv[0]} <alert_file_path> <api_key> <hook_url>")
            sys.exit(1)

        alert_file_path = sys.argv[1]
        api_key_str = sys.argv[2] # Expected format 'username:password'
        hook_base_url = sys.argv[3] # Base URL (e.g., http://127.0.0.1:9008)
        grr_api_url = f"{hook_base_url.rstrip('/')}/api" # API path

        log.debug(f"Alert file path: {alert_file_path}")
        log.debug(f"GRR API URL: {grr_api_url}")

        # --- 2. Read Wazuh Alert File ---
        try:
            with open(alert_file_path, 'r') as alert_file:
                alert_json = json.load(alert_file)
            log.debug(f"Successfully read alert: {alert_file_path}")
        except Exception as e:
            log.error(f"Error reading/parsing alert file {alert_file_path}: {e}")
            sys.exit(1)

        # --- 3. Extract Hostname and Credentials ---
        agent_info = alert_json.get("agent", {})
        hostname = agent_info.get("name")
        if not hostname:
            log.warning("Agent name not found in alert. Cannot search GRR client.")
            sys.exit(0) # Exit gracefully

        try:
            grr_user, grr_password = api_key_str.split(":", 1)
            log.debug(f"Using GRR user: {grr_user}")
        except ValueError:
            log.error("Invalid api_key format in ossec.conf. Expected 'username:password'.")
            sys.exit(1)

        log.info(f"Processing alert for hostname: {hostname}")

        # --- 4. Interact with GRR API ---
        grr_session = requests.Session()
        grr_session.auth = (grr_user, grr_password)
        grr_session.verify = False # Disable SSL check (adjust for production HTTPS)
        grr_session.timeout = GRR_API_TIMEOUT

        try:
            # --- 4a. Find GRR Client ID ---
            search_url = f"{grr_api_url}/clients"
            search_params = {"query": f"host:{hostname}"} # Use GRR search syntax
            log.debug(f"Searching GRR clients with query: host:{hostname}")

            response_search = grr_session.get(search_url, params=search_params)
            response_search.raise_for_status()

            # Handle GRR XSSI prefix
            response_text = response_search.text
            if response_text.startswith(GRR_XSSI_PREFIX):
                log.debug("Removing GRR XSSI prefix.")
                response_text = response_text[len(GRR_XSSI_PREFIX):].strip()

            try:
                client_data = json.loads(response_text)
            except json.JSONDecodeError as e:
                 log.error(f"Failed to decode JSON from GRR client search: {e}")
                 log.error(f"Response text (first 500 chars): {response_text[:500]}")
                 sys.exit(1)

            items = client_data.get("items", [])
            if not items:
                log.warning(f"No GRR client found for hostname: {hostname}. Cannot trigger flow.")
                sys.exit(0) # Not an error if client isn't enrolled

            client_info = items[0] # Assume first match is correct
            client_id = client_info.get("client_id") or client_info.get("clientId") # Check both key styles

            if not client_id:
                log.error(f"Could not extract client ID for {hostname}. Response: {client_info}")
                sys.exit(1)

            log.info(f"Found GRR client ID '{client_id}' for hostname '{hostname}'.")

            # --- 4b. Trigger GRR Flow ---
            start_flow_url = f"{grr_api_url}/clients/{client_id}/flows"
            flow_payload = {"flow": {"name": GRR_FLOW_TO_RUN}} # Payload to start the flow by name

            log.debug(f"Requesting GRR flow '{GRR_FLOW_TO_RUN}' for client: {client_id}")

            response_flow = grr_session.post(start_flow_url, json=flow_payload)
            response_flow.raise_for_status()

            # Log success (GRR flow start often returns 200 OK)
            log.info(f"Successfully requested GRR flow '{GRR_FLOW_TO_RUN}' for client {client_id}. Status: {response_flow.status_code}")
            sys.exit(0) # Signal success to Wazuh

        # --- Error Handling ---
        except requests.exceptions.HTTPError as e:
            log.error(f"HTTP Error: {e.response.status_code} - {e.response.text[:500]}")
            sys.exit(1)
        except requests.exceptions.ConnectionError as e:
            log.error(f"Connection Error: Cannot connect to GRR API at {grr_api_url}: {e}")
            sys.exit(1)
        except requests.exceptions.Timeout:
            log.error(f"Timeout: Request to GRR API timed out after {GRR_API_TIMEOUT} seconds.")
            sys.exit(1)
        except Exception as e:
            log.exception(f"Unexpected error during GRR API interaction: {e}") # Includes traceback
            sys.exit(1)

    # --- Script Entry Point ---
    if __name__ == "__main__":
        try:
            main()
        except Exception as e:
            log.exception(f"Unhandled exception during script execution: {e}")
            sys.exit(1)
    ```

3.  **Save and Close:** `Ctrl+O`, `Enter`, `Ctrl+X`.

4.  **Set Permissions and Ownership:** This is required by Wazuh `integratord`.

    ```bash
    # Set permissions: Owner=read/write/execute, Group=read/execute, Others=none
    sudo chmod 750 /var/ossec/integrations/custom-grr

    # Set owner: root user, wazuh group
    sudo chown root:wazuh /var/ossec/integrations/custom-grr

    # Verify permissions
    ls -l /var/ossec/integrations/custom-grr
    # Expected output: -rwxr-x--- 1 root wazuh ... custom-grr
    ```

5.  **Install Python `requests` (if needed):**

    ```bash
    # Use Wazuh's embedded Python to install the library
    sudo /var/ossec/framework/python/bin/pip3 install requests
    ```

### **4.2 Configure `ossec.conf` on Wazuh Manager**

1.  **Backup `ossec.conf`:**

    ```bash
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak_grr_$(date +%Y%m%d_%H%M%S)
    echo "Backed up current ossec.conf"
    ```

2.  **Edit `ossec.conf`:**

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

3.  **Add `<integration>` Block:**
    Paste this block inside `<ossec_config>`. **Replace `admin:YourStrongGRRPassword`** with the GRR admin user and the password you set. Adjust `<level>` and `<group>` to match the alerts you want to forward.

    ```xml
      <integration>
        <name>custom-grr</name>

        <hook_url>http://127.0.0.1:9008</hook_url>

        <api_key>admin:YourStrongGRRPassword</api_key>

        <alert_format>json</alert_format>

        <group>syscheck</group>

        <level>5</level>
      </integration>
    ```

      * **`<name>`:** Identifies the script file (`custom-grr`).
      * **`<hook_url>`:** The base URL of the GRR server, passed as `sys.argv[3]`. The script appends `/api`.
      * **`<api_key>`:** GRR credentials (`username:password`), passed as `sys.argv[2]`.
      * **`<alert_format>`:** Must be `json` so the script receives structured data.
      * **`<group>` / `<level>`:** Filters which alerts trigger the script. Remove these tags to send *all* alerts.

4.  **(Optional) Enable Integrator Debugging:**
    If not already enabled, add `integrator.debug=2` to `/var/ossec/etc/local_internal_options.conf`.

    ```bash
    echo "integrator.debug=2" | sudo tee -a /var/ossec/etc/local_internal_options.conf > /dev/null
    ```

### **4.3 Apply Wazuh Configuration**

Restart the Wazuh Manager to load the changes.

```bash
# Check XML syntax (optional)
# sudo /var/ossec/bin/wazuh-analysisd -t -c /var/ossec/etc/ossec.conf

echo "Restarting Wazuh Manager..."
sudo systemctl restart wazuh-manager

# Check status after restart
sudo systemctl status --no-pager wazuh-manager
```

-----

## **5. Part 3: (Optional) Alert Threshold Tuning**

If your target alerts (like default FIM rule 550) have a level lower than the `<level>` threshold set in `ossec.conf` (e.g., level 5), they won't trigger the integration. You can temporarily raise the alert level for testing using `local_rules.xml`.

1.  **Edit `local_rules.xml`:**

    ```bash
    sudo nano /var/ossec/etc/rules/local_rules.xml
    ```

2.  **Add Escalation Rule:** Add this group to temporarily raise the level of all `syscheck` alerts to 8 (adjust level as needed).

    ```xml
    <group name="local,syscheck,testing,">
      <rule id="100550" level="8">
        <if_group>syscheck</if_group>
        <description>TEST: Escalated syscheck alert for GRR integration validation.</description>
        </rule>
    </group>
    ```

3.  **Restart Wazuh Manager:**

    ```bash
    sudo systemctl restart wazuh-manager
    ```

      * **Remember to remove or disable this rule after testing\!**

-----

## **6. Part 4: End-to-End Validation**

Test the complete flow.

### **6.1 Monitor Logs**

Keep these commands running in separate terminals on the Wazuh Manager:

  * **Terminal 1 (Wazuh Integration Log):**
    ```bash
    sudo tail -f /var/ossec/logs/integrations.log
    ```
  * **Terminal 2 (Wazuh Manager Log):**
    ```bash
    sudo tail -f /var/ossec/logs/ossec.log | grep -Ei 'integrator|error|warn|grr'
    ```
  * **Terminal 3 (GRR Docker Log):**
    ```bash
    cd ~/grr-install # Go to compose file directory
    docker compose logs -f grr | grep -Ei 'POST /api/clients/.*/flows|GET /api/clients|error'
    ```

### **6.2 Generate a Matching Wazuh Alert (FIM Example)**

Trigger an alert that matches your `<integration>` filters (`syscheck` group, level 5+, or level 8+ if using the escalation rule).

1.  **Modify a Monitored File** (e.g., `/etc/hosts`):
    ```bash
    sudo bash -c 'echo "# GRR Integration Test - $(date -Is)" >> /etc/hosts'
    ```
2.  **(Optional) Force FIM Scan** on the manager (agent ID `000`):
    ```bash
    sudo /var/ossec/bin/agent_control -R -u 000
    ```

### **6.3 Verify Results**

1.  **Wazuh Logs:**
      * `integrations.log`: Should show script start, client search, client found, flow trigger request, and success message (e.g., "Successfully requested GRR flow 'Interrogate'..."). Check for errors.
      * `ossec.log`: Should show `wazuh-integratord` executing `custom-grr` script for the generated alert.
2.  **GRR Docker Logs:** Should show incoming API requests: `GET /api/clients?query=host:...` followed by `POST /api/clients/<client_id>/flows` with status `200 OK`.
3.  **GRR Web UI (`http://127.0.0.1:9008/`):**
      * Search for the client (hostname matching your Wazuh manager).
      * Navigate to the client's **Flows** tab.
      * You should see a new **"Interrogate"** flow listed as "RUNNING" or "FINISHED".

Successful execution of the "Interrogate" flow in GRR confirms the end-to-end integration is working.

-----

## **7. Part 5: Troubleshooting**

  * **Script Not Executing:** Check `ossec.log` for errors (permissions, name mismatch). Verify alert group/level matches `<integration>` filters in `ossec.conf`. Check script path and permissions (`750`, `root:wazuh`).
  * **HTTP 401 Unauthorized:** Incorrect `api_key` format or value in `ossec.conf`. Must be `username:password`. Verify credentials match GRR.
  * **HTTP 403 Forbidden:** The GRR user in `api_key` lacks permissions. Use `admin` initially or ensure the user has API access roles in GRR.
  * **HTTP 404 Not Found:** Incorrect `hook_url` in `ossec.conf`. Should be the *base* URL (e.g., `http://127.0.0.1:9008`), script appends `/api`.
  * **Connection Error/Timeout:** GRR container is down (`docker compose ps`), port `9008` not mapped correctly or blocked. Test with `curl -I http://127.0.0.1:9008`.
  * **GRR Client Not Found:** Script logs "No GRR client found". Check hostname in Wazuh alert matches hostname known to GRR *exactly*. Ensure a GRR client/agent is actually installed and enrolled for that host.
  * **JSON Errors / XSSI:** Script logs "Failed to decode JSON...". Check XSSI prefix removal logic. GRR API might have changed. Examine raw `response_text` in logs.

-----

## **8. Part 6: Security Hardening**

  * **Change GRR Admin Password:** If you used the default, change it immediately in the GRR UI.
  * **Use HTTPS:** Deploy a reverse proxy (like Nginx or Traefik) in front of GRR to handle TLS encryption. Update `hook_url` to `https://...` and set `verify=True` in the script (or provide a CA path).
  * **Restrict Network Access:** Bind GRR ports (`9008`, `9009`) to specific IPs or use firewall rules (including Docker's `DOCKER-USER` chain if using UFW) to limit access to the GRR UI/API.
  * **Secure API Credentials:** Avoid storing plain text credentials in `ossec.conf`. Use environment variables sourced by the Wazuh Manager process or explore Wazuh's secure options if available in your version.
  * **Disable Debugging:** Once validated, remove `integrator.debug=2` from `local_internal_options.conf` and set script logging level back to `INFO`. Remove temporary rule escalations.

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab – Threat Intelligence Stack*
