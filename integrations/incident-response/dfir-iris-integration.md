# **DFIR-IRIS Integration with Wazuh**

## **1. Overview**

This guide provides a comprehensive methodology for installing **DFIR-IRIS** (Incident Response Platform) using Docker and integrating it with **Wazuh 4.13.1** on **Ubuntu 24.04**.

The integration allows Wazuh alerts to be automatically forwarded to DFIR-IRIS, creating new alerts within the IRIS platform for centralized incident management. This process uses Wazuh's `integratord` component and a custom Python script, following official guidelines.

**Key Integration Points:**

  * DFIR-IRIS is installed using the recommended **Docker Compose** method.
  * Wazuh's `integratord` forwards alerts (level 7+ by default) via a custom Python script.
  * The script (`custom-wazuh_iris.py`) sends alert data to the IRIS API endpoint (`/alerts/add`).
  * **Crucial:** Correct configuration of IRIS **Customers**, **User Permissions**, and **API Keys** is mandatory for the integration to function, especially since IRIS version 2.4.6.

## **2. System Environment**

  * **Operating System:** Ubuntu 24.04 LTS
  * **SIEM:** Wazuh 4.13.1 (Manager, Indexer, Dashboard assumed already installed)
  * **IRIS Version:** DFIR-IRIS v2.4.20+ (using Docker)
  * **Networking:** All services assumed running on `localhost` (`127.0.0.1`).
  * **Ports:**
      * Wazuh Dashboard: 443 (default)
      * DFIR-IRIS Web/API: **9094** (chosen to avoid conflict)
      * IRIS Internal (Docker): PostgreSQL on 5432, RabbitMQ on 5672.
  * **Privileges:** All commands require `sudo`.

-----

## **3. Part 1: DFIR-IRIS Installation (Docker Compose)**

This section covers the recommended installation method using Docker Compose.

### **3.1 Install Docker and Docker Compose**

If not already installed:

```bash
# Install Docker Engine
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
# Add your user to the docker group (logout/login required)
sudo usermod -aG docker $USER 
echo "Docker installed. Please log out and log back in for group changes to take effect."
# Verify (after logout/login)
docker --version
docker-compose --version 
```

*(You might need to log out and log back in for the `docker` group changes to apply)*

### **3.2 Clone DFIR-IRIS Repository**

Clone the official repository and check out a stable version tag (e.g., `v2.4.20`). **Do not use the `master` branch for production.**

```bash
cd ~ 
git clone https://github.com/dfir-iris/iris-web.git
cd iris-web

# List available tags (optional)
# git tag --sort=-v:refname

# Checkout a specific stable tag (replace with the latest stable if needed)
git checkout v2.4.20 
echo "Checked out DFIR-IRIS tag v2.4.20"
```

### **3.3 Configure Environment (.env file)**

1.  **Copy the Model:** Create your `.env` file from the provided template.
    ```bash
    cp .env.model .env
    ```
2.  **Generate Strong Secrets:** Use `openssl` or another tool to generate secure random passwords/keys.
    ```bash
    # Example command to generate a 32-byte base64 string
    openssl rand -base64 32 
    ```
3.  **Edit `.env`:** Open the file (`nano .env`) and **replace** the default placeholder values with your generated secrets. **Key variables to set:**
      * `POSTGRES_PASSWORD`: Password for the `iris` database user.
      * `RABBITMQ_DEFAULT_PASS`: Password for the `iris` RabbitMQ user.
      * `IRIS_ADM_PASSWORD`: **Set a strong password here** for the initial `administrator` web UI user. If left blank, a random one will be generated and shown in the logs on first run.
      * *(Optional but recommended)* `SECRET_KEY`, `SECURITY_PASSWORD_SALT`: Generate and set these application secrets.
      * Ensure database/RabbitMQ hostnames are correct (defaults like `db` and `rabbitmq` usually work within Docker Compose network). Set `POSTGRES_SERVER=db` and `RABBITMQ_HOST=rabbitmq` if needed (these are often the service names in `docker-compose.yml`).

### **3.4 Configure Port Mapping (Avoid Conflicts)**

By default, the IRIS Nginx container listens on port 443. To avoid conflict with the Wazuh Dashboard, create an override file to map IRIS to port **9094** on the host (`localhost`).

```bash
# Create/edit docker-compose.override.yml in the iris-web directory
cat > docker-compose.override.yml <<'YAML'
services:
  nginx:
    ports:
      # Map host port 9094 (localhost only) to container port 443 (HTTPS)
      - "127.0.0.1:9094:443"   
YAML

echo "Docker Compose override created to map IRIS to port 9094."
```

### **3.5 Launch DFIR-IRIS**

Pull the required Docker images and start the services in detached mode.

```bash
# Pull images specified in docker-compose.yml
docker compose pull

# Start all services in the background
docker compose up -d

# Check if all containers are running and healthy
docker compose ps
```

  * Wait a minute or two for services to initialize.
  * **If you didn't set `IRIS_ADM_PASSWORD`:** Retrieve the auto-generated admin password:
    ```bash
    docker compose logs app | grep -A1 'create_safe_admin'
    ```

### **3.6 Initial Access and Verification**

  * Access the DFIR-IRIS web UI at: `https://127.0.0.1:9094/` (accept the self-signed certificate warning in your browser).
  * Log in using the username `administrator` and the password you set in `.env` (or the one retrieved from logs).
  * Navigate the interface briefly to confirm basic functionality.

-----

## **4. Part 2: Preparing DFIR-IRIS for Integration**

This step is **critical** for the Wazuh integration to work correctly, especially with IRIS versions 2.4.6 and later.

### **4.1 Create a Dedicated Service Account**

It's best practice to use a dedicated "service account" for API integrations.

1.  Log in to IRIS as `administrator`.
2.  Navigate to **Advanced** → **Access Control** → **Users**.
3.  Click **Add user**.
4.  Fill in the details:
      * **Full Name:** `Wazuh Integration Service` (or similar)
      * **Login:** `wazuh-service` (choose a unique login ID)
      * **Email:** `wazuh-service@<yourdomain.com>` (can be a functional email)
      * **Password:** Leave blank or set a random one (it won't be used for API key auth).
      * **Check the box:** `Is service account`.
5.  Click **Save**.

### **4.2 Assign Permissions via a Group**

Service accounts (like regular users) get permissions through groups.

1.  Still in **Access Control**, go to the **Groups** tab (or stay on Users and find Groups there).
2.  Click **Add group**.
3.  Create a group named `SIEM Integration` (or similar).
4.  Click the new group to edit it.
5.  Go to the **Permissions** tab. Select the **minimum required permissions** for Wazuh to create alerts:
      * `alerts_read`
      * `alerts_write`
      * *(Optional but recommended for basic functionality)* `standard_user`
6.  Go to the **Members** tab. Click **Manage** and add the `wazuh-service` account created earlier.
7.  Click **Save**.

### **4.3 Associate Service Account with a Customer (Mandatory)**

Since IRIS v2.4.6+, users (including service accounts) **must** be associated with at least one **Customer** to interact with data like alerts.

1.  Go back to **Advanced** → **Access Control** → **Users**.
2.  Click on the `wazuh-service` account.
3.  Go to the **Customers** tab.
4.  Click **Manage**.
5.  Select the appropriate customer. For a default installation, this is usually **`IrisInitialClient`** (which typically has `customer_id: 1`). If you created other customers, choose the one intended for Wazuh alerts.
6.  Click **Save**. The customer should now appear listed under the Customers tab for this user.

### **4.4 Obtain the API Key**

1.  While viewing the `wazuh-service` user details (or by clicking your username → My Settings if logged in as that user, though service accounts can't log in via UI), find the **API Key** section.
2.  **Copy the generated API Key**. This key is required for the Wazuh integration configuration. Store it securely.

-----

## **5. Part 3: Wazuh Integration Configuration**

Configure the Wazuh Manager to use the custom Python script to forward alerts.

### **5.1 Create the Integration Script**

1.  Create the script file on the **Wazuh Manager** server. The name **must** start with `custom-`.

    ```bash
    sudo nano /var/ossec/integrations/custom-wazuh_iris.py
    ```

2.  Paste the following Python script content. **Review the comments** regarding `verify=False` if using self-signed certificates.

    ````python
    #!/var/ossec/framework/python/bin/python3
    # -*- coding: utf-8 -*-
    # Wazuh Integrator script to forward alerts to DFIR-IRIS API

    import sys
    import json
    import requests
    import logging
    from datetime import datetime
    # Suppress InsecureRequestWarning for self-signed certs (use cautiously!)
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Configure logging for the integration script itself
    logging.basicConfig(filename='/var/ossec/logs/integrations.log',
                        level=logging.INFO, format='%(asctime)s %(levelname)s: %(name)s: %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger('custom-wazuh_iris.py')

    # Mapping from Wazuh Level (0-15) to IRIS Severity ID (1-6)
    # Adjust mapping based on your severity requirements
    def map_level_to_iris_severity(wazuh_level: int) -> int:
        if not isinstance(wazuh_level, int): return 1 # Default to Informational
        if wazuh_level < 5: return 2   # Low
        if 5 <= wazuh_level < 7: return 3   # Medium
        if 7 <= wazuh_level < 10: return 4  # Medium-High
        if 10 <= wazuh_level < 13: return 5 # High
        if wazuh_level >= 13: return 6 # Critical
        return 1 # Informational (default/fallback)

    # Function to create a detailed description for the IRIS alert
    def format_iris_description(alert_data: dict) -> str:
        rule = alert_data.get("rule", {})
        agent = alert_data.get("agent", {})
        mitre = rule.get("mitre", {})
        
        # Handle MITRE fields which can be strings or lists
        mitre_ids = mitre.get("id", "N/A")
        if isinstance(mitre_ids, list): mitre_ids = ', '.join(mitre_ids)
        
        mitre_tactics = mitre.get("tactic", "N/A")
        if isinstance(mitre_tactics, list): mitre_tactics = ', '.join(mitre_tactics)
        
        mitre_techniques = mitre.get("technique", "N/A")
        if isinstance(mitre_techniques, list): mitre_techniques = ', '.join(mitre_techniques)

        description_lines = [
            f"**Wazuh Alert Details**",
            f"- Rule ID: {rule.get('id', 'N/A')}",
            f"- Rule Level: {rule.get('level', 'N/A')}",
            f"- Rule Description: {rule.get('description', 'N/A')}",
            f"- Agent ID: {agent.get('id', 'N/A')}",
            f"- Agent Name: {agent.get('name', 'N/A')}",
            f"- Agent IP: {agent.get('ip', 'N/A')}",
            f"- MITRE IDs: {mitre_ids}",
            f"- MITRE Tactics: {mitre_tactics}",
            f"- MITRE Techniques: {mitre_techniques}",
            f"- Location: {alert_data.get('location', 'N/A')}",
            f"\n**Full Log:**\n```\n{alert_data.get('full_log', 'N/A')}\n```"
        ]
        return "\n".join(description_lines)

    def main():
        log.info("Starting DFIR-IRIS integration script.")
        
        # --- Argument Handling ---
        # Wazuh integratord passes: <script_path> <alert_file_path> <api_key> <hook_url>
        if len(sys.argv) != 4:
            log.error(f"Incorrect arguments. Usage: {sys.argv[0]} <alert_file> <api_key> <hook_url>")
            sys.exit(1)
            
        alert_file_path = sys.argv[1]
        api_key = sys.argv[2]
        hook_url = sys.argv[3]
        
        log.debug(f"Received alert file: {alert_file_path}")
        log.debug(f"Received hook URL: {hook_url}")
        # Avoid logging the API key directly for security
        
        # --- Read Alert Data ---
        try:
            with open(alert_file_path, 'r') as alert_file:
                alert_json = json.load(alert_file)
            log.debug("Successfully read and parsed alert JSON.")
        except json.JSONDecodeError as e:
            log.error(f"Error decoding JSON from alert file {alert_file_path}: {e}")
            sys.exit(1)
        except Exception as e:
            log.error(f"Error reading alert file {alert_file_path}: {e}")
            sys.exit(1)

        # --- Prepare IRIS Payload ---
        wazuh_level = alert_json.get("rule", {}).get("level", 0)
        iris_severity_id = map_level_to_iris_severity(wazuh_level)
        
        # Construct the payload for the IRIS API
        iris_payload = {
            "alert_title": alert_json.get("rule", {}).get("description", "Wazuh Alert - No Description"),
            "alert_description": format_iris_description(alert_json),
            "alert_source": "Wazuh",
            "alert_source_ref": alert_json.get("id", "N/A"), # Use Wazuh alert ID as reference
            "alert_source_link": "https://<your_wazuh_dashboard_ip_or_domain>:443", # Change to your dashboard URL
            "alert_severity_id": iris_severity_id,
            "alert_status_id": 2,  # Default status '2' (New) in IRIS
            "alert_customer_id": 1, # ** IMPORTANT: Set this to the correct Customer ID (default is 1 for IrisInitialClient) **
            "alert_source_event_time": alert_json.get("timestamp", datetime.utcnow().isoformat(timespec='seconds') + 'Z'), # Use Wazuh timestamp
            "alert_tags": f"wazuh,agent:{alert_json.get('agent', {}).get('name', 'N/A')},rule:{alert_json.get('rule', {}).get('id', 'N/A')}",
            "alert_source_content": alert_json # Include the full Wazuh alert JSON
        }
        log.debug(f"Prepared IRIS payload (excluding full alert content): { {k:v for k,v in iris_payload.items() if k != 'alert_source_content'} }")

        # --- Send Request to IRIS API ---
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        try:
            # Set verify=False ONLY if using self-signed certs and you accept the risk.
            # For production, configure certificate validation properly.
            response = requests.post(hook_url, headers=headers, json=iris_payload, verify=False, timeout=15)
            
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            log.info(f"Successfully sent alert to DFIR-IRIS. Status code: {response.status_code}")
            sys.exit(0) # Success exit code for Wazuh integratord

        except requests.exceptions.HTTPError as e:
            log.error(f"HTTP Error sending alert to IRIS: {e.response.status_code} - {e.response.text[:500]}")
            sys.exit(1)
        except requests.exceptions.ConnectionError as e:
            log.error(f"Connection Error sending alert to IRIS: {e}")
            sys.exit(1)
        except requests.exceptions.Timeout as e:
            log.error(f"Timeout sending alert to IRIS: {e}")
            sys.exit(1)
        except Exception as e:
            log.error(f"An unexpected error occurred: {e}")
            sys.exit(1)

    if __name__ == "__main__":
        main()
    ````

3.  **Set Permissions and Ownership:** This is crucial for `integratord` to execute the script.

    ```bash
    # Set permissions: owner(rwx), group(r-x), others(---)
    sudo chmod 750 /var/ossec/integrations/custom-wazuh_iris.py

    # Set ownership: root user, wazuh group
    sudo chown root:wazuh /var/ossec/integrations/custom-wazuh_iris.py

    # Verify
    ls -l /var/ossec/integrations/custom-wazuh_iris.py 
    # Expected output: -rwxr-x--- 1 root wazuh ... custom-wazuh_iris.py
    ```

### **5.2 Configure `ossec.conf` on Wazuh Manager**

1.  **Edit `ossec.conf`:**

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

2.  **Add the `<integration>` Block:**
    Paste the following block inside the `<ossec_config>` section. **Replace `<IRIS_API_KEY>`** with the key you obtained from the IRIS UI for the `wazuh-service` account.

    ```xml
      <integration>
        <name>custom-wazuh_iris.py</name>
        
        <hook_url>https://127.0.0.1:9094/alerts/add</hook_url> 
        
        <level>7</level> 
        
        <api_key>YOUR_COPIED_IRIS_API_KEY</api_key> 
        
        <alert_format>json</alert_format> 
      </integration>
    ```

### **5.3 Restart Wazuh Manager**

Apply the configuration changes.

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status --no-pager wazuh-manager
```

-----

## **6. Part 4: End-to-End Validation**

Test the complete flow from Wazuh alert generation to IRIS alert creation.

### **6.1 Monitor Logs**

Open multiple terminals on the Wazuh Manager to monitor relevant logs:

  * **Terminal 1: Wazuh Integration Log:** Shows script execution and success/failure messages.
    ```bash
    sudo tail -f /var/ossec/logs/integrations.log
    ```
  * **Terminal 2: Wazuh Manager Log:** Shows `integratord` activity, errors, warnings.
    ```bash
    sudo tail -f /var/ossec/logs/ossec.log | grep -Ei 'integrator|error|warn|iris'
    ```
  * **Terminal 3: IRIS Application Log (Docker):** Shows API requests received by IRIS.
    ```bash
    docker compose logs -f app | grep -Ei 'POST /alerts/add|error'
    ```

### **6.2 Generate a High-Level Wazuh Alert**

Trigger a Wazuh rule with a level ≥ 7 (or whatever you set in `ossec.conf`).

  * **Method 1: Failed SSH Login (Common)**
    On any machine (or the manager itself if SSH is enabled), attempt an invalid SSH login:

    ```bash
    ssh somefakeuser@localhost 
    # Or use the manager's actual IP if testing remotely
    ```

    This usually triggers rules like 5710 or 5712 (level 5-10). Ensure your `<level>` setting catches this.

  * **Method 2: Failed Sudo Attempt**

    ```bash
    sudo -k # Clear cached sudo credentials
    sudo -l # This might prompt for password - enter wrong one
    ```

    This often triggers PAM failure rules (e.g., 5503, level 5+).

  * **Method 3: Custom Test Rule (Reliable)**

    1.  Add a high-level test rule to `/var/ossec/etc/rules/local_rules.xml`:
        ```xml
        <group name="local,test,">
          <rule id="100100" level="10">
            <if_sid>1</if_sid> <match>IRIS Integration Test Event</match>
            <description>Manual Test for DFIR-IRIS Integration</description>
          </rule>
        </group>
        ```
    2.  Restart Wazuh Manager: `sudo systemctl restart wazuh-manager`
    3.  Trigger the rule using `wazuh-logtest` socket or by writing to a monitored log file:
        ```bash
        # Example using logger (sends to syslog, which Wazuh monitors)
        logger "IRIS Integration Test Event" 
        ```

### **6.3 Verify Results**

1.  **Wazuh Logs (Terminals 1 & 2):**
      * `integrations.log` should show messages like `INFO: custom-wazuh_iris.py: Successfully sent alert to DFIR-IRIS. Status code: 201`.
      * `ossec.log` should show `integratord` executing the `custom-wazuh_iris.py` script. Check for any errors.
2.  **IRIS Logs (Terminal 3):**
      * You should see a `POST /alerts/add` request with a `200` or `201` status code.
3.  **DFIR-IRIS Web UI:**
      * Log in to `https://127.0.0.1:9094/`.
      * Navigate to the **Alerts** section.
      * The new alert triggered by Wazuh should appear in the list. Verify the title, description, severity, and tags match the data sent by the script.

-----

## **7. Part 5: Troubleshooting Common Issues**

  * **Error: `integratord` doesn't run the script / No logs in `integrations.log`**

      * **Check `ossec.conf`:** Ensure `<name>` matches `custom-wazuh_iris.py` exactly. Verify `<alert_format>json</alert_format>` is present. Ensure the alert level generated meets the `<level>` threshold.
      * **Check Script Permissions:** Run `ls -l /var/ossec/integrations/custom-wazuh_iris.py`. Must be `750` and `root:wazuh`.
      * **Check `ossec.log`:** Look for errors like "Invalid integration name" or permission errors.
      * **Test Syntax:** Run `sudo /var/ossec/bin/wazuh-integratord -t` to validate the `<integration>` block syntax.

  * **Error: Script runs but logs HTTP 401 Unauthorized in `integrations.log`**

      * **Cause:** Invalid or revoked IRIS API Key.
      * **Solution:** Verify the `<api_key>` in `ossec.conf` matches the one generated in the IRIS UI for the `wazuh-service` account. Regenerate the key in IRIS if needed and update `ossec.conf`.

  * **Error: Script runs but logs HTTP 403 Forbidden in `integrations.log`**

      * **Cause 1 (Most Common):** The `wazuh-service` account in IRIS is **not associated with the correct Customer**.
      * **Solution 1:** Log in to IRIS as admin, go to Advanced → Access Control → Users → `wazuh-service` → Customers tab → Manage → Add `IrisInitialClient` (or the correct customer ID specified in the script's payload, usually `1`) → Save.
      * **Cause 2:** The `wazuh-service` account's group lacks `alerts_read` or `alerts_write` permissions.
      * **Solution 2:** Verify the group permissions assigned in IRIS (Part 4, Step 4.2).

  * **Error: Script runs but logs HTTP 404 Not Found**

      * **Cause:** Incorrect `<hook_url>` in `ossec.conf`. The API endpoint is `/alerts/add`, not `/api/...` or `/webhooks/...`.
      * **Solution:** Ensure `hook_url` is `https://127.0.0.1:9094/alerts/add`.

  * **Error: Connection Refused / Timeout in `integrations.log`**

      * **Cause:** IRIS Docker containers might be down, or network issues prevent connection to `127.0.0.1:9094`.
      * **Solution:** Check `docker compose ps` in the `iris-web` directory. Ensure `nginx` container is running. Check firewall rules if applicable. Test connectivity with `curl -k https://127.0.0.1:9094/api/ping`.

  * **Alert Sent Successfully (201) but Not Visible in IRIS UI**

      * **Cause:** The `alert_customer_id` in the Python script's payload (default is `1`) does **not** match the Customer(s) associated with the user you are *logged into IRIS with*. You only see alerts belonging to customers you are linked to.
      * **Solution:** Ensure the user you are using to view alerts in the IRIS UI is associated with `IrisInitialClient` (ID 1) or whichever customer ID is set in the script.

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab – Threat Intelligence Stack*
