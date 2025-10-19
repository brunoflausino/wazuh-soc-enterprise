# **nwipe and Wazuh SIEM Integration**

## **1. Overview**

This guide provides a complete, step-by-step methodology for installing **nwipe** (a secure disk erasure tool) and integrating its execution logs with a **Wazuh 4.12** SIEM platform on **Ubuntu 24.04**.

The primary objective is to create a complete audit trail for all disk erasure operations. This is achieved by configuring Wazuh to ingest custom JSON logs generated during `nwipe` execution.

This methodology follows a **safety-first principle**. The installation, configuration, and testing steps are separated to prevent any accidental data destruction during setup.

## **2. System Environment**

  * **Operating System:** Ubuntu 24.04 (x86\_64)
  * **SIEM:** Wazuh 4.12 (Manager, Indexer, and Dashboard)
  * **Privileges:** All commands require `sudo`.

-----

## **3. Part 1: Safe Installation of nwipe**

This phase installs the `nwipe` tool. No disks will be accessed or erased.

### **3.1. Attempt 1: Installation via APT (Recommended)**

First, try to install `nwipe` using the Ubuntu package manager.

```bash
# 1. Update APT indexes
sudo apt-get update -y

# 2. Try to install the nwipe package
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nwipe
```

### **3.2. Verify the Installation**

Run the following command to verify if the installation was successful:

```bash
nwipe --version
```

  * If this command shows the `nwipe` version, **Part 1 is complete**. Proceed to **Part 2**.
  * If the command fails (or if the APT installation failed), continue to **Part 3.3**.

### **3.3. Attempt 2: Compilation from Source Code**

If `nwipe` is not available in the repositories, compile it manually.

1.  **Install Build Dependencies:**
    Install the necessary tools to compile `nwipe`.

    ```bash
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential git autoconf automake libtool pkg-config \
        libparted-dev libncurses-dev
    ```

2.  **Clone the Repository:**
    Clone the official `nwipe` source code.

    ```bash
    git clone --depth=1 https://github.com/martijnvanbrummelen/nwipe.git /tmp/nwipe_source
    ```

3.  **Compile and Install:**
    Enter the directory, configure, compile, and install the binary.

    ```bash
    cd /tmp/nwipe_source

    # Generate configuration scripts, if necessary
    if [ -x ./autogen.sh ]; then
      ./autogen.sh
    fi

    # Configure to install in /usr
    ./configure --prefix=/usr

    # Compile using all processor cores
    make -j"$(nproc)"

    # Install the binary to the system
    sudo make install
    ```

4.  **Verify Installation (Again):**
    Confirm that `nwipe` is now installed.

    ```bash
    nwipe --version
    ```

5.  **Cleanup:**
    Remove the source code directory.

    ```bash
    cd ~
    rm -rf /tmp/nwipe_source
    ```

-----

## **4. Part 2: Wazuh Integration Configuration**

This phase configures the Wazuh (agent or manager) to monitor a dedicated JSON log file for `nwipe` events.

### **4.1. Set Permissions and Variables**

1.  First, identify the correct user group for your Wazuh installation (usually `wazuh`):

    ```bash
    # This command saves the group name to the $OSSEC_GRP variable
    OSSEC_GRP=$(stat -c %G /var/ossec)

    # Check if it worked (should print 'wazuh' or similar)
    echo "Wazuh group detected: $OSSEC_GRP"
    ```

2.  Create the log directory for `nwipe` and assign ownership to the Wazuh group:

    ```bash
    sudo install -d -m 0750 -o root -g $OSSEC_GRP /var/log/nwipe
    ```

3.  Create the empty JSON log file and assign the correct permissions:

    ```bash
    sudo install -m 0640 -o root -g $OSSEC_GRP /dev/null /var/log/nwipe/wazuh_events.log
    ```

### **4.2. Configure Logrotate**

Create a log rotation file to prevent this file from growing indefinitely.

1.  Open a new logrotate configuration file:

    ```bash
    sudo nano /etc/logrotate.d/nwipe
    ```

2.  Paste the following content. Make sure to **replace `wazuh`** with your group name (`$OSSEC_GRP`) if it's different.

    ```ini
    /var/log/nwipe/*.log {
        daily
        rotate 14
        missingok
        compress
        delaycompress
        notifempty
        create 0640 root wazuh
    }
    ```

    *(Replace `wazuh` if your group is different.)*

### **4.3. Configure Wazuh (ossec.conf)**

1.  Back up your `ossec.conf` file:

    ```bash
    sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak_$(date +'%Y%m%d_%H%M%S')
    ```

2.  Edit the `ossec.conf` file to add the new log file:

    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```

3.  Add the following `<localfile>` block inside the `<ossec_config>` section, preferably near other `<localfile>` blocks. This block instructs Wazuh to read the file as JSON.

    ```xml
      <localfile>
        <location>/var/log/nwipe/wazuh_events.log</location>
        <log_format>json</log_format>
      </localfile>
    ```

4.  **(Required for Debugging)** Ensure that archiving for all logs (even those that don't trigger a rule) is active. Inside the `<global>` block, verify that `<logall_json>yes</logall_json>` is present.

    ```xml
      <global>
        <logall_json>yes</logall_json>
        ...
      </global>
    ```

### **4.4. Add Custom Rules (local\_rules.xml)**

1.  Edit your local rules file:

    ```bash
    sudo nano /var/ossec/etc/rules/local_rules.xml
    ```

2.  Add the following rule group. If the file is empty, make sure to paste it between `<group name="local,">` and `</group>` tags.

    ```xml
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
    ```

    *Note: These rules use `<decoded_as>json</decoded_as>`, which is the correct syntax for JSON rules.*

### **4.5. Apply Changes**

Restart the Wazuh service to load the new configuration and rules.

```bash
# If on the Wazuh Manager
sudo systemctl restart wazuh-manager

# If on a Wazuh Agent
sudo systemctl restart wazuh-agent
```

-----

## **5. Part 3: Test Event Generation**

This phase validates the log pipeline **without executing nwipe**. We will manually write simulated JSON events to the monitored log file.

Run the following commands in the terminal. They will simulate a start, a success, and an error event.

```bash
# 1. Simulate START event (Level 3)
echo '{"ts":"$(date -u +'%Y-%m-%dT%H:%M:%SZ')","component":"nwipe-wrapper","level":"info","msg":"INICIO","extra":{"device":"/dev/TEST","args":"--method dodshort --verify last","runlog":"/var/log/nwipe/nwipe_TEST.log"}}' | sudo tee -a /var/log/nwipe/wazuh_events.log

# 2. Simulate SUCCESS event (Level 3)
echo '{"ts":"$(date -u +'%Y-%m-%dT%H:%M:%SZ')","component":"nwipe-wrapper","level":"info","msg":"FIM","extra":{"device":"/dev/TEST","rc":0}}' | sudo tee -a /var/log/nwipe/wazuh_events.log

# 3. Simulate ERROR event (Level 10)
echo '{"ts":"$(date -u +'%Y-%m-%dT%H:%M:%SZ')","component":"nwipe-wrapper","level":"error","msg":"FIM","extra":{"device":"/dev/TEST_FAIL","rc":1,"error":"simulado"}}' | sudo tee -a /var/log/nwipe/wazuh_events.log
```

-----

## **6. Part 4: Validation and Verification**

Let's verify that the test events generated the correct alerts in the Wazuh Manager.

### **6.1. Verification (archives.json)**

Thanks to the `<logall_json>yes</logall_json>` configuration, we can see the raw logs arriving at the manager.

```bash
# Monitor the archive logs in real-time
sudo tail -f /var/ossec/logs/archives/archives.json | grep "nwipe-wrapper"
```

  * **Expected Output:** You should see the three JSON events you simulated appear in this file. If they appear, Wazuh is reading the log file correctly.

### **6.2. Verification (alerts.json)**

Now, check if your custom rules (100500, 100501, 100502) fired correctly.

```bash
# Monitor the alert logs in real-time
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep "NWipe:"
```

  * **Expected Output:** You should see three JSON alerts, one for each rule, confirming the correct levels and descriptions were triggered.

### **6.3. Verification (wazuh-logtest)**

For detailed debugging, use the `wazuh-logtest` tool.

1.  Run the tool:

    ```bash
    sudo /var/ossec/bin/wazuh-logtest
    ```

2.  Paste one of your JSON log lines and press Enter:
    `{"ts":"2025-10-18T06:16:02Z","component":"nwipe-wrapper","level":"error","msg":"FIM","extra":{"device":"/dev/TEST_FAIL","rc":1,"error":"simulado"}}`

3.  **Expected Output:** The tool should show you that the `decoder: 'json'` was used and that `rule id: '100502'` (level 10) was triggered.

-----

### Author

**Bruno Rubens Flausino Teixeira**
*Wazuh SOC Enterprise Lab – Threat Intelligence Stack*
