# WireGuard Integration with Wazuh Monitoring

[cite_start]This document provides a complete, production-grade methodology for deploying a WireGuard VPN [cite: 7] [cite_start]and integrating its operations with the Wazuh SIEM platform for auditable monitoring[cite: 7, 1069].

[cite_start]The solution provides real-time visibility into VPN connections [cite: 214, 1070][cite_start], automated alerting [cite: 214, 1070][cite_start], anomaly detection [cite: 214][cite_start], and supports compliance-driven auditing[cite: 1070, 1077]. [cite_start]WireGuard is a modern, minimal, and high-performance VPN [cite: 12, 224] [cite_start]using state-of-the-art cryptography[cite: 12, 227]. [cite_start]Wazuh is an open-source platform for SIEM (Security Information and Event Management) and XDR (Extended Detection and Response)[cite: 230, 237, 238].

[cite_start]The objective is to centralize WireGuard logs, metrics, and events into Wazuh [cite: 243] [cite_start]for correlation, detection, and response[cite: 245, 248].

## Architecture Overview

* [cite_start]**WireGuard Server:** An Ubuntu Linux server acts as a VPN gateway for remote clients[cite: 16].
* [cite_start]**VPN Subnet:** Clients receive dedicated IP addresses from the `10.8.0.0/24` subnet[cite: 17, 320].
* [cite_start]**NAT Routing:** The server performs NAT (MASQUERADE) to allow clients full internet access through the server's public interface[cite: 18, 324, 1107].
* [cite_start]**Wazuh Agent:** The agent is installed on the WireGuard server[cite: 19, 103]. [cite_start]It collects system logs (syslog) [cite: 106, 403][cite_start], service logs (journalctl) [cite: 116, 410][cite_start], configuration file integrity events (syscheck) [cite: 120, 421][cite_start], and custom peer metrics via a script[cite: 123, 416].
* [cite_start]**Wazuh Manager:** The manager receives encrypted data from the agent [cite: 265, 275][cite_start], processes it through custom decoders and rules [cite: 276][cite_start], and generates alerts for security events[cite: 277].

---

## Part 1: WireGuard Server Configuration

This section covers the installation and configuration of the main WireGuard server.

### 1.1 Installation (Ubuntu/Debian)

1.  Update package lists:
    ```bash
    [cite_start]sudo apt update [cite: 289, 1083]
    ```
2.  Install WireGuard and its tools:
    ```bash
    [cite_start]sudo apt install wireguard wireguard-tools [cite: 291, 1084]
    ```
3.  Verify the installation:
    ```bash
    [cite_start]wg --version [cite: 293, 1086]
    ```

### 1.2 Server Key Generation

[cite_start]Keys must be generated on the host that will own them[cite: 21]. [cite_start]Only public keys are shared[cite: 21].

1.  Create the configuration directory:
    ```bash
    [cite_start]sudo mkdir -p /etc/wireguard [cite: 299, 1091]
    [cite_start]cd /etc/wireguard [cite: 300, 1091]
    ```
2.  Generate the server's private key:
    ```bash
    [cite_start]wg genkey | sudo tee server_private.key [cite: 24, 302, 1096]
    ```
3.  Generate the server's public key from the private key:
    ```bash
    [cite_start]sudo cat server_private.key | wg pubkey | sudo tee server_public.key [cite: 29, 304, 1097]
    ```
4.  Set secure permissions for the private key:
    ```bash
    [cite_start]sudo chmod 600 server_private.key [cite: 30, 306, 1097]
    ```

### 1.3 Enable IP Forwarding

[cite_start]This is mandatory for routing client traffic to the internet[cite: 39].

1.  Enable forwarding in `sysctl.conf`:
    ```bash
    [cite_start]echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf [cite: 41, 349, 1136]
    ```
2.  Apply the changes immediately:
    ```bash
    [cite_start]sudo sysctl -p [cite: 41, 350, 1137]
    ```

### 1.4 Server Configuration File

[cite_start]Create the interface configuration file at `/etc/wireguard/wg0.conf`[cite: 52, 308].

[cite_start]**Note:** You must replace `<SERVER_PRIVATE_KEY>` with the content of your `server_private.key` file[cite: 53]. [cite_start]You must also replace `<EGRESS_IFACE>` in the `PostUp`/`PostDown` rules with your server's public-facing network interface (e.g., `eth0`, `eno1`, or `enp3s0`)[cite: 139, 140].

```ini
[Interface]
# Server's private key
[cite_start]PrivateKey = <SERVER_PRIVATE_KEY> [cite: 55, 318, 1104]
# Server's VPN IP address
[cite_start]Address = 10.8.0.1/24 [cite: 55, 320, 1105]
[cite_start]ListenPort = 51820 [cite: 56, 322, 1106]
[cite_start]SaveConfig = false [cite: 58, 327, 1108]

# NAT and Forwarding rules.
# %i is replaced with the interface name (wg0)
# <EGRESS_IFACE> must be your server's public interface
[cite_start]PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o <EGRESS_IFACE> -j MASQUERADE [cite: 57, 324, 1107]
[cite_start]PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o <EGRESS_IFACE> -j MASQUERADE [cite: 57, 325, 1107]

# --- Client Peer 1 ---
[cite_start][Peer] [cite: 59, 329, 1110]
# Public key from client 1
[cite_start]PublicKey = <CLIENT1_PUBLIC_KEY> [cite: 63, 330, 1111]
# VPN IP address to assign to client 1
[cite_start]AllowedIPs = 10.8.0.2/32 [cite: 64, 330, 1112]
[cite_start]PersistentKeepalive = 25 [cite: 66, 331, 1113]

# --- Client Peer 2 ---
[cite_start][Peer] [cite: 68, 333, 1114]
# Public key from client 2
[cite_start]PublicKey = <CLIENT2_PUBLIC_KEY> [cite: 69, 334, 1115]
# VPN IP address to assign to client 2
[cite_start]AllowedIPs = 10.8.0.3/32 [cite: 70, 335, 1116]
[cite_start]PersistentKeepalive = 25 [cite: 73, 336, 1117]
````

### 1.5 Start and Enable the WireGuard Service

1.  Enable the service to start on boot:
    ```bash
    [cite_start]sudo systemctl enable wg-quick@wg0 [cite: 75, 352, 1138]
    ```
2.  Start the service immediately:
    ```bash
    [cite_start]sudo systemctl start wg-quick@wg0 [cite: 76, 353, 1139]
    ```
3.  Inspect the status and verify peers:
    ```bash
    [cite_start]sudo wg show wg0 [cite: 77, 355, 1141]
    ```

-----

## Part 2: WireGuard Client Configuration

This section covers the configuration for end-user client devices.

### 2.1 Client Key Generation

[cite\_start]These steps should be performed on the client's machine, not the server[cite: 31, 160, 1098].

1.  Generate the client's private key:
    ```bash
    [cite_start]wg genkey | tee client_private.key [cite: 32, 1099]
    ```
2.  Generate the client's public key:
    ```bash
    [cite_start]cat client_private.key | wg pubkey | tee client_public.key [cite: 33, 1100]
    ```
3.  [cite\_start]Securely transfer *only* the contents of `client_public.key` to the server administrator[cite: 34, 1101]. [cite\_start]This is the key you add to the `[Peer]` block in `wg0.conf`[cite: 155].

### 2.2 Client Configuration File

[cite\_start]The client creates a configuration file (e.g., `client.conf` or `wg0.conf`)[cite: 82, 357].

[cite\_start]**Note:** Replace `<CLIENT_PRIVATE_KEY>` with the client's private key[cite: 83, 85]. [cite\_start]Replace `<CLIENT_VPN_IP>` with the IP address assigned by the administrator (e.g., `10.8.0.2`)[cite: 83, 86]. [cite\_start]Replace `<SERVER_PUBLIC_KEY>` and `<SERVER_PUBLIC_IP>` with the server's public key and public IP address[cite: 79, 81].

```ini
[Interface]
# Client's private key
[cite_start]PrivateKey = <CLIENT_PRIVATE_KEY> [cite: 85, 360, 1125]
# Client's assigned VPN IP
[cite_start]Address = <CLIENT_VPN_IP>/24 [cite: 86, 361, 1126]
# DNS servers to use when connected
[cite_start]DNS = 1.1.1.1, 8.8.8.8 [cite: 87, 362, 1129]

[Peer]
# Server's public key
[cite_start]PublicKey = <SERVER_PUBLIC_KEY> [cite: 91, 364, 1130]
# Server's public IP address and port
[cite_start]Endpoint = <SERVER_PUBLIC_IP>:51820 [cite: 93, 365, 1131]
# Route all traffic (full tunnel) through the VPN
[cite_start]AllowedIPs = 0.0.0.0/0, ::/0 [cite: 95, 366, 1132]
[cite_start]PersistentKeepalive = 25 [cite: 97, 367, 1133]
```

-----

## Part 3: Wazuh Agent Integration (on Server)

[cite\_start]Install and configure the Wazuh agent on the WireGuard server[cite: 103, 1145].

### 3.1 Install Wazuh Agent

1.  Add the Wazuh GPG key:
    ```bash
    [cite_start]curl -s [https://packages.wazuh.com/key/GPG-KEY-WAZUH](https://packages.wazuh.com/key/GPG-KEY-WAZUH) | gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import [cite: 378, 1146]
    ```
2.  Add the Wazuh repository:
    ```bash
    [cite_start]echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] [https://packages.wazuh.com/4.x/apt/](https://packages.wazuh.com/4.x/apt/) stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list [cite: 379, 1146]
    ```
3.  Install the agent:
    ```bash
    [cite_start]sudo apt-get update [cite: 380, 1147]
    [cite_start]sudo apt-get install wazuh-agent [cite: 381, 1147]
    ```
4.  Set the Wazuh Manager IP (replace with your manager's IP):
    ```bash
    [cite_start]echo "WAZUH_MANAGER='IP_DO_WAZUH_MANAGER'" > /var/ossec/etc/ossec.conf.d/manager.conf [cite: 383]
    ```
5.  Enable and start the agent:
    ```bash
    [cite_start]sudo systemctl daemon-reload [cite: 385]
    [cite_start]sudo systemctl enable wazuh-agent [cite: 386]
    [cite_start]sudo systemctl start wazuh-agent [cite: 387]
    ```

### 3.2 Configure Agent Log Collection

[cite\_start]Add the following blocks to the agent's configuration file at `/var/ossec/etc/ossec.conf`[cite: 105, 389, 1149].

```xml
[cite_start]<localfile> [cite: 106, 403, 1150]
  [cite_start]<log_format>syslog</log_format> [cite: 107, 404, 1151]
  [cite_start]<location>/var/log/syslog</location> [cite: 112, 405, 1152]
[cite_start]</localfile> [cite: 113, 406, 1153]

[cite_start]<localfile> [cite: 114, 408, 1154]
  [cite_start]<log_format>command</log_format> [cite: 115, 409, 1155]
  [cite_start]<command>journalctl -u wg-quick@wg0 -n 100 --no-pager</command> [cite: 116, 410, 1156]
  [cite_start]<frequency>60</frequency> [cite: 117, 411, 1161]
[cite_start]</localfile> [cite: 118, 412, 1162]

[cite_start]<localfile> [cite: 414, 1163]
  [cite_start]<log_format>json</log_format> [cite: 415, 1164]
  [cite_start]<command>/var/ossec/wodles/wireguard-monitor.sh</command> [cite: 416, 1165]
  [cite_start]<frequency>60</frequency> [cite: 417, 1166]
[cite_start]</localfile> [cite: 418, 1167]

[cite_start]<syscheck> [cite: 119, 420, 1168]
  [cite_start]<directories check_all="yes" realtime="yes">/etc/wireguard</directories> [cite: 120, 421, 1169]
[cite_start]</syscheck> [cite: 121, 422, 1170]
```

### 3.3 Create Custom Monitoring Script

[cite\_start]This script collects detailed peer status, handshake times, and data transfer metrics, outputting them in JSON format for Wazuh[cite: 123, 274, 437].

1.  Create the script file:
    ```bash
    [cite_start]sudo nano /var/ossec/wodles/wireguard-monitor.sh [cite: 425]
    ```
2.  Paste the following content:
    ```bash
    #!/bin/bash
    # WireGuard monitoring script for Wazuh
    # [cite_start]Collects metrics and peer status [cite: 436, 437]

    # Check if WireGuard is running
    [cite_start]if ! systemctl is-active --quiet wg-quick@wg0; then [cite: 439]
      [cite_start]echo "{\"wireguard\":{\"status\":\"down\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}}" [cite: 441]
      [cite_start]exit 0 [cite: 441]
    fi

    # Get peer information from wg show dump
    wg show wg0 dump | tail -n +2 | while IFS=$'\t' read -r public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
    do
      # Calculate time since last handshake
      [cite_start]if [ "$latest_handshake" != "0" ]; then [cite: 445]
        [cite_start]current_time=$(date +%s) [cite: 446]
        [cite_start]time_since_handshake=$((current_time - latest_handshake)) [cite: 447]
      else
        [cite_start]time_since_handshake=-1 [cite: 450]
      fi

      # Determine connection status based on handshake age
      # Active = < 180 seconds
      [cite_start]if [ "$time_since_handshake" -lt 180 ] && [ "$time_since_handshake" -ge 0 ]; then [cite: 452]
        [cite_start]connection_status="active" [cite: 452]
      # Never connected = -1
      [cite_start]elif [ "$time_since_handshake" -eq -1 ]; then [cite: 453]
        [cite_start]connection_status="never_connected" [cite: 454]
      # Stale = > 180 seconds
      else
        [cite_start]connection_status="stale" [cite: 457]
      fi

      # Convert bytes to MB for easier reading
      [cite_start]rx_mb=$((transfer_rx / 1048576)) [cite: 459]
      [cite_start]tx_mb=$((transfer_tx / 1048576)) [cite: 460]

      # Output JSON for Wazuh
      [cite_start]cat <<EOF [cite: 462]
    {
      [cite_start]"wireguard": { [cite: 464]
        [cite_start]"interface": "wg0", [cite: 465]
        [cite_start]"peer": { [cite: 466]
          [cite_start]"public_key": "${public_key:0:16}...${public_key: -6}", [cite: 467]
          [cite_start]"public_key_full": "$public_key", [cite: 474]
          [cite_start]"endpoint": "$endpoint", [cite: 475]
          [cite_start]"allowed_ips": "$allowed_ips", [cite: 476]
          [cite_start]"connection_status": "$connection_status", [cite: 477]
          [cite_start]"time_since_handshake_seconds": $time_since_handshake, [cite: 480]
          [cite_start]"transfer": { [cite: 481]
            [cite_start]"received_bytes": $transfer_rx, [cite: 483]
            [cite_start]"received_mb": $rx_mb, [cite: 484]
            [cite_start]"transmitted_bytes": $transfer_tx, [cite: 485]
            [cite_start]"transmitted_mb": $tx_mb [cite: 486]
          },
          [cite_start]"persistent_keepalive": "$persistent_keepalive" [cite: 487]
        },
        [cite_start]"timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)" [cite: 488]
      }
    }
    EOF
    done
    ```

### 3.4 Set Script Permissions and Restart

1.  Make the script executable and set ownership:
    ```bash
    [cite_start]sudo chmod +x /var/ossec/wodles/wireguard-monitor.sh [cite: 501, 1180]
    [cite_start]sudo chown root:ossec /var/ossec/wodles/wireguard-monitor.sh [cite: 502, 1181]
    ```
2.  Restart the agent to apply all changes:
    ```bash
    sudo systemctl restart wazuh-agent
    ```

-----

## Part 4: Wazuh Manager Configuration (Rules & Decoders)

[cite\_start]On the Wazuh Manager, add custom decoders and rules to interpret and alert on WireGuard events[cite: 124, 503].

### 4.1 Custom Decoders

[cite\_start]Add to `/var/ossec/etc/decoders/local_decoder.xml`[cite: 621]:

```xml
[cite_start]<decoder name="wireguard-syslog"> [cite: 636]
  <prematch>wg | [cite_start]WireGuard | wireguard</prematch> [cite: 637]
[cite_start]</decoder> [cite: 638]

[cite_start]<decoder name="wireguard-peer"> [cite: 639]
  [cite_start]<parent>wireguard-syslog</parent> [cite: 640]
  [cite_start]<regex offset="after_parent">peer (\S+)</regex> [cite: 641]
  [cite_start]<order>peer_key</order> [cite: 642]
[cite_start]</decoder> [cite: 643]

[cite_start]<decoder name="wireguard-endpoint"> [cite: 644]
  [cite_start]<parent>wireguard-syslog</parent> [cite: 645]
  [cite_start]<regex>endpoint (\d+\.\d+\.\d+\.\d+:\d+)</regex> [cite: 646]
  [cite_start]<order>endpoint</order> [cite: 647]
[cite_start]</decoder> [cite: 648]
```

### 4.2 Custom Rules

[cite\_start]Add to `/var/ossec/etc/rules/local_rules.xml`[cite: 124, 505]:

```xml
[cite_start]<group name="wireguard,vpn,"> [cite: 520]

  [cite_start]<rule id="100200" level="3"> [cite: 522]
    [cite_start]<decoded_as>wg</decoded_as> [cite: 523]
    [cite_start]<description>WireGuard: Event detected</description> [cite: 524]
    [cite_start]<group>wireguard,</group> [cite: 525]
  </rule>

  [cite_start]<rule id="100201" level="3"> [cite: 528, 1184]
    [cite_start]<if_sid>100200</if_sid> [cite: 529, 1185]
    [cite_start]<match>Peer|peer</match> [cite: 530, 1186]
    [cite_start]<match>connected | handshake</match> [cite: 531, 1187]
    [cite_start]<description>WireGuard: Peer connection established</description> [cite: 532, 1188]
    [cite_start]<group>wireguard,connection,</group> [cite: 533]
  </rule>

  [cite_start]<rule id="100202" level="5"> [cite: 536, 1190]
    [cite_start]<if_sid>100200</if_sid> [cite: 537, 1191]
    [cite_start]<match>Peer|peer</match> [cite: 538]
    [cite_start]<match>disconnected | removed | timeout</match> [cite: 539, 1192]
    [cite_start]<description>WireGuard: Peer disconnected</description> [cite: 540, 1193]
    [cite_start]<group>wireguard,connection,</group> [cite: 541]
  </rule>

  [cite_start]<rule id="100210" level="3"> [cite: 544]
    [cite_start]<decoded_as>json</decoded_as> [cite: 545]
    [cite_start]<field name="wireguard">\.+</field> [cite: 546]
    [cite_start]<description>WireGuard: Metrics collected</description> [cite: 547]
    [cite_start]<group>wireguard,monitoring,</group> [cite: 548]
  </rule>
  
  [cite_start]<rule id="100211" level="3"> [cite: 556]
    [cite_start]<if_sid>100210</if_sid> [cite: 557]
    [cite_start]<field name="wireguard.peer.connection_status">active</field> [cite: 560]
    [cite_start]<description>WireGuard: Peer connection is active</description> [cite: 561]
    [cite_start]<group>wireguard,connection,</group> [cite: 562]
  </rule>

  [cite_start]<rule id="100212" level="7"> [cite: 565]
    [cite_start]<if_sid>100210</if_sid> [cite: 566]
    [cite_start]<field name="wireguard.peer.connection_status">stale</field> [cite: 567]
    [cite_start]<description>WireGuard: Peer connection is stale (no recent handshake)</description> [cite: 568]
    [cite_start]<group>wireguard,connection,anomaly,</group> [cite: 569]
  </rule>

  [cite_start]<rule id="100214" level="10"> [cite: 579]
    [cite_start]<if_sid>100210</if_sid> [cite: 580]
    [cite_start]<field name="wireguard.status">down</field> [cite: 581]
    [cite_start]<description>WireGuard: Service is down!</description> [cite: 582]
    [cite_start]<group>wireguard,service_availability,</group> [cite: 583]
  </rule>

  [cite_start]<rule id="100220" level="8"> [cite: 593, 1195]
    [cite_start]<if_sid>550</if_sid> [cite: 594, 1196]
    [cite_start]<match>s/etc/wireguard/|/etc/wireguard</match> [cite: 595, 1197]
    [cite_start]<description>WireGuard: Configuration file modified</description> [cite: 604, 1198]
    [cite_start]<group>wireguard,config_change,pci_dss_11.5,hipaa_164.312.c.1,</group> [cite: 605]
  </rule>

  [cite_start]<rule id="100222" level="12"> [cite: 614]
    [cite_start]<if_sid>100200</if_sid> [cite: 615]
    [cite_start]<match>Invalid | invalid | unauthorized | not allowed | rejected</match> [cite: 616]
    [cite_start]<description>WireGuard: Unauthorized connection attempt detected</description> [cite: 617]
    [cite_start]<group>wireguard,authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group> [cite: 618]
  </rule>

[cite_start]</group> [cite: 619]
```

### 4.3 Restart the Wazuh Manager

Restart the manager to load the new decoders and rules.

```bash
[cite_start]sudo systemctl restart wazuh-manager [cite: 655]
```

-----

## Part 5: Active Response (Optional)

[cite\_start]This configures the manager to automatically block the source IP of unauthorized connection attempts[cite: 214, 726].

### 5.1 Create Active Response Script

[cite\_start]On the **Wazuh Manager**, create the block script[cite: 784]:

```bash
sudo nano /var/ossec/active-response/bin/wireguard-block.sh
```

Paste the following content:

```bash
#!/bin/bash
# [cite_start]Active Response: Block suspicious WireGuard peer [cite: 796]

[cite_start]ACTION=$1 [cite: 798]
USER=$2
[cite_start]IP=$3 [cite: 800]
ALERTID=$4
[cite_start]RULEID=$5 [cite: 802]
[cite_start]LOGFILE="/var/ossec/logs/active-responses.log" [cite: 808]

# Logging function
[cite_start]log() { [cite: 810]
  [cite_start]echo "$(date) $0: $1" >> ${LOGFILE} [cite: 811]
}

[cite_start]if [ "x${ACTION}" = "xadd" ]; then [cite: 814]
  [cite_start]log "Blocking suspicious WireGuard peer: IP=${IP}, Rule=${RULEID}" [cite: 815]
  
  # Block IP in firewall for WireGuard UDP port
  # Note: This command runs on the *agent* host (location=local)
  [cite_start]iptables -I INPUT -s ${IP} -p udp --dport 51820 -j DROP [cite: 819]
  [cite_start]log "IP ${IP} blocked successfully" [cite: 820]

[cite_start]elif [ "x${ACTION}" = "xdelete" ]; then [cite: 821]
  [cite_start]log "Unblocking WireGuard peer: IP=${IP}" [cite: 822]
  [cite_start]iptables -D INPUT -s ${IP} -p udp --dport 51820 -j DROP 2>/dev/null [cite: 823]
  [cite_start]log "IP ${IP} unblocked" [cite: 832]
fi

[cite_start]exit 0 [cite: 834]
```

### 5.2 Set Script Permissions

On the **Wazuh Manager**, set permissions for the new script:

```bash
[cite_start]sudo chmod 750 /var/ossec/active-response/bin/wireguard-block.sh [cite: 837]
[cite_start]sudo chown root:ossec /var/ossec/active-response/bin/wireguard-block.sh [cite: 838]
```

**Note:** This script must also be present with the same permissions on the **Wazuh Agent** machine since the `<location>local</location>` tag will be used.

### 5.3 Configure Active Response in Manager

[cite\_start]Add the following to the `ossec.conf` file on the **Wazuh Manager** (`/var/ossec/etc/ossec.conf`)[cite: 840]:

```xml
  [cite_start]<command> [cite: 842]
    [cite_start]<name>wireguard-block</name> [cite: 843]
    [cite_start]<executable>wireguard-block.sh</executable> [cite: 844]
    [cite_start]<timeout_allowed>yes</timeout_allowed> [cite: 845]
  [cite_start]</command> [cite: 846]
  
  [cite_start]<active-response> [cite: 847]
    [cite_start]<command>wireguard-block</command> [cite: 848]
    [cite_start]<location>local</location> [cite: 849]
    [cite_start]<rules_id>100222</rules_id> [cite: 850]
    [cite_start]<timeout>3600</timeout> [cite: 851]
  [cite_start]</active-response> [cite: 852]
```

### 5.4 Restart the Manager

Restart the manager one more time to enable Active Response.

```bash
sudo systemctl restart wazuh-manager
```

-----

## Part 6: Troubleshooting

Common deployment blockers and checks.

  * **No Internet Access Through VPN:**

    1.  **Check IP Forwarding:** Run `sysctl net.ipv4.ip_forward` on the server. [cite\_start]The result must be `1`[cite: 134].
    2.  [cite\_start]**Validate NAT:** Run `sudo iptables -t nat -S | grep MASQUERADE` on the server[cite: 136]. [cite\_start]Ensure it shows your correct public egress interface (e.g., `eth0`, `eno1`)[cite: 136, 137].
    3.  [cite\_start]**Check Egress Interface:** Run `ip route | grep default` to find the correct interface name[cite: 138].
    4.  [cite\_start]**Test DNS:** From the client, run `dig A example.com @1.1.1.1`[cite: 144]. [cite\_start]If it fails, ensure the `DNS` entry is correct in the client config[cite: 145].

  * **No Handshake Occurring (Client Can't Connect):**

    1.  [cite\_start]**Check Server Port:** On the server, run `sudo ss -lunp | grep 51820`[cite: 152]. It must show the server is listening on UDP port 51820.
    2.  [cite\_start]**Check Firewalls:** Ensure any firewalls on the server (e.g., `ufw allow 51820/udp`) or any upstream cloud/network firewall (e.g., AWS Security Group, router port forwarding) are configured to allow UDP traffic on port 51820[cite: 153].
    3.  [cite\_start]**Validate Keys:** Double-check that the `PublicKey` in the server's `[Peer]` block *exactly* matches the client's public key[cite: 154, 155].
    4.  [cite\_start]**Validate IPs:** Ensure the client's `Address` in its config (e.g., `10.8.0.2/24`) matches the `AllowedIPs` on the server for that peer (e.g., `10.8.0.2/32`)[cite: 156].

  * **Logs Not Appearing in Wazuh:**

    1.  [cite\_start]**Test the Script:** On the agent, run the script manually as the `ossec` user: `sudo -u ossec /var/ossec/wodles/wireguard-monitor.sh`[cite: 870]. It should output JSON data.
    2.  [cite\_start]**Check Agent Logs:** Run `tail -f /var/ossec/logs/ossec.log` on the agent[cite: 873]. Look for errors related to the script or "Connection refused" to the manager.
    3.  [cite\_start]**Test Rules:** On the manager, use `wazuh-logtest` to paste in a sample log (either from syslog or the script's JSON output) and see if it triggers the correct rules[cite: 653, 875].

<!-- end list -->
