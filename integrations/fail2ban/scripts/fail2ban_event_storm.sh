#!/bin/bash
# Fail2ban synthetic event generator for dashboard population and pipeline validation.
# All IPs are RFC 5737 documentation addresses (harmless).
#
# NOTE: fail2ban-client banip only emits a NOTICE Ban event if the IP is not
# already banned. Re-running this script requires fresh IP addresses to
# guarantee new decodable events. Edit the IPS array and the two persistent
# attacker IPs below before each re-run.

JAIL="sshd"
IPS=(
  203.0.113.100 203.0.113.101 203.0.113.102 203.0.113.103 203.0.113.104
  198.51.100.110 198.51.100.111 198.51.100.112 198.51.100.113
  192.0.2.120 192.0.2.121 192.0.2.122 192.0.2.123 192.0.2.124
)
PERSIST1="198.51.100.211"
PERSIST2="192.0.2.211"

echo "=== Phase 1: Distributed bans (rule 100801) ==="
for ip in "${IPS[@]}"; do
  sudo fail2ban-client set "$JAIL" banip "$ip" >/dev/null 2>&1
  echo "  Ban $ip"; sleep 0.4
done
sleep 2

echo "=== Phase 2: Partial unbans (rule 100802) ==="
for ip in "${IPS[@]:0:7}"; do
  sudo fail2ban-client set "$JAIL" unbanip "$ip" >/dev/null 2>&1
  echo "  Unban $ip"; sleep 0.4
done
sleep 2

echo "=== Phase 3: Persistent attacker 1 (rule 100803) ==="
for i in 1 2 3 4; do
  sudo fail2ban-client set "$JAIL" banip "$PERSIST1" >/dev/null 2>&1
  echo "  Ban #$i $PERSIST1"
  sudo fail2ban-client set "$JAIL" unbanip "$PERSIST1" >/dev/null 2>&1
  sleep 0.5
done

echo "=== Phase 4: Persistent attacker 2 (rule 100803) ==="
for i in 1 2 3 4; do
  sudo fail2ban-client set "$JAIL" banip "$PERSIST2" >/dev/null 2>&1
  echo "  Ban #$i $PERSIST2"
  sudo fail2ban-client set "$JAIL" unbanip "$PERSIST2" >/dev/null 2>&1
  sleep 0.5
done
sleep 2

echo "=== Cleanup ==="
for ip in "${IPS[@]:7}"; do
  sudo fail2ban-client set "$JAIL" unbanip "$ip" >/dev/null 2>&1
done
sleep 3

echo ""
echo "=== Local alert verification ==="
echo "100801 (Ban):         $(sudo grep -c '"id":"100801"' /var/ossec/logs/alerts/alerts.json)"
echo "100802 (Unban):       $(sudo grep -c '"id":"100802"' /var/ossec/logs/alerts/alerts.json)"
echo "100803 (correlation): $(sudo grep -c '"id":"100803"' /var/ossec/logs/alerts/alerts.json)"
