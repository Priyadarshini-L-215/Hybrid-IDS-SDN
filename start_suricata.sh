#!/bin/bash
# start_suricata.sh
# Automate suricata startup with password

PASSWORD="0000"
CONFIG="/mnt/d/projects/FYP/config/suricata/suricata.yaml"
RULES="/mnt/d/projects/FYP/config/suricata/signatures.rules"

echo "[*] Cleaning up old Suricata sessions..."
echo "$PASSWORD" | sudo -S pkill -x suricata
sleep 1

echo "[*] Starting Suricata Sensor on eth0..."
echo "$PASSWORD" | sudo -S suricata -c "$CONFIG" -s "$RULES" -i eth0

echo ""
echo "[!] Suricata exited. Check logs if this was unexpected."
echo "Press Enter to close this window..."
read
