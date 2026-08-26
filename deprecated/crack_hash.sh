#!/bin/bash

HASH_FILE="hash/captured_packet.hc22000"
WORDLIST="./rockyou.txt"

# Verify files exist
if [ ! -f "$HASH_FILE" ]; then
    echo "[-] Error: Hash file $HASH_FILE not found. Run extract_hash.sh first."
    exit 1
fi

if [ ! -f "$WORDLIST" ]; then
    echo "[-] Error: Wordlist $WORDLIST not found."
    echo "[?] Please specify a valid wordlist path inside this script."
    exit 1
fi

echo "[+] Starting Hashcat..."
echo "[+] Target: $HASH_FILE"
echo "[+] Wordlist: $WORDLIST"
echo "--------------------------------------------------"

# -m 22000 = WPA-PBKDF2-PMKID+EAPOL
# -a 0 = Straight dictionary attack
hashcat -m 22000 -a 0 "$HASH_FILE" "$WORDLIST" --potfile-disable
