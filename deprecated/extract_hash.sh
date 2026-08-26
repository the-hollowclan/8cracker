#!/bin/bash

INPUT_CAP="captured_packet-01.cap"
OUTPUT_DIR="hash"
OUTPUT_HASH="$OUTPUT_DIR/captured_packet.hc22000"

# Check if input file exists
if [ ! -f "$INPUT_CAP" ]; then
    echo "[-] Error: $INPUT_CAP not found in the current directory!"
    exit 1
fi

# Create hash directory if missing
mkdir -p "$OUTPUT_DIR"

echo "[+] Converting $INPUT_CAP to Hashcat PMKID/EAPOL format..."
# hcxpcapngtool used to convert cap/pcap to the newer 22000 hash format
hcxpcapngtool -o "$OUTPUT_HASH" "$INPUT_CAP"

if [ -f "$OUTPUT_HASH" ] && [ -s "$OUTPUT_HASH" ]; then
    echo "[+] Success! Hash extracted to: $OUTPUT_HASH"
    echo "[+] Content preview:"
    cat "$OUTPUT_HASH"
else
    echo "[-] Extraction failed. Make sure a full handshake or PMKID was captured."
fi
