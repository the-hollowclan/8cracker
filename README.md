# 8cracker

A lightweight automation toolkit to crack a WPA/WPA2 handshake/PMKID. Works with
(almost) any monitor-mode WiFi adapter, including RTL8188FTV / rtl8xxxu. Use it
as a fallback to wifite2 when that has RTL driver compatibility issues.

The cracking step uses **hashcat's OpenCL backend**, so it is GPU-agnostic: it
runs on any OpenCL-capable device (AMD, NVIDIA, Intel) and across distributions.

Wordlist generation is **not** included here — use
[crunchwl](https://github.com/its-ernest/crunchwl) for that.

Supportted Protocols: `WPA`, `WPA2`

## Build & install (from source)

Make sure you have Python3 installed

```bash
make build            # prepares bin/8cracker
sudo make install     # copies it to /usr/local/bin (global, on PATH)
```

To install somewhere other than `/usr/local`, override `PREFIX`:

```bash
sudo make install PREFIX=/usr
```

## Install dependencies

Required: `aircrack-ng`, `hcxtools`, `hashcat`, `ocl-icd`, and an OpenCL runtime
(e.g. `intel-compute-runtime`). The tool prints the right command for the
running distro:

```bash
8cracker install-deps --yes
```

Or manually, e.g. on Arch:

```bash
sudo pacman -S intel-compute-runtime ocl-icd hashcat hcxtools aircrack-ng
```

(Debian/Ubuntu use `apt`, Fedora `dnf`, openSUSE `zypper`, Alpine `apk` —
`install-deps` selects the right one automatically.)

## Usage

Run as root — capture needs monitor mode and raw frame injection. Working files
(capture, hash, potfile) are stored under `~/.cache/8cracker` (override with
`CRACKER_DIR`), so the tool locates them no matter where it is launched from —
including after a system-wide install.

```bash
# 1. Capture the handshake/PMKID
#    --interface wlan1mon  -> use that adapter directly
#    --interface (no value) -> show the adapter picker and choose at runtime
#    (no --interface)       -> same as the picker
sudo 8cracker capture --interface wlan1mon

# 2. Convert the capture to hashcat -m 22000 format
sudo 8cracker extract

# 3. Crack with a wordlist (OpenCL / GPU-agnostic)
sudo 8cracker crack --wordlist /path/to/wordlist.txt

# 4. Show cracked passwords
sudo 8cracker show
```

Capture files are written as `captured_packet-01.cap`; the hash becomes
`~/.cache/8cracker/hash/captured_packet.hc22000`.

## Important: a handshake can only be captured when a client is connecting

This is the #1 reason `extract` reports *"no hashes written"*.

A WPA/WPA2 handshake is the 4-way exchange between the **client** (phone,
laptop, etc.) and the **AP**. The capture needs the client's frames (M2 and M4)
too — not just the AP's M1/M3. If no client is actively associating during the
capture, you will capture only M1/M3 (or nothing), and `hcxpcapngtool` writes
no hash.

`8cracker capture` now auto-detects a complete handshake and stops, but it can
only succeed if:

- At least one **real client is connected to (or reconnecting to) the target
  network** during the capture window. If the network is idle (no devices
  associated), there is no handshake to capture — wait until a device is online.
- A client is **forced to reconnect** so the 4-way exchange happens while you
  are listening. `capture` sends deauth bursts automatically; for a cleaner
  result deauth a specific client with `--client <MAC>` instead of broadcasting.

### Symptoms and what they mean

- `EAPOL M1: 1, M3: 1` in the `hcxpcapngtool` output, but *no hash written*:
  only the AP's frames were captured, the client's M2/M4 were missed. Re-run
  while a client is connecting.
- `Warning: too many deauthentication/disassociation frames detected!`: a deauth
  storm (your bursts, the network's own churn, or both) makes the AP reset the
  EAPOL timer / renew the anonce, which prevents a valid message pair. Kill
  interfering processes with `--kill` and prefer targeting a single client with
  `--client <MAC>`.
- `extract` says *"no hashes written to hash files"*: the capture had no full
  handshake or PMKID. Re-run `capture` with a client actively connecting.

### Recommended capture command

```bash
# kill NetworkManager/wpa_supplicant first so they don't flip channels,
# then capture against a monitor-mode interface
sudo 8cracker capture --kill --interface wlan1mon

# optional: deauth one specific client for a cleaner handshake
sudo 8cracker capture --kill --interface wlan1mon --client AA:BB:CC:DD:EE:FF
```

Keep a device (phone/laptop) connected to the target and, ideally, toggle its
WiFi off/on during the capture so it re-associates and produces a fresh
handshake.

### Keep your built-in WiFi (wlan0) connected

`--kill` runs `airmon-ng check kill`, which kills `NetworkManager`,
`wpa_supplicant`, `dhclient`, etc. **system-wide** — not just for the adapter
you picked. That is what drops an in-use `wlan0` connection.

- If you capture on an **already-monitor USB adapter** (e.g. `wlan1mon`,
  shown as `[monitor]` in the picker), you usually do **not** need `--kill`,
  because nothing is managing that interface — so just omit it:
  `sudo 8cracker capture --interface wlan1mon`.
- Only pass `--kill` when the interface you capture on is `[managed]` and is
  being controlled by NetworkManager (or you see channel-flipping / managed-mode
  interference in airodump-ng).
- Selecting a `[managed]` adapter (like `wlan0`) puts it into monitor mode, which
  **by definition disconnects it from its network**. To keep `wlan0` online,
  capture on a separate monitor-mode adapter instead.

## Shell scripts (legacy)

The original bash scripts (`capture_packet.sh`, `extract_hash.sh`,
`crack_hash.sh`, `show_cracked.sh`) are kept and use the same
`captured_packet` naming, so they still work:

```bash
sudo bash capture_packet.sh && sudo bash extract_hash.sh
sudo bash crack_hash.sh && sudo bash show_cracked.sh
```
