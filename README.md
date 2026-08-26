# 8cracker

A lightweight automation toolkit to crack a WPA/WPA2 handshake/PMKID. Works with
(almost) any monitor-mode WiFi adapter, including RTL8188FTV / rtl8xxxu. Use it
as a fallback to wifite2 when that has RTL driver compatibility issues.

The cracking step uses **hashcat's OpenCL backend**, so it is GPU-agnostic: it
runs on any OpenCL-capable device (AMD, NVIDIA, Intel) and across distributions.

Wordlist generation is **not** included here — use
[crunchwl](https://github.com/its-ernest/crunchwl) for that.

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

## Shell scripts (legacy)

The original bash scripts (`capture_packet.sh`, `extract_hash.sh`,
`crack_hash.sh`, `show_cracked.sh`) are kept and use the same
`captured_packet` naming, so they still work:

```bash
sudo bash capture_packet.sh && sudo bash extract_hash.sh
sudo bash crack_hash.sh && sudo bash show_cracked.sh
```
