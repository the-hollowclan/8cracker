# 8cracker

A lightweight, terminal-based toolkit to **capture and crack WPA/WPA2 handshakes / PMKIDs**.
8cracker drives the standard open-source tooling (`aircrack-ng`, `hcxtools`, `hashcat`,
`john`) behind an interactive **TUI**, so the whole flow — pick adapter → scan → capture
handshake → extract → crack — runs from a single `sudo ./8cracker`.

The cracking step is GPU-agnostic: choose **hashcat on the GPU** (any OpenCL device:
AMD, NVIDIA, Intel) or **John the Ripper on the CPU** (no OpenCL needed).

> Supported: `WPA`, `WPA2`. Use it as a fallback to wifite when your adapter (e.g.
> RTL8188FTV / `rtl8xxxu`) has driver compatibility issues.

---

## Requirements

- **Linux** with a WiFi adapter capable of **monitor mode** and frame injection.
- Run as **root** — capture needs monitor mode and raw frame injection.
- External tools on `PATH`:
  - `aircrack-ng` (provides `airmon-ng`, `airodump-ng`, `aireplay-ng`)
  - `hcxtools` (provides `hcxpcapngtool`)
  - `hashcat` (GPU backend) **and/or** `john` (CPU backend)
  - An OpenCL runtime for the GPU backend (e.g. `intel-compute-runtime`,
    `opencl-nvidia`, `rocm-opencl-runtime`, …)

Install on Arch as a reference:

```bash
sudo pacman -S intel-compute-runtime ocl-icd hashcat hcxtools aircrack-ng john
```

(Debian/Ubuntu use `apt`, Fedora `dnf`, openSUSE `zypper`, Alpine `apk` — the package
names live in `internal/core/deps.go`.)

---

## Build

```bash
go build -o 8cracker ./cmd/8cracker
```

This produces the `8cracker` TUI binary. (A convenience copy is also built into `bin/`
via `make`.) Modern tooling is wired into the Makefile: `make fmt` (gofmt),
`make lint` (`go vet` + format check), and `make test`.

---

## Usage

```bash
sudo ./8cracker
```

Command-line flags (no TUI interaction needed for these):

```bash
sudo ./8cracker --show     # print already-cracked passwords and exit
sudo ./8cracker --kill     # kill processes that conflict with monitor mode
sudo ./8cracker --run-cpu  # default the backend picker to CPU (john)
```

The interactive flow:

1. **Adapter** — pick the wireless interface. A managed interface will be put into
   monitor mode (with a confirmation step, since that drops its current connection).
2. **Scan** — nearby APs are listed live; press `q` to stop scanning and `enter` to
   select a target.
3. **Client (optional)** — optionally pin a single client MAC to deauthenticate
   (gentler); leave blank to deauthenticate the whole AP.
4. **Capture** — airodump-ng locks onto the target BSSID/channel. Deauth bursts are
   sent *gently and only when clients are present*. The screen shows live EAPOL
   M1–M4 / PMKID progress and the associated-client count. **It stops automatically
   the moment a full handshake (or PMKID) is detected.** Keys: `d` force a deauth
   burst, `s` stop early, `q` quit.
5. **Extract** — `hcxpcapngtool` converts the capture into a hashcat `-m 22000` hash
   and a John hash. Stale hashes are cleared first so failures are reported honestly.
6. **Crack — wordlist** — type the wordlist path, then `enter`.
7. **Crack — backend** — choose **GPU (hashcat)** or **CPU (john)** with the arrow
   keys, then `enter` to start. Progress/output are shown live.
8. **Results** — recovered passwords from both `john --show` and `hashcat --show`.

### Why deauth is kept gentle

hcxpcapngtool explicitly warns that *excessive* deauthentication makes the AP reset its
EAPOL timer, renew the ANONCE, and zero the PMKID — which destroys the handshake you
are trying to capture. 8cracker therefore sends only a few deauth frames per burst and
only while a client is actually associated (see `internal/core/fs.go` tunables
`DeauthCount` / `DeauthInterval`).

---

## How it works

The repository follows the standard Go application layout:

- **`cmd/8cracker`** — the `main` entry point; parses flags (`--show`, `--kill`,
  `--run-cpu`) and launches the TUI.
- **`internal/core/`** — backend logic. Wraps the external tools in `*exec.Cmd`
  builders, owns the on-disk layout (`~/.cache/8cracker` by default, override with
  `CRACKER_DIR`), and answers the key question *"do we have a handshake yet?"* via
  `core.InspectCapture`, which snapshots the live capture and runs `hcxpcapngtool` on the
  copy (reading a file that airodump-ng is still writing can race the writer and report a
  truncated capture). Kept under `internal/` because it is an application-private
  package, not a library.
- **`internal/tui/`** — the bubbletea state machine. Each screen is its own model;
  `root.go` routes messages between them.

Capture files are written as `captured_packet-01.pcapng`; the hash becomes
`~/.cache/8cracker/hash/captured_packet.hc22000`.

---

## Legacy

`legacy/8cracker.py` is the **original Python CLI front-end** and is kept only for
reference. The actively maintained tool is the Go TUI built from this repository.

> The old `deprecated/` shell scripts (capture_packet.sh, extract_hash.sh, …) have been
> removed — they are fully superseded by the Go TUI.
