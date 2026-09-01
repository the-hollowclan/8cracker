// Package core contains the backend logic for 8cracker: it wraps the external
// wireless/cracking tooling (aircrack-ng, hcxtools, hashcat, john) behind small
// Go helpers, manages the on-disk layout for captures/hashes, and provides the
// capture-quality checks the TUI polls during a live capture.
//
// The package intentionally does no terminal rendering — that lives in the tui
// package. Here we only build *exec.Cmd values, run the tools, parse their
// output, and answer "do we have a handshake yet?".
package core

import (
	"io"
	"os"
	"path/filepath"
)

// Tuning knobs for the live capture loop. These are deliberately gentle: blasting
// too many deauthentication frames makes the target AP reset its EAPOL timer,
// renew the ANONCE and zero the PMKID, which destroys the very handshake we are
// trying to capture (hcxpcapngtool warns about exactly this).
const (
	// DefaultWordlist is used to prefill the crack screen's wordlist field.
	DefaultWordlist = "rockyou.txt"
	// MaxCaptureSeconds is the overall budget before we give up on a handshake.
	MaxCaptureSeconds = 240
	// DeauthCount is the number of deauth frames sent per burst.
	DeauthCount = 5
	// DeauthInterval is how often (in seconds) a deauth burst is sent.
	DeauthInterval = 8
	// WriteInterval is the airodump-ng flush interval (seconds).
	WriteInterval = 1
)

// WorkDir returns the directory where 8cracker keeps all its working files
// (captures, hashes, potfile). It honors CRACKER_DIR, then XDG_CACHE_HOME, then
// ~/.cache, creating the directory if needed. Keeping everything under one fixed
// path means the tool locates its files regardless of the current directory.
func WorkDir() string {
	base := os.Getenv("CRACKER_DIR")
	if base == "" {
		base = os.Getenv("XDG_CACHE_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				home = "/tmp"
			}
			base = filepath.Join(home, ".cache")
		}
	}
	d := filepath.Join(base, "8cracker")
	os.MkdirAll(d, 0o755)
	return d
}

// CaptureBase is the file-path prefix (without extension) for the capture files
// written by airodump-ng, e.g. ".../captured_packet".
func CaptureBase() string { return filepath.Join(WorkDir(), "captured_packet") }

// CaptureCap returns the path to the current capture file. airodump-ng writes a
// .pcapng (preferred) or .cap; we resolve whichever actually exists, falling
// back to a glob, and finally to the canonical .pcapng name if nothing is there
// yet (so callers can pre-create/snapshot it).
func CaptureCap() string {
	base := CaptureBase()
	// Prefer pcapng (recommended by hcxpcapngtool); fall back to legacy .cap.
	for _, ext := range []string{".pcapng", ".cap"} {
		p := base + "-01" + ext
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if matches, _ := filepath.Glob(base + "-*.pcapng"); len(matches) > 0 {
		return matches[0]
	}
	if matches, _ := filepath.Glob(base + "-*.cap"); len(matches) > 0 {
		return matches[0]
	}
	return base + "-01.pcapng"
}

// CaptureCSV returns the path to airodump-ng's CSV sidecar for the capture, used
// to read the list of associated stations during a live capture.
func CaptureCSV() string { return CaptureBase() + "-01.csv" }

// CaptureTmp is a scratch directory (under os.TempDir) used for snapshot copies
// of the live capture while inspecting it.
func CaptureTmp() string {
	d := filepath.Join(os.TempDir(), "8cracker")
	os.MkdirAll(d, 0o755)
	return d
}

// RemoveStale deletes every file matching pattern. Used to clear old capture
// artifacts before starting a fresh airodump-ng run so it writes a clean -01
// file instead of auto-incrementing to -02, -03, ...
func RemoveStale(pattern string) {
	if matches, err := filepath.Glob(pattern); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}

// HashDir returns (and creates) the directory holding the extracted hashes and
// the potfile.
func HashDir() string {
	d := filepath.Join(WorkDir(), "hash")
	os.MkdirAll(d, 0o755)
	return d
}

// HashFile is the hashcat -m 22000 hash file produced by hcxpcapngtool.
func HashFile() string { return filepath.Join(HashDir(), "captured_packet.hc22000") }

// JohnHash is the John-the-Ripper compatible hash (hcxpcapngtool --john).
func JohnHash() string { return filepath.Join(HashDir(), "captured_packet.john") }

// Potfile is the shared potfile hashcat/john write recovered passwords to.
func Potfile() string { return filepath.Join(HashDir(), "captured_packet.potfile") }

// fileSize returns the size of path in bytes, or 0 if it does not exist.
func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// Exists reports whether path exists (exported wrapper around the unexported
// exists helper defined in net.go, kept unexported to avoid name clashes).
func Exists(path string) bool { return exists(path) }

// FileSize is the exported wrapper around fileSize.
func FileSize(path string) int64 { return fileSize(path) }

// copyFile copies src to dst so external tools can read a stable snapshot of a
// capture file that airodump-ng is still actively writing. Without the copy,
// hcxpcapngtool can race airodump-ng's writer and report an empty/truncated
// capture even when a handshake is present.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
