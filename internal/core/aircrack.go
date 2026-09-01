// Package core contains the backend logic for 8cracker. See the package doc on
// fs.go for an overview; this file builds the external-tool commands and provides
// the capture-quality inspection used by the TUI's live capture screen.
package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// detach puts cmd into its own session (Setsid) and redirects stdin from
// /dev/null. This keeps long-running capture tools (airodump-ng) alive and
// independent of the TUI's process group, so they keep running until we send them
// a signal ourselves.
func detach(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if dn, err := os.OpenFile(os.DevNull, os.O_RDWR, 0); err == nil {
		cmd.Stdin = dn
	}
	return cmd
}

// KillConflicts kills processes that interfere with monitor mode (NetworkManager,
// wpa_supplicant, etc.) via "airmon-ng check kill".
func KillConflicts() error {
	return exec.Command("airmon-ng", "check", "kill").Run()
}

// InspectCapture snapshots the live capture file and asks hcxpcapngtool to convert
// it. It returns whether a usable hash (WPA handshake or PMKID) was extracted,
// plus the tool's summary text (used by the UI to show live EAPOL/PMKID counts).
//
// Copying the file first matters: airodump-ng keeps the capture open and appends
// to it, and running hcxpcapngtool against the live file can race the writer and
// report a truncated/empty capture even when a handshake is present.
func InspectCapture(capPath string) (hashable bool, summary string) {
	if !exists(capPath) {
		return false, ""
	}
	tmpDir := CaptureTmp()
	tmpCap := filepath.Join(tmpDir, "inspect.cap")
	tmpHash := filepath.Join(tmpDir, "inspect.hc22000")
	os.Remove(tmpHash)
	defer os.Remove(tmpCap)
	defer os.Remove(tmpHash)
	if err := copyFile(capPath, tmpCap); err != nil {
		return false, ""
	}
	res, _ := exec.Command("hcxpcapngtool", "-o", tmpHash, tmpCap).CombinedOutput()
	summary = string(res)
	if exists(tmpHash) && fileSize(tmpHash) > 0 {
		hashable = true
	}
	return hashable, summary
}

// HasHandshake reports whether the capture already yields a crackable hash.
func HasHandshake(capPath, bssid string) bool {
	ok, _ := InspectCapture(capPath)
	return ok
}

// HandshakeProgress parses hcxpcapngtool's summary for the EAPOL M1–M4 message
// counts and the PMKID count, so the UI can display incremental progress toward a
// complete 4-way handshake (seeing both M2 and M4 is the signal that a full
// exchange was captured).
func HandshakeProgress(summary string) (m1, m2, m3, m4, pmkid int) {
	eapol := regexp.MustCompile(`EAPOL M(\d) messages \(total\)\s*:\s*(\d+)`)
	for _, m := range eapol.FindAllStringSubmatch(summary, -1) {
		n, _ := strconv.Atoi(m[2])
		switch m[1] {
		case "1":
			m1 = n
		case "2":
			m2 = n
		case "3":
			m3 = n
		case "4":
			m4 = n
		}
	}
	if pm := regexp.MustCompile(`PMKID \(total\)\s*:\s*(\d+)`).FindStringSubmatch(summary); pm != nil {
		pmkid, _ = strconv.Atoi(pm[1])
	}
	return
}

// AirodumpScanCmd builds an airodump-ng scan that writes a CSV of all nearby APs
// (used by the live-scan screen to pick a target).
func AirodumpScanCmd(monIface, prefix string) *exec.Cmd {
	return detach(exec.Command("airodump-ng", "-w", prefix, "--output-format", "csv", monIface))
}

// AirodumpCaptureCmd builds an airodump-ng command locked to a single BSSID and
// channel, writing pcapng + csv. We lock to the target so the capture stays small
// and the handshake is easy to find.
func AirodumpCaptureCmd(bssid, channel, prefix, monIface string) *exec.Cmd {
	args := []string{"--bssid", bssid, "--write-interval", strconv.Itoa(WriteInterval), "--output-format", "pcapng,csv"}
	if channel != "" {
		args = append(args, "-c", channel)
	}
	args = append(args, "-w", prefix, monIface)
	return detach(exec.Command("airodump-ng", args...))
}

// AireplayDeauthCmd builds a deauthentication burst. When client is empty the
// whole AP is deauthenticated (broadcast); otherwise only that single client is
// targeted, which is gentler and forces just that client to reconnect.
func AireplayDeauthCmd(bssid, monIface string, count int, client string) *exec.Cmd {
	args := []string{"-0", strconv.Itoa(count), "-a", bssid}
	if client != "" {
		args = append(args, "-c", client)
	}
	args = append(args, monIface)
	return detach(exec.Command("aireplay-ng", args...))
}

// HcxpcapngtoolCmd builds the command that converts a capture into a hashcat
// -m 22000 hash file.
func HcxpcapngtoolCmd(capPath, hashPath string) *exec.Cmd {
	return exec.Command("hcxpcapngtool", "-o", hashPath, capPath)
}

// HcxpcapngtoolJohnCmd builds the command that converts a capture into a
// John-the-Ripper compatible hash.
func HcxpcapngtoolJohnCmd(capPath, johnPath string) *exec.Cmd {
	return exec.Command("hcxpcapngtool", "--john="+johnPath, capPath)
}

// HashcatCmd builds the GPU cracking command (OpenCL device type 2).
func HashcatCmd(hashPath, wordlist, potfile string) *exec.Cmd {
	return exec.Command("hashcat", "-m", "22000", "-a", "0", "--potfile-path", potfile, hashPath, wordlist, "-D", "2")
}

// JohnCmd builds the CPU cracking command.
func JohnCmd(hashPath, wordlist string) *exec.Cmd {
	return exec.Command("john", "--wordlist", wordlist, hashPath)
}

// JohnShowCmd builds the command that prints passwords john has already cracked.
func JohnShowCmd(hashPath string) *exec.Cmd {
	return exec.Command("john", "--show", hashPath)
}

// HashcatShowCmd builds the command that prints passwords hashcat has recovered.
func HashcatShowCmd(hashPath, potfile string) *exec.Cmd {
	return exec.Command("hashcat", "-m", "22000", "--show", "--potfile-path", potfile, hashPath)
}

// ShowResults returns the passwords recovered so far by john --show and
// hashcat --show. It is used both by the results screen and by the `--show`
// command-line flag, which prints them and exits without launching the TUI.
func ShowResults() string {
	var b strings.Builder
	if _, err := exec.LookPath("john"); err == nil {
		out, _ := JohnShowCmd(JohnHash()).CombinedOutput()
		b.WriteString("john --show:\n" + string(out) + "\n")
	}
	if _, err := exec.LookPath("hashcat"); err == nil {
		out, _ := HashcatShowCmd(HashFile(), Potfile()).CombinedOutput()
		b.WriteString("hashcat --show:\n" + string(out))
	}
	if b.Len() == 0 {
		b.WriteString("no cracking tools found to show results")
	}
	return b.String()
}

// capture if necessary. Returns whether a usable John hash is now present.
func EnsureJohnHash() bool {
	if exists(JohnHash()) && fileSize(JohnHash()) > 0 {
		return true
	}
	if !exists(CaptureCap()) {
		return false
	}
	out, err := HcxpcapngtoolJohnCmd(CaptureCap(), JohnHash()).CombinedOutput()
	_ = out
	return err == nil && exists(JohnHash()) && fileSize(JohnHash()) > 0
}
