package tui

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"8cracker/internal/core"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

type apUpdateMsg struct{ aps []core.AP }

// scanModel runs an airodump-ng scan in the background and periodically refreshes
// the AP table from its CSV. The user stops the scan (q) then picks a target (enter).
type scanModel struct {
	monIface string
	proc     *exec.Cmd
	aps      []core.AP
	tbl      table.Model
	scanning bool
}

func newScanModel(mon string) scanModel {
	cols := []table.Column{
		{Title: "ESSID", Width: 28},
		{Title: "BSSID", Width: 20},
		{Title: "CH", Width: 4},
		{Title: "PWR", Width: 6},
	}
	t := table.New(
		table.WithColumns(cols),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		table.WithHeight(15),
		table.WithWidth(60),
	)
	prefix := filepath.Join(core.WorkDir(), "scan")
	core.RemoveStale(prefix + "-*")
	proc := core.AirodumpScanCmd(mon, prefix)
	if lf, err := os.Create(filepath.Join(core.WorkDir(), "scan_airodump.log")); err == nil {
		proc.Stdout = lf
		proc.Stderr = lf
	}
	_ = proc.Start()
	return scanModel{monIface: mon, proc: proc, tbl: t, scanning: true}
}

func (m scanModel) Init() tea.Cmd { return scanTick() }

func scanTick() tea.Cmd {
	return tea.Tick(800*time.Millisecond, func(time.Time) tea.Msg {
		csv := filepath.Join(core.WorkDir(), "scan-01.csv")
		return apUpdateMsg{aps: core.ParseAPs(csv)}
	})
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q":
			if m.scanning {
				m.stopScan()
				m.scanning = false
				return m, nil
			}
			return m, tea.Quit
		case "enter":
			if len(m.aps) > 0 {
				idx := m.tbl.Cursor()
				if idx >= len(m.aps) {
					idx = len(m.aps) - 1
				}
				ap := m.aps[idx]
				if m.scanning {
					m.stopScan()
					m.scanning = false
				}
				return m, func() tea.Msg { return nextScreenMsg{screen: screenClient, payload: ap} }
			}
		case "esc":
			if m.scanning {
				m.stopScan()
				m.scanning = false
			} else {
				return m, tea.Quit
			}
		}
	case apUpdateMsg:
		m.aps = msg.aps
		m.tbl.SetRows(apRows(msg.aps))
		if m.scanning {
			return m, scanTick()
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.tbl.SetHeight(msg.Height - 8)
	}
	var cmd tea.Cmd
	m.tbl, cmd = m.tbl.Update(msg)
	return m, cmd
}

func (m *scanModel) stopScan() {
	if m.proc != nil && m.proc.Process != nil {
		_ = m.proc.Process.Signal(os.Interrupt)
		_ = m.proc.Wait()
	}
}

func (m scanModel) View() string {
	status := greenStyle.Render("scanning...")
	if !m.scanning {
		status = yellowStyle.Render("scan stopped — enter to select target")
	}
	header := titleStyle.Render("Live scan") + "  " + status
	return header + "\n\n" + m.tbl.View() +
		"\n\n" + helpStyle.Render("enter select target • q stop scan • esc quit")
}

func apRows(aps []core.AP) []table.Row {
	rows := make([]table.Row, 0, len(aps))
	for _, a := range aps {
		essid := a.ESSID
		if essid == "" {
			essid = "<hidden>"
		}
		rows = append(rows, table.Row{essid, a.BSSID, a.Channel, a.Power})
	}
	return rows
}
