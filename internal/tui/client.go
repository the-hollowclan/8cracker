package tui

import (
	"path/filepath"
	"strings"

	"8cracker/internal/core"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// clientModel lets the user choose a specific client MAC to deauthenticate. Leaving
// it blank deauthenticates the whole AP (broadcast). The field is pre-filled with
// the first station seen during the scan for convenience.
type clientModel struct {
	ap core.AP
	ti textinput.Model
}

func newClientModel(ap core.AP) clientModel {
	ti := textinput.New()
	ti.Placeholder = "client MAC (blank = broadcast deauth of all clients)"
	clients := core.ParseStations(filepath.Join(core.WorkDir(), "scan-01.csv"), ap.BSSID)
	if len(clients) > 0 {
		ti.SetValue(clients[0])
	}
	ti.Focus()
	return clientModel{ap: ap, ti: ti}
}

func (m clientModel) Init() tea.Cmd { return textinput.Blink }

func (m clientModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q":
			return m, func() tea.Msg { return nextScreenMsg{screen: screenScan} }
		case "enter":
			return m, func() tea.Msg {
				return nextScreenMsg{screen: screenCapture, payload: strings.TrimSpace(m.ti.Value())}
			}
		}
	}
	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

func (m clientModel) View() string {
	essid := m.ap.ESSID
	if essid == "" {
		essid = "<hidden>"
	}
	hdr := titleStyle.Render("Target") + "  " + cyanStyle.Render(essid) +
		"  " + subStyle.Render(m.ap.BSSID)
	body := "\n\nDefault: a single client (pre-filled from the scan) is deauthenticated to " +
		"force just that handshake — less disruptive than blasting the whole AP. " +
		"Clear the field to deauthenticate all clients.\n\n" +
		m.ti.View() + "\n\n" + helpStyle.Render("enter start capture • esc back")
	return hdr + body
}
