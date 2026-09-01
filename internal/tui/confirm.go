package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
)

// confirmModel warns the user that enabling monitor mode on a managed interface
// (e.g. wlan0) will drop its current connection, and asks for confirmation.
type confirmModel struct {
	iface string
	kill  bool
}

func newConfirmModel(kill bool, iface string) confirmModel {
	return confirmModel{iface: iface, kill: kill}
}

func (m confirmModel) Init() tea.Cmd { return nil }

func (m confirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			return m, startMonitorCmd(m.kill, m.iface)
		case "n", "N", "q", "esc":
			return m, func() tea.Msg { return nextScreenMsg{screen: screenAdapter} }
		}
	}
	return m, nil
}

func (m confirmModel) View() string {
	return titleStyle.Render("8cracker") + "\n\n" +
		yellowStyle.Render(fmt.Sprintf("%s is [managed]; switching to monitor mode will drop its current connection.", m.iface)) + "\n" +
		yellowStyle.Render("Continue? [y/N]") + "\n\n" +
		helpStyle.Render("y yes • n back")
}
