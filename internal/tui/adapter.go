package tui

import (
	"8cracker/internal/core"
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

type adapterItem struct {
	iface   string
	driver  string
	monitor bool
}

func (i adapterItem) Title() string { return i.iface }
func (i adapterItem) Description() string {
	tag := "[managed]"
	if i.monitor {
		tag = "[monitor]"
	}
	d := i.driver
	if d == "" {
		d = "(unknown driver)"
	}
	return fmt.Sprintf("%s  %s", d, tag)
}
func (i adapterItem) FilterValue() string { return i.iface }

// adapterModel is the first screen: it lists the system's wireless interfaces
// (from core.ListWirelessInterfaces) so the user can pick one. A managed interface
// is sent through a confirmation screen before monitor mode is enabled.
type adapterModel struct {
	list list.Model
	kill bool
	err  string
}

func newAdapterModel(kill bool) adapterModel {
	ifaces := core.ListWirelessInterfaces()
	items := make([]list.Item, 0, len(ifaces))
	for _, w := range ifaces {
		items = append(items, adapterItem{iface: w.Name, driver: w.Driver, monitor: w.Monitor})
	}
	del := list.NewDefaultDelegate()
	l := list.New(items, del, 0, 0)
	l.Title = "Select WiFi adapter (Use Arrow Down or Up to select)"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	m := adapterModel{list: l, kill: kill}
	if len(ifaces) == 0 {
		m.err = "No wireless interfaces found. Plug in an adapter and retry."
	}
	return m
}

func (m adapterModel) Init() tea.Cmd { return nil }

func (m adapterModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit
		case "enter":
			if m.err != "" {
				return m, nil
			}
			sel, ok := m.list.SelectedItem().(adapterItem)
			if !ok {
				return m, nil
			}
			if sel.monitor {
				return m, startMonitorCmd(m.kill, sel.iface)
			}
			return m, func() tea.Msg { return nextScreenMsg{screen: screenConfirm, payload: sel.iface} }
		}
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height-4)
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m adapterModel) View() string {
	if m.err != "" {
		return titleStyle.Render("8cracker") + "\n\n" + redStyle.Render(m.err) +
			"\n\n" + helpStyle.Render("press q to quit")
	}
	return titleStyle.Render("8cracker") + "\n\n" + m.list.View() +
		"\n" + helpStyle.Render("enter select • q quit")
}

func startMonitorCmd(kill bool, iface string) tea.Cmd {
	return func() tea.Msg {
		if kill {
			_ = core.KillConflicts()
		}
		mon, err := core.StartMonitor(iface)
		return monitorReadyMsg{mon: mon, err: err}
	}
}
