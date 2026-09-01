package tui

import (
	"os"

	"8cracker/internal/core"
	tea "github.com/charmbracelet/bubbletea"
)

type extractDoneMsg struct {
	out    string
	err    error
	hashOK bool
	johnOK bool
}

// extractModel converts the captured file into hashcat (-m 22000) and John hashes.
// It clears any stale hash files first, so a failed extraction is reported honestly
// instead of being masked by a leftover file from an earlier run.
type extractModel struct {
	target core.AP
	output string
	err    error
	hashOK bool
	johnOK bool
	done   bool
}

func newExtractModel(ap core.AP) extractModel {
	return extractModel{target: ap}
}

func (m extractModel) Init() tea.Cmd {
	return func() tea.Msg {
		// Remove any stale hash files so a failed extraction is reported honestly
		// instead of being masked by a leftover file from a previous run.
		_ = os.Remove(core.HashFile())
		_ = os.Remove(core.JohnHash())
		out1, err1 := core.HcxpcapngtoolCmd(core.CaptureCap(), core.HashFile()).CombinedOutput()
		out2, _ := core.HcxpcapngtoolJohnCmd(core.CaptureCap(), core.JohnHash()).CombinedOutput()
		hashOK := core.Exists(core.HashFile()) && core.FileSize(core.HashFile()) > 0
		johnOK := core.Exists(core.JohnHash()) && core.FileSize(core.JohnHash()) > 0
		return extractDoneMsg{out: string(out1) + "\n" + string(out2), err: err1, hashOK: hashOK, johnOK: johnOK}
	}
}

func (m extractModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case extractDoneMsg:
		m.output = msg.out
		m.err = msg.err
		m.hashOK = msg.hashOK
		m.johnOK = msg.johnOK
		m.done = true
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if m.done && m.hashOK {
				return m, func() tea.Msg { return nextScreenMsg{screen: screenCrack} }
			}
			return m, func() tea.Msg { return nextScreenMsg{screen: screenResults} }
		case "q", "esc":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m extractModel) View() string {
	hdr := titleStyle.Render("Extract") + "\n"
	if !m.done {
		return hdr + greenStyle.Render("running hcxpcapngtool...") +
			"\n\n" + helpStyle.Render("working")
	}
	body := m.output
	switch {
	case m.hashOK:
		body += "\n" + greenStyle.Render("hash extracted — ready to crack")
	case m.johnOK:
		body += "\n" + yellowStyle.Render("no WPA handshake, but a John hash was produced")
	default:
		body += "\n" + redStyle.Render("extraction failed — no EAPOL handshake or PMKID was captured")
	}
	cont := helpStyle.Render("enter continue • q quit")
	if !m.hashOK {
		cont = helpStyle.Render("no usable hash — enter view results • q quit")
	}
	return hdr + body + "\n\n" + cont
}
