package tui

import (
	"os/exec"
	"strings"

	"8cracker/internal/core"
	tea "github.com/charmbracelet/bubbletea"
)

type resultsDoneMsg struct{ out string }

// resultsModel shows the passwords recovered so far by john --show and hashcat --show.
type resultsModel struct {
	target core.AP
	output string
	done   bool
}

func newResultsModel(ap core.AP) resultsModel {
	return resultsModel{target: ap}
}

func (m resultsModel) Init() tea.Cmd {
	return func() tea.Msg {
		var b strings.Builder
		if _, err := exec.LookPath("john"); err == nil {
			out, _ := core.JohnShowCmd(core.JohnHash()).CombinedOutput()
			b.WriteString("john --show:\n" + string(out) + "\n")
		}
		if _, err := exec.LookPath("hashcat"); err == nil {
			out, _ := core.HashcatShowCmd(core.HashFile(), core.Potfile()).CombinedOutput()
			b.WriteString("hashcat --show:\n" + string(out))
		}
		if b.Len() == 0 {
			b.WriteString("no cracking tools found to show results")
		}
		return resultsDoneMsg{out: b.String()}
	}
}

func (m resultsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case resultsDoneMsg:
		m.output = msg.out
		m.done = true
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "enter":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m resultsModel) View() string {
	hdr := titleStyle.Render("Results") + "\n"
	if !m.done {
		return hdr + greenStyle.Render("loading recovered passwords...")
	}
	return hdr + m.output + "\n\n" + helpStyle.Render("q quit")
}
