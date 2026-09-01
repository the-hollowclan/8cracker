package tui

import (
	"fmt"
	"strings"

	"8cracker/internal/core"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// ---------------------------------------------------------------------------
// Screen 1: wordlist path input
// ---------------------------------------------------------------------------

// wordlistModel is the first crack screen: it collects the wordlist path. Pressing
// enter proceeds to the backend-selection screen.
type wordlistModel struct {
	target core.AP
	ti     textinput.Model
}

func newWordlistModel(ap core.AP) wordlistModel {
	ti := textinput.New()
	ti.Placeholder = "wordlist path"
	ti.SetValue(core.DefaultWordlist)
	ti.Focus()
	return wordlistModel{target: ap, ti: ti}
}

func (m wordlistModel) Init() tea.Cmd { return textinput.Blink }

func (m wordlistModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit
		case "enter":
			return m, func() tea.Msg {
				return nextScreenMsg{screen: screenBackend, payload: strings.TrimSpace(m.ti.Value())}
			}
		}
	}
	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

func (m wordlistModel) View() string {
	hdr := titleStyle.Render("Crack — wordlist") + "\n\n"
	body := "wordlist path:\n" + m.ti.View() + "\n\n" +
		helpStyle.Render("enter continue • q quit")
	return hdr + body
}

// ---------------------------------------------------------------------------
// Screen 2: backend selection (GPU/CPU), then it runs
// ---------------------------------------------------------------------------

type crackDoneMsg struct {
	out string
	err error
}

type backendOption struct {
	name string
	desc string
	cpu  bool
}

// backendModel is the second crack screen: it lets the user pick GPU (hashcat) or
// CPU (john) with the arrow keys, then runs the cracker. On completion it advances
// to the results screen.
type backendModel struct {
	target   core.AP
	wordlist string
	options  []backendOption
	cursor   int
	spinner  spinner.Model
	running  bool
	done     bool
	output   string
	err      error
}

func newBackendModel(wordlist string, ap core.AP, defaultCPU bool) backendModel {
	opts := []backendOption{
		{name: "GPU (hashcat)", desc: "OpenCL GPU cracking — hashcat -m 22000", cpu: false},
		{name: "CPU (john)", desc: "CPU-only cracking — john, no OpenCL needed", cpu: true},
	}
	cursor := 0
	if defaultCPU {
		cursor = 1
	}
	return backendModel{target: ap, wordlist: wordlist, options: opts, cursor: cursor, spinner: spinner.New()}
}

func (m backendModel) selectedCPU() bool { return m.options[m.cursor].cpu }

func (m backendModel) Init() tea.Cmd { return m.spinner.Tick }

func startCrackCmd(runCPU bool, wordlist string) tea.Cmd {
	return func() tea.Msg {
		var out []byte
		var err error
		if runCPU {
			if !core.Exists(core.JohnHash()) || core.FileSize(core.JohnHash()) == 0 {
				if !core.EnsureJohnHash() {
					return crackDoneMsg{
						out: "no John hash available — run extract first (capture may have failed)",
						err: fmt.Errorf("missing john hash"),
					}
				}
			}
			out, err = core.JohnCmd(core.JohnHash(), wordlist).CombinedOutput()
		} else {
			if !core.Exists(core.HashFile()) || core.FileSize(core.HashFile()) == 0 {
				if _, e := core.HcxpcapngtoolCmd(core.CaptureCap(), core.HashFile()).CombinedOutput(); e != nil {
					return crackDoneMsg{
						out: "no hc22000 hash available — run extract first (capture may have failed)",
						err: fmt.Errorf("missing hash"),
					}
				}
			}
			out, err = core.HashcatCmd(core.HashFile(), wordlist, core.Potfile()).CombinedOutput()
		}
		return crackDoneMsg{out: string(out), err: err}
	}
}

func (m backendModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case crackDoneMsg:
		m.output = msg.out
		m.err = msg.err
		m.done = true
		m.running = false
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < len(m.options)-1 {
				m.cursor++
			}
			return m, nil
		case "enter":
			if !m.running && !m.done {
				m.running = true
				return m, startCrackCmd(m.selectedCPU(), m.wordlist)
			}
			if m.done {
				return m, func() tea.Msg { return nextScreenMsg{screen: screenResults} }
			}
		}
	}
	return m, nil
}

func (m backendModel) View() string {
	hdr := titleStyle.Render("Crack — backend") + "\n\n"
	switch {
	case m.running:
		return hdr + m.spinner.View() + " cracking...\n"
	case m.done:
		body := m.output
		if m.err != nil {
			body += "\n" + redStyle.Render("cracker exited with an error (passwords may still be recovered)")
		}
		return hdr + body + "\n\n" + helpStyle.Render("enter view results • q quit")
	default:
		var b strings.Builder
		for i, o := range m.options {
			if i == m.cursor {
				b.WriteString(cyanStyle.Render("> "+o.name) + "\n")
				b.WriteString("    " + helpStyle.Render(o.desc) + "\n\n")
			} else {
				b.WriteString(subStyle.Render("  "+o.name) + "\n")
				b.WriteString("    " + helpStyle.Render(o.desc) + "\n\n")
			}
		}
		return hdr + b.String() + helpStyle.Render("↑/↓ or j/k select • enter start cracking • q quit")
	}
}
