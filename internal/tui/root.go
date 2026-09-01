// Package tui implements the interactive terminal UI for 8cracker using
// charmbracelet/bubbletea. It is a small state machine: each "screen" is a bubbletea
// model (adapter selection, scan, capture, extract, etc.) and root.go routes
// messages between them via nextScreenMsg.
//
// The overall flow is:
//
//	adapter -> (confirm) -> scan -> client -> capture -> extract -> crack(wordlist) -> crack(backend) -> results
//
// Long-running external tools (airodump-ng, aireplay-ng, hcxpcapngtool, hashcat,
// john) are spawned as detached subprocesses; the TUI polls their output/state on a
// timer and advances screens automatically (e.g. the capture screen stops itself
// the moment a handshake is detected).
package tui

import (
	"8cracker/internal/core"
	"github.com/charmbracelet/bubbletea"
)

// screen identifies which part of the flow is currently active. The root model
// delegates Update/View to the sub-model for the active screen.
type screen int

const (
	screenAdapter screen = iota
	screenConfirm
	screenScan
	screenClient
	screenCapture
	screenExtract
	screenCrack
	screenBackend
	screenResults
)

type nextScreenMsg struct {
	screen  screen
	payload interface{}
}

type monitorReadyMsg struct {
	mon string
	err error
}

// model is the root bubbletea model. It holds the shared flow state (which screen
// is active, the chosen monitor interface and target AP) plus one sub-model per
// screen. Only the sub-model for m.active handles Update/View; the rest are kept
// around so we can return to them without rebuilding state.
type model struct {
	kill   bool
	runCPU bool
	width  int
	height int

	active screen

	adapter  adapterModel
	confirm  confirmModel
	scan     scanModel
	client   clientModel
	capture  captureModel
	extract  extractModel
	wordlist wordlistModel
	backend  backendModel
	results  resultsModel

	pendingIface  string
	monIface      string
	target        core.AP
	pendingClient string
	err           error
}

// New builds the initial root model, starting on the adapter-selection screen.
// kill/runCPU come from the command-line flags in main.go.
func New(kill, runCPU bool) model {
	return model{
		kill:    kill,
		runCPU:  runCPU,
		active:  screenAdapter,
		adapter: newAdapterModel(kill),
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		m.stopActive()
		return m, tea.Quit
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case nextScreenMsg:
		return m.transition(msg)
	case monitorReadyMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.monIface = msg.mon
		return m.transition(nextScreenMsg{screen: screenScan, payload: msg.mon})
	}
	switch m.active {
	case screenAdapter:
		newM, cmd := m.adapter.Update(msg)
		m.adapter = newM.(adapterModel)
		return m, cmd
	case screenConfirm:
		newM, cmd := m.confirm.Update(msg)
		m.confirm = newM.(confirmModel)
		return m, cmd
	case screenScan:
		newM, cmd := m.scan.Update(msg)
		m.scan = newM.(scanModel)
		return m, cmd
	case screenClient:
		newM, cmd := m.client.Update(msg)
		m.client = newM.(clientModel)
		return m, cmd
	case screenCapture:
		newM, cmd := m.capture.Update(msg)
		m.capture = newM.(captureModel)
		return m, cmd
	case screenExtract:
		newM, cmd := m.extract.Update(msg)
		m.extract = newM.(extractModel)
		return m, cmd
	case screenCrack:
		newM, cmd := m.wordlist.Update(msg)
		m.wordlist = newM.(wordlistModel)
		return m, cmd
	case screenBackend:
		newM, cmd := m.backend.Update(msg)
		m.backend = newM.(backendModel)
		return m, cmd
	case screenResults:
		newM, cmd := m.results.Update(msg)
		m.results = newM.(resultsModel)
		return m, cmd
	}
	return m, nil
}

func (m model) transition(s nextScreenMsg) (model, tea.Cmd) {
	switch s.screen {
	case screenAdapter:
		m.active = screenAdapter
		m.adapter = newAdapterModel(m.kill)
		return m, m.adapter.Init()
	case screenConfirm:
		m.active = screenConfirm
		m.pendingIface = s.payload.(string)
		m.confirm = newConfirmModel(m.kill, s.payload.(string))
		return m, m.confirm.Init()
	case screenScan:
		m.active = screenScan
		m.monIface = s.payload.(string)
		m.scan = newScanModel(m.monIface)
		return m, m.scan.Init()
	case screenClient:
		m.active = screenClient
		m.target = s.payload.(core.AP)
		m.client = newClientModel(m.target)
		return m, m.client.Init()
	case screenCapture:
		m.active = screenCapture
		if c, ok := s.payload.(string); ok {
			m.pendingClient = c
		}
		m.capture = newCaptureModel(m.monIface, m.target, m.pendingClient)
		return m, m.capture.Init()
	case screenExtract:
		m.active = screenExtract
		m.extract = newExtractModel(m.target)
		return m, m.extract.Init()
	case screenCrack:
		m.active = screenCrack
		m.wordlist = newWordlistModel(m.target)
		return m, m.wordlist.Init()
	case screenBackend:
		m.active = screenBackend
		m.backend = newBackendModel(s.payload.(string), m.target, m.runCPU)
		return m, m.backend.Init()
	case screenResults:
		m.active = screenResults
		m.results = newResultsModel(m.target)
		return m, m.results.Init()
	}
	return m, nil
}

func (m *model) stopActive() {
	switch m.active {
	case screenScan:
		m.scan.stopScan()
	case screenCapture:
		m.capture.stopProc()
	}
}

func (m model) View() string {
	switch m.active {
	case screenAdapter:
		return m.adapter.View()
	case screenConfirm:
		return m.confirm.View()
	case screenScan:
		return m.scan.View()
	case screenClient:
		return m.client.View()
	case screenCapture:
		return m.capture.View()
	case screenExtract:
		return m.extract.View()
	case screenCrack:
		return m.wordlist.View()
	case screenBackend:
		return m.backend.View()
	case screenResults:
		return m.results.View()
	}
	return ""
}

// Run launches the bubbletea program in the alternate screen and blocks until the
// user quits.
func Run(kill, runCPU bool) error {
	p := tea.NewProgram(New(kill, runCPU), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
