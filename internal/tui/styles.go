// Styles used across the TUI. Centralizing them keeps the color scheme consistent
// and easy to tweak.
package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	subStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	cyanStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	greenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	yellowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	redStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	helpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Faint(true)
)
