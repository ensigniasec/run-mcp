package tui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// resultItem is the list item backing a discovered server row.
type resultItem struct {
	ID      string
	Name    string
	Status  Status
	Message string
	ErrText string
}

// List item interface methods.
func (it resultItem) Title() string       { return it.Name }
func (it resultItem) Description() string { return "" }
func (it resultItem) FilterValue() string { return it.Name + " " + it.Message }

// resultsDelegate renders resultItem rows with right-justified message and status icon.
type resultsDelegate struct{}

func (d resultsDelegate) Height() int                             { return 1 }
func (d resultsDelegate) Spacing() int                            { return 0 }
func (d resultsDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }

func (d resultsDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	it, ok := listItem.(resultItem)
	if !ok {
		return
	}
	// Determine selection and styles
	selected := index == m.Index()
	name := it.Name
	leftPrefix := "  "
	lineStyle := lipgloss.NewStyle()
	if selected {
		leftPrefix = "> "
		lineStyle = lineStyle.Foreground(lipgloss.Color("69")).Bold(true)
	}

	// Left: index and name
	left := fmt.Sprintf("%s%02d. %s", leftPrefix, index+1, name)

	// Right: message then status icon
	icon := statusIcon(it.Status)
	right := it.Message
	if icon != "" {
		if right != "" {
			right += " "
		}
		right += icon
	}

	available := m.Width()
	padding := available - lipgloss.Width(left) - lipgloss.Width(right)
	if padding < 1 {
		padding = 1
	}

	line := left + lipgloss.NewStyle().Render(spaces(padding)) + right
	_, _ = fmt.Fprint(w, lineStyle.Render(line))
}

func spaces(n int) string {
	if n <= 0 {
		return ""
	}
	return lipgloss.NewStyle().Width(n).Render("")
}

func statusIcon(s Status) string {
	switch s {
	case OK:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("✅")
	case Fail:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("❌")
	case Timeout:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("⏰")
	case Pending:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("⏳")
	case Running:
		return "…"
	default:
		return ""
	}
}
