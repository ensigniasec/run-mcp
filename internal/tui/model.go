package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

// Status represents per-host lifecycle.
type Status int

const (
	Pending Status = iota
	Running
	OK
	Fail
	Timeout
)

// HostRow is the per-host state rendered in the table.
type HostRow struct {
	ID          string
	Name        string
	Status      Status
	StartedAt   time.Time
	Spinner     spinner.Model
	LastMessage string
	Error       string
}

// SortMode controls row ordering.
type SortMode int

const (
	SortByStatus SortMode = iota
	SortByDuration
	SortByName
)

// Model is the root Bubble Tea model.
type Model struct {
	deadline       time.Time
	now            time.Time
	hosts          []HostRow
	completedCount int
	failedCount    int
	progress       progress.Model
	polling        bool
	viewportOffset int
	verbose        bool
	sortMode       SortMode
	selectedIndex  int
	width          int
	height         int
	quitting       bool

	// inbound messages from scanner bridge
	resultsCh     chan resultsMsg
	fileResultsCh chan fileScanMsg

	// ui state
	helpVisible bool

	// scanning phase state
	scanCompleted  bool
	filesScanned   int
	fileScanEvents []fileScanMsg
	totalFiles     int
	_seenStarts    map[string]struct{}

	// mode flags for header rendering
	offline   bool
	anonymous bool

	// results list view (search, pagination, highlight)
	resultsList list.Model

	// keymap for consistent keybindings
	keys keyMap
}

// NewModel constructs a Model with initial state.
func NewModel(deadline time.Time, initialHosts []HostRow, resultsCh chan resultsMsg, fileResultsCh chan fileScanMsg) Model { // nolint:ireturn
	p := progress.New(progress.WithDefaultGradient())
	// initialize empty list with custom delegate
	delegate := resultsDelegate{}
	lst := list.New([]list.Item{}, delegate, 0, 0)
	lst.SetShowStatusBar(true)
	lst.SetFilteringEnabled(true)
	lst.SetShowHelp(false)
	lst.SetShowPagination(true)
	return Model{
		deadline:      deadline,
		now:           time.Now(),
		hosts:         initialHosts,
		progress:      p,
		sortMode:      SortByStatus,
		resultsCh:     resultsCh,
		fileResultsCh: fileResultsCh,
		helpVisible:   false,
		scanCompleted: false,
		resultsList:   lst,
		keys:          newKeyMap(),
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.listenForResults(),
		m.listenForFileResults(),
		m.tickCountdown(),
	)
}

// listenForResults returns a Tea command that waits for resultsMsg.
func (m Model) listenForResults() tea.Cmd {
	return func() tea.Msg {
		msg := <-m.resultsCh
		return msg
	}
}

// listenForFileResults returns a Tea command that waits for fileScanMsg.
func (m Model) listenForFileResults() tea.Cmd {
	return func() tea.Msg {
		msg := <-m.fileResultsCh
		return msg
	}
}

// tickCountdown schedules the next countdown tick.
func (m Model) tickCountdown() tea.Cmd {
	return func() tea.Msg {
		time.Sleep(countdownTickInterval)
		return tickCountdownMsg{}
	}
}
