package tui

import "errors"

// Message types for Bubble Tea update loop.

// tickCountdownMsg fires every second to advance the deadline countdown.
type tickCountdownMsg struct{}

// tickRowMsg advances a specific row's spinner/stopwatch cadence.
type tickRowMsg struct{ HostID string }

// resultsMsg carries a status update for a host.
type resultsMsg struct {
	HostID  string
	Status  Status
	Message string
	Err     error
}

// fileScanMsg carries per-file scanning progress for the scanning phase.
type fileScanMsg struct {
	Path     string
	Found    bool
	Err      error
	Complete bool
}

// scanCompleteMsg signals that the scanning phase has finished.
type scanCompleteMsg struct{}

// pollTickMsg triggers a polling cycle for pending/running hosts.
type pollTickMsg struct{}

// quitMsg indicates the program should quit.
type quitMsg struct{ Reason error }

// resizeMsg updates terminal size-dependent layout.
type resizeMsg struct{ Width, Height int }

// ErrQuit is a sentinel quit reason.
var ErrQuit = errors.New("quit")
