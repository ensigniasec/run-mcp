package tui

import "time"

// Package-level constants to avoid magic numbers and improve readability.
const (
	channelBufferSize      = 256
	defaultDeadlineSeconds = 30
	resultsPollIntervalMS  = 50
	countdownTickSeconds   = 1
	sortModesCount         = 3
	// viewport height for the transient scanning list (small, fast fly-out).
	scanningViewportLines = 3
	rightViewportMax      = 90

	// listOverheadLines represents header+countdown+progress+spacer lines above the list.
	// Keep this in sync with renderMainContent layout calculations.
	listOverheadLines = 6
	// listMinHeight enforces a minimum results list height to avoid collapsing.
	listMinHeight = 3

	defaultDeadlineDuration = time.Duration(defaultDeadlineSeconds) * time.Second
	resultsPollInterval     = time.Duration(resultsPollIntervalMS) * time.Millisecond
	countdownTickInterval   = time.Duration(countdownTickSeconds) * time.Second
)
