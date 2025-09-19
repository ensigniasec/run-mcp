package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) { // nolint:ireturn,gocognit,gocyclo,cyclop,funlen // WIP code
	switch x := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = x.Width, x.Height
		return m, nil

	case tea.KeyMsg:
		if m.scanCompleted {
			// Results mode: let list handle the key
			var cmd tea.Cmd
			m.resultsList, cmd = m.resultsList.Update(x)
			return m, cmd
		}
		var cmd tea.Cmd
		m, cmd = m.handleKey(x)
		return m, cmd

	case tickCountdownMsg:
		m.now = time.Now()
		if m.now.After(m.deadline) {
			m.markTimeouts()
		}
		return m, m.tickCountdown()

	case tickRowMsg:
		// no-op for now; spinners advanced via bubbletea messages when integrated
		_ = x
		return m, nil

	case resultsMsg:
		m.applyResult(x)
		// Keep list items in sync when hosts change
		m.syncResultsListItems()
		return m, m.listenForResults()

	case fileScanMsg:
		// Empty path is a completion signal from the scanner; flip view immediately.
		if x.Path == "" && x.Complete {
			m.scanCompleted = true
			_ = m.progress.SetPercent(1.0)
			// Ensure list has items when switching views
			m.syncResultsListItems()
			return m, m.listenForFileResults()
		}

		m.fileScanEvents = append(m.fileScanEvents, x)
		// Trim to a small tail so items fly out quickly
		if len(m.fileScanEvents) > scanningViewportLines*3 {
			m.fileScanEvents = m.fileScanEvents[len(m.fileScanEvents)-scanningViewportLines*3:]
		}
		// Track total files dynamically: when we first see a start for a path, bump totalFiles.
		if !x.Complete && x.Path != "" {
			if m._seenStarts == nil {
				m._seenStarts = make(map[string]struct{})
			}
			if _, ok := m._seenStarts[x.Path]; !ok {
				m._seenStarts[x.Path] = struct{}{}
				m.totalFiles++
			}
		}
		if x.Complete {
			m.filesScanned++
		}
		// Update progress percentage if we know total files.
		if m.totalFiles > 0 {
			pct := float64(m.filesScanned) / float64(m.totalFiles)
			_ = m.progress.SetPercent(pct)
			// If we've scanned everything, immediately switch to results view.
			if m.filesScanned >= m.totalFiles {
				m.scanCompleted = true
				_ = m.progress.SetPercent(1.0)
				m.syncResultsListItems()
			}
		}
		return m, m.listenForFileResults()

	case scanCompleteMsg:
		m.scanCompleted = true
		_ = m.progress.SetPercent(1.0)
		m.syncResultsListItems()
		return m, nil
	}

	return m, nil
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
