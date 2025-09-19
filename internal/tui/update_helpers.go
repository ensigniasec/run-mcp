package tui

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

// handleKey processes key bindings and returns updated model and command.
func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) { // nolint:ireturn
	switch {
	case key.Matches(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit

	case key.Matches(msg, m.keys.Help):
		m.helpVisible = !m.helpVisible
		return m, nil

	case key.Matches(msg, m.keys.Sort):
		m.sortMode = (m.sortMode + 1) % sortModesCount
		return m, nil

	case key.Matches(msg, m.keys.Repoll):
		return m, nil
	}

	return m, nil
}

// jumpToNextProblem moves selection to the next failing/timeout host.
func (m *Model) jumpToNextProblem() {
	total := len(m.hosts)
	if total == 0 {
		return
	}
	for i := 1; i <= total; i++ {
		idx := (m.selectedIndex + i) % total
		if m.hosts[idx].Status == Fail || m.hosts[idx].Status == Timeout {
			m.selectedIndex = idx
			return
		}
	}
}

// markTimeouts marks pending/running hosts as timed out and updates counters.
func (m *Model) markTimeouts() {
	for i := range m.hosts {
		if m.hosts[i].Status == Pending || m.hosts[i].Status == Running {
			m.hosts[i].Status = Timeout
			m.failedCount++
		}
	}
}

// applyResult upserts a host row from a results message and updates counters.
func (m *Model) applyResult(x resultsMsg) {
	// Allow intermediate Running statuses to appear and update messages
	if x.Status == Running {
		for i := range m.hosts {
			if m.hosts[i].ID == x.HostID {
				m.hosts[i].Status = x.Status
				m.hosts[i].LastMessage = x.Message
				return
			}
		}
		m.hosts = append(m.hosts, HostRow{ID: x.HostID, Name: x.HostID, Status: x.Status, LastMessage: x.Message, Error: errString(x.Err)})
		return
	}
	// Only render OK discoveries as rows for final state.
	if x.Status != OK {
		m.bumpCounters(x.Status)
		return
	}
	for i := range m.hosts {
		if m.hosts[i].ID == x.HostID {
			m.hosts[i].Status = x.Status
			m.hosts[i].LastMessage = x.Message
			if x.Err != nil {
				m.hosts[i].Error = x.Err.Error()
			}
			m.bumpCounters(x.Status)
			return
		}
	}
	m.hosts = append(m.hosts, HostRow{ID: x.HostID, Name: x.HostID, Status: x.Status, LastMessage: x.Message, Error: errString(x.Err)})
	m.bumpCounters(x.Status)
}

func (m *Model) bumpCounters(status Status) {
	switch status {
	case Pending, Running:
		// No counters incremented for intermediate states.
	case OK:
		m.completedCount++
	case Fail, Timeout:
		m.failedCount++
	}
}

// syncResultsListItems rebuilds the list items from current hosts.
func (m *Model) syncResultsListItems() {
	items := make([]list.Item, 0, len(m.hosts))
	for _, h := range m.hosts {
		items = append(items, resultItem{ID: h.ID, Name: h.Name, Status: h.Status, Message: h.LastMessage, ErrText: h.Error})
	}
	m.resultsList.SetItems(items)
}
