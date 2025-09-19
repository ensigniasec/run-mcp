package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
)

func (m Model) View() string {
	if m.quitting {
		return "Shutting down...\n"
	}

	left := runMCPBanner()
	leftWidth := lipgloss.Width(left)
	leftHeight := lipgloss.Height(left)
	if leftHeight == 0 {
		leftHeight = 20
	}
	gap := 2

	right := renderMainContent(m)

	// Constrain right to the same height as the banner, with footer pinned at bottom.
	rightStyled := lipgloss.NewStyle().Height(leftHeight).Render(
		pinFooter(right, renderFooter(), leftHeight),
	)

	// If we have a window width, size the right column but cap to 90 cols.
	if m.width > 0 && m.width > leftWidth+gap {
		available := m.width - leftWidth - gap
		if available < 1 {
			available = 1
		}
		if available > rightViewportMax {
			available = rightViewportMax
		}
		rightStyled = lipgloss.NewStyle().MarginLeft(gap).Width(available).Height(leftHeight).Render(
			pinFooter(right, renderFooter(), leftHeight),
		)
		return lipgloss.JoinHorizontal(lipgloss.Top, left, rightStyled)
	}

	// Fallback to vertical stacking if we don't yet know the window or it's too small.
	var b strings.Builder
	b.WriteString(left)
	b.WriteString("\n")
	b.WriteString(rightStyled)
	return b.String()
}

func renderMainContent(m Model) string {
	var b strings.Builder
	if m.helpVisible {
		b.WriteString(renderHelp(m))
		b.WriteString("\n\n")
	}
	b.WriteString(renderHeader())
	b.WriteString("\n")

	// Compute right column width similar to View and cap to 90.
	leftBanner := runMCPBanner()
	leftWidth := lipgloss.Width(leftBanner)
	leftHeight := lipgloss.Height(leftBanner)
	if leftHeight == 0 {
		leftHeight = 20
	}
	gap := 2
	rightMax := rightViewportMax // fallback/maximum target width
	if m.width > 0 && m.width > leftWidth+gap {
		available := m.width - leftWidth - gap
		if available < rightMax {
			rightMax = available
		}
		if rightMax < 1 {
			rightMax = 1
		}
	}

	// Countdown (left) and mode badge (right), aligned to right column width.
	countdown := renderCountdown(m.deadline, m.now)
	mode := modeBadge(m)
	pad := rightMax - lipgloss.Width(countdown) - lipgloss.Width(mode)
	if pad < 1 {
		pad = 1
	}
	b.WriteString(countdown)
	b.WriteString(strings.Repeat(" ", pad))
	b.WriteString(mode)
	b.WriteString("\n")

	// Progress bar widened to right column width, with explicit percent computation.
	mCopy := m
	mCopy.progress.Width = rightMax
	b.WriteString(renderProgress(mCopy))
	b.WriteString("\n\n")

	// Scanning subview (package-manager style) before results are ready
	if !m.scanCompleted {
		b.WriteString(renderScanningList(m))
	} else {
		// Build list items from hosts (already filtered to OK in applyResult).
		items := make([]list.Item, 0, len(m.hosts))
		for _, h := range m.hosts {
			items = append(items, resultItem{ID: h.ID, Name: h.Name, Status: h.Status, Message: h.LastMessage, ErrText: h.Error})
		}
		lst := m.resultsList
		lst.SetItems(items)
		// Constrain list height to fit within the banner height minus header/progress lines.
		// Header+countdown+progress+spacer roughly consume listOverheadLines; keep at least listMinHeight for list.
		listHeight := leftHeight - listOverheadLines
		if listHeight < listMinHeight {
			listHeight = listMinHeight
		}
		lst.SetSize(rightMax, listHeight)
		b.WriteString(lst.View())
	}

	return b.String()
}

func pinFooter(content string, footer string, totalHeight int) string {
	// Ensure content + footer equals totalHeight by padding content with newlines.
	contentLines := strings.Count(content, "\n")
	footerLines := strings.Count(footer, "\n") + 1 // footer will add a trailing newline
	// Keep at least one blank line between content and footer if space allows.
	minSpacing := 1
	needed := totalHeight - (contentLines + footerLines + minSpacing)
	if needed < 0 {
		needed = 0
	}
	var b strings.Builder
	b.WriteString(content)
	b.WriteString(strings.Repeat("\n", minSpacing+needed))
	b.WriteString(footer)
	return b.String()
}

func renderHeader() string {
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("Security Scanner for MCP Servers\n")
	return subtitle
}

func renderCountdown(deadline, now time.Time) string {
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	return fmt.Sprintf("⏰ Time remaining: %s", style.Render(remaining.Truncate(time.Second).String()))
}

func modeBadge(m Model) string {
	style := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch {
	case m.offline && m.anonymous:
		return style.Foreground(lipgloss.Color("208")).Render("OFFLINE • ANON")
	case m.offline:
		return style.Foreground(lipgloss.Color("208")).Render("OFFLINE")
	case m.anonymous:
		return style.Foreground(lipgloss.Color("69")).Render("ANON")
	default:
		return style.Foreground(lipgloss.Color("46")).Render("ONLINE")
	}
}

func renderProgress(m Model) string {
	// Prefer file-based progress when we have totals (covers scanning and root scans).
	if m.totalFiles > 0 {
		pct := float64(m.filesScanned) / float64(m.totalFiles)
		if pct > 1 {
			pct = 1
		}
		_ = m.progress.SetPercent(pct)
		return m.progress.View()
	}
	// After scanning, compute based on host completion.
	total := len(m.hosts)
	if total == 0 {
		return m.progress.View()
	}
	completed := m.completedCount
	if completed > total {
		completed = total
	}
	pct := float64(completed) / float64(total)
	cmd := m.progress.SetPercent(pct)
	// ignore returned cmd in pure render
	_ = cmd
	return m.progress.View()
}

func renderResults(m Model) string { //nolint:funlen,gocognit,gocyclo,cyclop WIP code
	var b strings.Builder
	if len(m.hosts) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("No hosts yet. Streaming results will appear here."))
		return b.String()
	}
	// Compute right column width to right-justify the message, capped to 90.
	leftWidth := lipgloss.Width(runMCPBanner())
	gap := 2
	rightMax := rightViewportMax
	if m.width > 0 && m.width > leftWidth+gap {
		available := m.width - leftWidth - gap
		if available < rightMax {
			rightMax = available
		}
		if rightMax < 1 {
			rightMax = 1
		}
	}
	for i, h := range m.hosts {
		sel := "  "
		if i == m.selectedIndex {
			sel = "> "
		}
		status := renderStatus(h.Status)
		msg := h.LastMessage
		left := fmt.Sprintf("%s%02d. %s", sel, i+1, h.Name)
		// Right column combines message then status icon at the very end.
		right := msg
		if right == "" {
			right = ""
		}
		rightWithIcon := right
		if status != "" {
			// Ensure a space before icon if message present.
			if rightWithIcon != "" {
				rightWithIcon += " "
			}
			rightWithIcon += status
		}
		remaining := rightMax - lipgloss.Width(left) - lipgloss.Width(rightWithIcon)
		if remaining < 1 {
			remaining = 1
		}
		b.WriteString(left)
		b.WriteString(strings.Repeat(" ", remaining))
		b.WriteString(rightWithIcon)
		if m.verbose && h.Error != "" {
			b.WriteString("\n    ")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(h.Error))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderStatus(s Status) string {
	switch s {
	case Pending:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("⏳ PENDING")
	case Running:
		return "… RUNNING"
	case OK:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("✅ OK")
	case Fail:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("❌ FAIL")
	case Timeout:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("⏰ TIMEOUT")
	default:
		return ""
	}
}

func renderFooter() string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("esc/q: quit • s: sort • r: repoll • ↑/↓ or j/k: move • h/?: help")
}

func renderHelp(m Model) string {
	border := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).Padding(0, 1).Foreground(lipgloss.Color("69"))
	content := []string{
		"Help",
		"",
		"h/?: toggle this help",
		"q/ctrl+c: quit",
		"s: cycle sort (status, duration, name)",
		"r: repoll failed/timeouts (future)",
	}
	return border.Render(strings.Join(content, "\n"))
}

func renderScanningList(m Model) string {
	// TODO BUG: long lines wrap over two lines and cause UI to jump around. Make max 1 line with ... if needed.
	// Show file scan events with icons, similar to package-manager example.
	// ✓ green for server(s) found, ↷ gray for none/skipped, ✗ red for errors; spinner is omitted for simplicity.
	var b strings.Builder
	// Only render the last scanningViewportLines events for a small, fast viewport
	start := len(m.fileScanEvents) - scanningViewportLines
	if start < 0 {
		start = 0
	}
	for i := start; i < len(m.fileScanEvents); i++ {
		e := m.fileScanEvents[i]
		icon := "↷"
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		if e.Err != nil {
			icon = "✗"
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
		} else if e.Found {
			icon = "✓"
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
		}
		// Only show icon + path; avoid dumping error text for a clean UI
		b.WriteString(style.Render(fmt.Sprintf(" %s %s", icon, e.Path)))
		if e.Complete && e.Err == nil && !e.Found {
			b.WriteString(style.Render(" (none)"))
		}
		b.WriteString("\n")
	}
	return b.String()
}
