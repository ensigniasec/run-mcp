package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/stopwatch"
	"github.com/charmbracelet/bubbles/timer"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
)

// TUI dimension constants.
const (
	defaultTUIWidth      = 80
	defaultTUIHeight     = 24
	progressMargin       = 20
	progressMaxWidth     = 60
	resultsChannelBuffer = 100
	stopwatchInterval    = 100 // milliseconds
	percentageMultiplier = 100

	// Color constants.
	cyanColor      = "63"  // cyan
	grayColor      = "241" // gray
	redColor       = "196" // red
	orangeColor    = "33"  // orange
	greenColor     = "46"  // green
	yellowColor    = "226" // yellow
	orange208Color = "208" // orange variant
	gray240Color   = "240" // gray variant

	// Risk score thresholds.
	criticalRiskThreshold = 9.0
	indexOffset           = 1 // For 1-based indexing in display

	// Timing constants for simulation.
	tUIInitDelay      = 50  // milliseconds
	scanningDelay     = 300 // milliseconds
	completionStagger = 50  // milliseconds
)

// FileStatus represents the state of a file being scanned.
type FileStatus struct {
	Path        string
	State       apigen.ScanTargetStatus
	Spinner     spinner.Model
	Results     []ServerReport
	Errors      []string
	StartedAt   time.Time
	CompletedAt time.Time
}

// ScanPhase represents the current phase of the TUI.
type ScanPhase int

const (
	PhaseScanning ScanPhase = iota // Phase 1: Package-manager style file scanning
	PhaseResults                   // Phase 2: Table of servers with spinners
)

// ScanTUIModel represents the main TUI model.
type ScanTUIModel struct {
	// Overall scan state
	deadline     time.Time
	timer        timer.Model
	progress     progress.Model
	scannedCount int // Simple counter of files scanned
	phase        ScanPhase

	// Phase 1: File scanning tracking
	files           map[string]*FileStatus
	fileOrder       []string        // to maintain display order
	currentFile     string          // Currently being scanned (for scrolling display)
	completedFiles  []string        // Recently completed files (for scrolling effect)
	globalStopwatch stopwatch.Model // Single stopwatch for entire scan

	// Phase 2: Server results tracking
	servers     map[string]*ServerResult // Deduplicated servers
	serverOrder []string                 // Display order for servers

	// Streaming results
	resultsChan chan FileScanResult
	done        bool
	width       int
	height      int

	// UI state
	showResults bool
	quitting    bool
}

// ServerResult represents a deduplicated MCP server with aggregated data.
type ServerResult struct {
	Name        string
	Sources     []string // Which files this server was found in
	Spinner     spinner.Model
	Stopwatch   stopwatch.Model
	Rating      *apigen.SecurityRating
	State       apigen.ScanTargetStatus
	StartedAt   time.Time
	CompletedAt time.Time
}

// FileScanResult represents a result received from scanning.
type FileScanResult struct {
	FilePath string
	Servers  []ServerReport
	Error    error
	Complete bool
}

// NewScanTUI creates a new TUI model.
func NewScanTUI(filePaths []string, deadline time.Duration) *ScanTUIModel {
	// Initialize timer for deadline countdown
	t := timer.NewWithInterval(deadline, time.Second)

	// Initialize progress bar
	p := progress.New(progress.WithDefaultGradient())
	p.Width = 40

	// Initialize global stopwatch for Phase 1
	globalSw := stopwatch.NewWithInterval(time.Millisecond * stopwatchInterval)

	// Initialize file statuses (simplified without individual stopwatches)
	fileStatuses := make(map[string]*FileStatus)
	for _, filePath := range filePaths {
		s := spinner.New()
		s.Spinner = spinner.Dot
		s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(cyanColor))

		fileStatuses[filePath] = &FileStatus{
			Path:    filePath,
			State:   apigen.Queued,
			Spinner: s,
			Results: []ServerReport{},
			Errors:  []string{},
		}
	}

	// Initialize server tracking for Phase 2
	servers := make(map[string]*ServerResult)
	serverOrder := make([]string, 0)

	return &ScanTUIModel{
		deadline:        time.Now().Add(deadline),
		timer:           t,
		progress:        p,
		scannedCount:    0,
		phase:           PhaseScanning,
		files:           fileStatuses,
		fileOrder:       filePaths,
		completedFiles:  make([]string, 0),
		globalStopwatch: globalSw,
		servers:         servers,
		serverOrder:     serverOrder,
		resultsChan:     make(chan FileScanResult, resultsChannelBuffer),
		width:           defaultTUIWidth,
		height:          defaultTUIHeight,
	}
}

// Init implements tea.Model.
func (m ScanTUIModel) Init() tea.Cmd {
	var cmds []tea.Cmd

	// Start the timer
	cmds = append(cmds, m.timer.Init())

	// Start all spinners and stopwatches.
	for _, file := range m.files {
		cmds = append(cmds, file.Spinner.Tick)
		// File stopwatch removed - using global stopwatch instead
	}

	// Start listening for results.
	cmds = append(cmds, m.waitForResults())

	return tea.Batch(cmds...)
}

// waitForResults creates a command to listen for incoming scan results.
func (m ScanTUIModel) waitForResults() tea.Cmd {
	return func() tea.Msg {
		select {
		case result := <-m.resultsChan:
			return result
		default:
			return nil
		}
	}
}

// Update implements tea.Model.
//
//nolint:mnd,gocognit,gocyclo,cyclop,funlen // WIP code: allow magic numbers and complexity in TUI update handler
func (m ScanTUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = min(m.width-progressMargin, progressMaxWidth)

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "r":
			m.showResults = !m.showResults
		}

	case timer.TickMsg:
		var cmd tea.Cmd
		m.timer, cmd = m.timer.Update(msg)
		cmds = append(cmds, cmd)

		// Update progress bar based on time elapsed (not file count)
		elapsed := time.Since(m.deadline.Add(-30 * time.Second)) // 30s is our deadline
		timeProgress := elapsed.Seconds() / 30.0                 //nolint:mnd // WIP code
		if timeProgress > 1.0 {
			timeProgress = 1.0
		}
		cmds = append(cmds, m.progress.SetPercent(timeProgress))

		if m.timer.Timedout() {
			m.done = true
			// Accelerate progress to 100% when timeout
			cmds = append(cmds, m.progress.SetPercent(1.0))
		}

	case timer.TimeoutMsg:
		m.done = true
		// Accelerate progress to 100% when timeout
		cmds = append(cmds, m.progress.SetPercent(1.0))

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		if p, ok := progressModel.(progress.Model); ok {
			m.progress = p
		}
		cmds = append(cmds, cmd)

	case FileScanResult:
		// Update file status based on result.
		if file, exists := m.files[msg.FilePath]; exists {
			if msg.Complete {
				file.State = apigen.Completed
				file.CompletedAt = time.Now()
				m.scannedCount++

				// Clear current file if this was the current one
				if m.currentFile == msg.FilePath {
					m.currentFile = ""
				}

				// Add to completed files for scrolling display in Phase 1
				m.completedFiles = append(m.completedFiles, msg.FilePath)
				// Keep only the last few for scrolling effect
				if len(m.completedFiles) > 5 { //nolint:mnd // WIP code
					m.completedFiles = m.completedFiles[1:]
				}

				// Process and deduplicate servers
				if msg.Error == nil {
					m.processServersFromFile(msg.FilePath, msg.Servers)
				}
			} else if file.State == apigen.Queued {
				file.State = apigen.Running
				file.StartedAt = time.Now()
				m.currentFile = msg.FilePath // Set current file for display
				// Start global stopwatch if this is the first file
				if m.scannedCount == 0 {
					cmds = append(cmds, m.globalStopwatch.Start())
				}
			}

			if msg.Error != nil {
				file.State = apigen.Failed
				file.Errors = append(file.Errors, msg.Error.Error())
			} else {
				file.Results = append(file.Results, msg.Servers...)
			}
		}

		// Continue listening for more results.
		cmds = append(cmds, m.waitForResults())

		// Transition to Phase 2 when scan completes (timeout or explicit finish signal)
		if m.done && m.phase == PhaseScanning {
			m.phase = PhaseResults
			m.currentFile = "" // Clear current file when transitioning
			// Accelerate progress to 100% when finishing early
			cmds = append(cmds, m.progress.SetPercent(1.0))
			// Start server spinners in Phase 2
			for _, server := range m.servers {
				if server.State == apigen.Queued {
					server.State = apigen.Running
					server.StartedAt = time.Now()
					cmds = append(cmds, server.Spinner.Tick)
					cmds = append(cmds, server.Stopwatch.Start())
				}
			}
		}

	case spinner.TickMsg:
		// Update all file spinners (Phase 1)
		for _, file := range m.files {
			var cmd tea.Cmd
			file.Spinner, cmd = file.Spinner.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

		// Update all server spinners (Phase 2)
		for _, server := range m.servers {
			var cmd tea.Cmd
			server.Spinner, cmd = server.Spinner.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

	case stopwatch.TickMsg:
		// Update global stopwatch (Phase 1) and server stopwatches (Phase 2)
		if m.phase == PhaseScanning {
			var cmd tea.Cmd
			m.globalStopwatch, cmd = m.globalStopwatch.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		} else {
			// Update server stopwatches in Phase 2
			for _, server := range m.servers {
				if server.State == apigen.Running {
					var cmd tea.Cmd
					server.Stopwatch, cmd = server.Stopwatch.Update(msg)
					if cmd != nil {
						cmds = append(cmds, cmd)
					}
				}
			}
		}
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model.
func (m ScanTUIModel) View() string {
	if m.quitting {
		return "Shutting down...\n"
	}

	var b strings.Builder

	// Header with ASCII art.
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Deadline timer.
	b.WriteString(m.renderDeadline())
	b.WriteString("\n")

	// Render based on current phase
	switch m.phase {
	case PhaseScanning:
		// Phase 1: Package-manager style file scanning
		b.WriteString(m.renderScanningPhase())
	case PhaseResults:
		// Phase 2: Server table with spinners
		b.WriteString(m.renderResultsPhase())
	}

	// Footer with controls.
	b.WriteString("\n")
	b.WriteString(m.renderFooter())

	return b.String()
}

func (m ScanTUIModel) renderHeader() string {
	// Simple text-based header for better terminal compatibility
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(cyanColor)).
		Render("RUN-MCP")

	subtitle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(grayColor)).
		Render("Security Scanner for MCP Servers")

	return fmt.Sprintf("%s\n%s", title, subtitle)
}

func (m ScanTUIModel) renderDeadline() string {
	remaining := m.timer.View()

	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(redColor)).
		Bold(true)

	// Show scanning status based on phase
	switch m.phase {
	case PhaseScanning:
		if m.done {
			return style.Render("⏰ SCAN COMPLETE - Processing servers...")
		}
		return fmt.Sprintf("⏰ Scanning files... (%s remaining)", style.Render(remaining))
	case PhaseResults:
		if m.done && len(m.servers) == 0 {
			return style.Render("⏰ SCAN COMPLETE")
		}
		return style.Render("⏰ Fetching server ratings...")
	default:
		return fmt.Sprintf("⏰ Time remaining: %s", style.Render(remaining))
	}
}

// renderProgress is now integrated into renderScanningPhase

// renderFiles is replaced by renderScanningPhase package-manager style

// renderResults removed - replaced by renderResultsPhase

// renderScanningPhase renders Phase 1: Package-manager style file scanning.
func (m ScanTUIModel) renderScanningPhase() string {
	var b strings.Builder

	// Global progress bar (time-based, not file-based)
	progressBar := m.progress.View()

	b.WriteString(fmt.Sprintf("📁 Files Scanned: %d\n", m.scannedCount))
	b.WriteString(progressBar)
	b.WriteString("\n\n")

	// Current file being scanned (package-manager style)
	if m.currentFile != "" {
		currentStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(cyanColor)).
			Bold(true)
		b.WriteString("Currently scanning: ")
		b.WriteString(currentStyle.Render(m.currentFile))
		b.WriteString("\n\n")
	}

	// Recently completed files (scrolling effect)
	if len(m.completedFiles) > 0 {
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color(grayColor)).
			Render("Recently completed:"))
		b.WriteString("\n")

		for _, file := range m.completedFiles {
			b.WriteString("  ✓ ")
			b.WriteString(lipgloss.NewStyle().
				Foreground(lipgloss.Color(greenColor)).
				Render(file))
			b.WriteString("\n")
		}
	}

	return b.String()
}

// renderResultsPhase renders Phase 2: Server table with spinners.
func (m ScanTUIModel) renderResultsPhase() string {
	var b strings.Builder

	// Results header
	b.WriteString(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(orangeColor)).
		Render(fmt.Sprintf("🔍 Discovered Servers (%d found)", len(m.servers))))
	b.WriteString("\n\n")

	if len(m.servers) == 0 {
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color(grayColor)).
			Render("No MCP servers found in scanned files."))
		b.WriteString("\n")
		return b.String()
	}

	// Server table
	for i, serverName := range m.serverOrder {
		server := m.servers[serverName]

		// Status indicator
		var indicator string
		switch server.State {
		case apigen.Queued:
			indicator = lipgloss.NewStyle().Foreground(lipgloss.Color(gray240Color)).Render("⏳ PENDING")
		case apigen.Running:
			indicator = fmt.Sprintf("%s RATING", server.Spinner.View())
		case apigen.Completed:
			indicator = lipgloss.NewStyle().Foreground(lipgloss.Color(greenColor)).Render("✅ RATED")
		case apigen.Failed:
			indicator = lipgloss.NewStyle().Foreground(lipgloss.Color(redColor)).Render("❌ FAILED")
		case apigen.Skipped:
			indicator = lipgloss.NewStyle().Foreground(lipgloss.Color(gray240Color)).Render("⤼ SKIPPED")
		default:
			indicator = lipgloss.NewStyle().Foreground(lipgloss.Color(gray240Color)).Render("❓ UNKNOWN")
		}

		// Server info
		sourceCount := len(server.Sources)
		sourceInfo := fmt.Sprintf(" (found in %d file%s)", sourceCount,
			map[bool]string{true: "s", false: ""}[sourceCount != 1])

		// Rating info using A-F grade system
		ratingInfo := ""
		if server.Rating != nil {
			gradeStr := string(server.Rating.Scores.OverallGrade)
			switch server.Rating.Scores.OverallGrade {
			case apigen.F, apigen.D:
				ratingInfo = lipgloss.NewStyle().
					Foreground(lipgloss.Color(redColor)).
					Render(fmt.Sprintf(" ⚠️ Grade %s", gradeStr))
			case apigen.C2, apigen.C1, apigen.C:
				ratingInfo = lipgloss.NewStyle().
					Foreground(lipgloss.Color(orange208Color)).
					Render(fmt.Sprintf(" 🟠 Grade %s", gradeStr))
			case apigen.B2, apigen.B1, apigen.B:
				ratingInfo = lipgloss.NewStyle().
					Foreground(lipgloss.Color(yellowColor)).
					Render(fmt.Sprintf(" 🟡 Grade %s", gradeStr))
			case apigen.A2, apigen.A1, apigen.A:
				ratingInfo = lipgloss.NewStyle().
					Foreground(lipgloss.Color(greenColor)).
					Render(fmt.Sprintf(" 🟢 Grade %s", gradeStr))
			}
		}

		line := fmt.Sprintf("  %02d. %-25s %s%s%s",
			i+indexOffset, serverName, indicator, sourceInfo, ratingInfo)
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

func (m ScanTUIModel) renderFooter() string {
	switch m.phase {
	case PhaseScanning:
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Render("Press 'q' to quit • Scanning files...")
	case PhaseResults:
		if m.done {
			return lipgloss.NewStyle().
				Foreground(lipgloss.Color(grayColor)).
				Render("Press 'q' to quit • Scan complete")
		}
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Render("Press 'q' to quit • Fetching ratings...")
	default:
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color(grayColor)).
			Render("Press 'q' to quit")
	}
}

// processServersFromFile processes servers found in a file and deduplicates them.
func (m *ScanTUIModel) processServersFromFile(filePath string, servers []ServerReport) {
	for _, server := range servers {
		serverName := server.Name
		if existing, exists := m.servers[serverName]; exists {
			// Server already exists, add this file as a source
			existing.Sources = append(existing.Sources, filePath)
		} else {
			// Create new server entry
			s := spinner.New()
			s.Spinner = spinner.Dot
			s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(cyanColor))

			sw := stopwatch.NewWithInterval(time.Millisecond * stopwatchInterval)

			serverResult := &ServerResult{
				Name:      serverName,
				Sources:   []string{filePath},
				Spinner:   s,
				Stopwatch: sw,
				Rating:    nil, // Will be populated by ratings collector in Phase 2
				State:     apigen.Queued,
			}

			m.servers[serverName] = serverResult
			m.serverOrder = append(m.serverOrder, serverName)
		}
	}
}

// SendResult sends a scan result to the TUI.
func (m *ScanTUIModel) SendResult(result FileScanResult) {
	select {
	case m.resultsChan <- result:
	default:
		// Channel full, skip.
	}
}

// RunTUI starts the Bubble Tea program.
func RunTUI(files []string, deadline time.Duration) (*ScanTUIModel, error) {
	model := NewScanTUI(files, deadline)

	p := tea.NewProgram(model, tea.WithAltScreen())

	go func() {
		_, _ = p.Run() // Error handling omitted for background goroutine
	}()

	return model, nil
}

// RunTUIWithSummary starts the TUI and simulates scanning with the provided results.
func RunTUIWithSummary(configPaths []string, summary ScanSummary) error {
	// Create a reasonable deadline for the demo (but shorter for snappiness)
	deadline := 15 * time.Second //nolint:mnd // WIP code
	model := NewScanTUI(configPaths, deadline)

	// Start the TUI
	p := tea.NewProgram(model, tea.WithAltScreen())

	// Simulate the scanning process immediately
	go simulateDynamicScanning(model, summary)

	// Run the TUI (blocks until quit)
	_, err := p.Run()
	return err
}

// simulateDynamicScanning provides a more dynamic, responsive scanning simulation.
func simulateDynamicScanning(model *ScanTUIModel, summary ScanSummary) {
	// Immediate start - no delay for maximum responsiveness

	// Group servers by config file path to simulate file-based scanning
	fileResults := make(map[string][]ServerReport)
	for _, server := range summary.Servers {
		filePath := server.Path
		if filePath == "" {
			filePath = "unknown" //nolint:goconst // WIP code
		}
		fileResults[filePath] = append(fileResults[filePath], server)
	}

	// Start all files scanning immediately for dynamic feel
	for filePath := range fileResults {
		model.SendResult(FileScanResult{
			FilePath: filePath,
			Servers:  nil,
			Error:    nil,
			Complete: false,
		})
	}

	// Small delay to show spinners, then complete files rapidly
	time.Sleep(scanningDelay * time.Millisecond)

	// Complete files in quick succession for streaming feel
	for filePath, servers := range fileResults {
		model.SendResult(FileScanResult{
			FilePath: filePath,
			Servers:  servers,
			Error:    nil,
			Complete: true,
		})
		// Very short stagger between completions for dynamic effect
		time.Sleep(completionStagger * time.Millisecond)
	}
}

// RunTUIWithRealTimeScanning starts the TUI immediately and performs real-time scanning.
func RunTUIWithRealTimeScanning(configPaths []string, scanner *MCPScanner, collector *RatingsCollector) error {
	// Create a reasonable deadline for real scanning
	deadline := 30 * time.Second //nolint:mnd // WIP code
	model := NewScanTUI(configPaths, deadline)

	// Start the TUI in full-screen mode immediately - this is the key!
	p := tea.NewProgram(model, tea.WithAltScreen())

	// Start real-time scanning in background immediately
	go performRealTimeScanning(model, scanner, collector)

	// Run the TUI (blocks until quit) - user sees results streaming in real-time
	_, err := p.Run()
	return err
}

// performRealTimeScanning performs actual scanning and streams results directly to TUI.
func performRealTimeScanning(model *ScanTUIModel, scanner *MCPScanner, collector *RatingsCollector) {
	// Set up streaming callback to receive real-time updates
	scanner.WithStreamingCallback(func(filePath string, fileResult *FileResult, err error) {
		if err != nil {
			// Stream error immediately to TUI
			model.SendResult(FileScanResult{
				FilePath: filePath,
				Servers:  nil,
				Error:    err,
				Complete: true,
			})
			return
		}

		// Convert to ServerReports and apply ratings if available
		var serverReports []ServerReport
		if fileResult != nil {
			for _, serverConfig := range fileResult.Servers {
				serverReport := ServerReport{
					Name: serverConfig.Name,
					Path: filePath,
					// Rating will be applied by collector if available
				}
				serverReports = append(serverReports, serverReport)
			}
		}

		// Stream completion immediately to TUI
		model.SendResult(FileScanResult{
			FilePath: filePath,
			Servers:  serverReports,
			Error:    nil,
			Complete: true,
		})
	})

	// Use the original Scan method which now calls our streaming callback
	_, err := scanner.Scan()
	if err != nil {
		// Send error result for any failed targets
		for _, target := range scanner.targets {
			model.SendResult(FileScanResult{
				FilePath: target,
				Servers:  nil,
				Error:    err,
				Complete: true,
			})
		}
		return
	}

	// Cleanup collector
	collector.FlushAndStop()
}

// Helper function for min.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
