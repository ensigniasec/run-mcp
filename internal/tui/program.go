package tui

import (
	"context"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/sirupsen/logrus"

	api "github.com/ensigniasec/run-mcp/internal/api"
	"github.com/ensigniasec/run-mcp/internal/scanner"
)

// Run starts the Bubble Tea TUI program, wiring the scanner stream to messages.
func Run(ctx context.Context, configPaths []string, s *scanner.MCPScanner, rc *scanner.RatingsCollector) error {
	// Shared results channel between adapter and model.
	resultsCh := make(chan resultsMsg, channelBufferSize)
	fileCh := make(chan fileScanMsg, channelBufferSize)

	// Build initial model – start with empty hosts; they will stream in.
	deadline := time.Now().Add(defaultDeadlineDuration)
	model := NewModel(deadline, nil, resultsCh, fileCh)

	// Determine mode flags for display.
	isOffline := rc == nil || rc.IsOffline()
	if id, ok := api.IdentityFromContext(ctx); !ok || id.Anonymous {
		model.anonymous = true
	}
	model.offline = isOffline

	// Wire collector stage notifiers to results updates (even if offline at start).
	if rc != nil {
		rc.WithStageNotifiers(
			func(serverName string) {
				resultsCh <- resultsMsg{HostID: serverName, Status: Running, Message: "submitted"}
			},
			func(serverName string) {
				resultsCh <- resultsMsg{HostID: serverName, Status: Running, Message: "processing"}
			},
			func(serverName string) {
				resultsCh <- resultsMsg{HostID: serverName, Status: OK, Message: "results received"}
			},
		)
	}

	// Bridge: stream file results to TUI messages.
	s.WithStreamingCallback(func(filePath string, fileResult *scanner.FileResult, err error) {
		handleFileCallback(fileCh, resultsCh, isOffline, filePath, fileResult, err)
	})

	p := tea.NewProgram(model, tea.WithAltScreen())

	// Silence external logs (WARN/ERRO) during TUI to avoid corrupting the view.
	prevOut := logrus.StandardLogger().Out
	logrus.SetOutput(io.Discard)
	defer logrus.SetOutput(prevOut)

	seedInitialFileEvents(fileCh, configPaths)

	// Start scan in background.
	go runScanAndFinalize(s, rc, fileCh)

	// Run TUI blocking in this goroutine.
	_, err := p.Run()
	return err
}

// handleFileCallback adapts scanner streaming callbacks into UI messages.
func handleFileCallback(fileCh chan fileScanMsg, resultsCh chan resultsMsg, isOffline bool, filePath string, fileResult *scanner.FileResult, err error) {
	if err != nil {
		fileCh <- fileScanMsg{Path: filePath, Complete: false}
		fileCh <- fileScanMsg{Path: filePath, Err: err, Complete: true}
		return
	}
	if fileResult == nil {
		fileCh <- fileScanMsg{Path: filePath, Complete: false}
		return
	}
	found := len(fileResult.Servers) > 0
	fileCh <- fileScanMsg{Path: filePath, Complete: false}
	fileCh <- fileScanMsg{Path: filePath, Found: found, Complete: true}
	for _, server := range fileResult.Servers {
		hostID := server.Name
		if isOffline {
			resultsCh <- resultsMsg{HostID: hostID, Status: OK, Message: "discovered (offline)"}
			continue
		}
		resultsCh <- resultsMsg{HostID: hostID, Status: Running, Message: "discovered"}
	}
}

// seedInitialFileEvents emits early started events for explicit file targets.
func seedInitialFileEvents(fileCh chan fileScanMsg, configPaths []string) {
	for _, path := range configPaths {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			fileCh <- fileScanMsg{Path: path, Complete: false}
		}
	}
}

// runScanAndFinalize runs the scan and performs finalization steps.
func runScanAndFinalize(s *scanner.MCPScanner, rc *scanner.RatingsCollector, fileCh chan fileScanMsg) {
	_, err := s.Scan()
	if err != nil {
		logrus.Debugf("scan error: %v", err)
	}
	if rc != nil {
		rc.FlushAndStop()
	}
	fileCh <- fileScanMsg{Path: "", Found: false, Complete: true}
}
