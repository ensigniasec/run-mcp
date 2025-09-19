package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// ScanResult represents the results for an entire Scan across all targets.
type ScanResult struct {
	Targets        []string        `json:"targets"`
	Files          []FileResult    `json:"files"`
	Servers        []ServerConfig  `json:"servers,omitempty"`
	SecretFindings []SecretFinding `json:"secret_findings,omitempty"`

	StartedAt   time.Time     `json:"started_at"`
	Duration    time.Duration `json:"duration,omitempty"`
	CompletedAt time.Time     `json:"completed_at,omitempty"`

	Summary *ScanSummary `json:"summary,omitempty"`
}

func NewScanResult(targets []string) *ScanResult {
	sr := new(ScanResult)
	sr.Targets = targets
	sr.StartedAt = time.Now()
	return sr
}

func NewFileResult(path string) *FileResult {
	fr := new(FileResult)
	fr.Path = path
	return fr
}

type MCPScanner struct {
	seenFiles         map[string]struct{}
	targets           []string
	storageFile       string
	ScanResult        *ScanResult
	collector         *RatingsCollector
	streamingCallback func(filePath string, fileResult *FileResult, err error)
}

func NewMCPScanner(targets []string, storageFile string) *MCPScanner {
	return &MCPScanner{
		targets: targets,
		seenFiles: make(
			map[string]struct{},
		), // using a struct{} instead of bool here - as it is a zero-byte value & we only care about the key,
		storageFile: storageFile,
		ScanResult:  NewScanResult(targets),
	}
}

// WithRatingsCollector sets the ratings collector for live enrichment.
func (s *MCPScanner) WithRatingsCollector(rc *RatingsCollector) *MCPScanner { //nolint:ireturn
	s.collector = rc
	return s
}

// WithStreamingCallback sets a callback for real-time file processing updates.
func (s *MCPScanner) WithStreamingCallback(callback func(filePath string, fileResult *FileResult, err error)) *MCPScanner { //nolint:ireturn
	s.streamingCallback = callback
	return s
}

//nolint:gocognit // Scanning logic is explicit for clarity; future refactor may split by phases.
func (s *MCPScanner) Scan() (*ScanResult, error) {
	logrus.Debug("Starting scan of ", len(s.targets), " targets")
	// Defensive reset of per-scan aggregations while preserving targets and start time
	s.ScanResult.Files = nil
	s.ScanResult.Servers = nil
	s.ScanResult.SecretFindings = nil

	// Stream discovered files and process immediately.
	processFile := func(filePath string) {
		if _, ok := s.seenFiles[filePath]; ok {
			return
		}
		s.seenFiles[filePath] = struct{}{}

		// Emit a 'started' streaming event prior to scanning for real-time UIs.
		if s.streamingCallback != nil {
			s.streamingCallback(filePath, nil, nil)
		}

		fileResult, err := s.scanFile(filePath)

		// Call streaming callback if provided (before error handling)
		if s.streamingCallback != nil {
			s.streamingCallback(filePath, fileResult, err)
		}

		if err != nil {
			if os.IsNotExist(err) {
				logrus.Debugf("File not found: %s", filePath)
			} else {
				logrus.Errorf("Error scanning file %s: %v", filePath, err)
			}
			return
		}
		// Append individualfile result
		s.ScanResult.Files = append(s.ScanResult.Files, *fileResult)
		// Aggregate servers at top-level (findings appended during parse/redact)
		if len(fileResult.Servers) > 0 {
			s.ScanResult.Servers = append(s.ScanResult.Servers, fileResult.Servers...)
		}
	}

	ctx := context.Background()
	for _, target := range s.targets {
		st, err := os.Stat(target)
		if err != nil {
			logrus.Debugf("Skipping target %s due to error: %v", target, err)
			continue
		}
		// Early skip for top-level directories like .ssh, .git, node_modules, etc.
		if st.IsDir() && isSkippedDir(filepath.Base(target)) {
			logrus.Debugf("Skipping directory %s due to skip rules", target)
			continue
		}

		if !st.IsDir() {
			processFile(target)
			continue
		}

		for p := range streamConfigFiles(ctx, target) {
			processFile(p)
		}
	}

	// Finalize timing
	s.ScanResult.CompletedAt = time.Now()
	s.ScanResult.Duration = s.ScanResult.CompletedAt.Sub(s.ScanResult.StartedAt)

	logrus.Debug("Scan completed successfully")
	return s.ScanResult, nil
}

func (s *MCPScanner) scanFile(path string) (*FileResult, error) {
	logrus.Debug("Scanning file: ", path)

	fileResult := new(FileResult)
	fileResult.Path = path

	// Capture current secret findings count to attribute new findings to this file
	prevFindingsCount := len(s.ScanResult.SecretFindings)

	config, err := s.ParseMCPConfigFile(path)
	if err != nil || config == nil {
		logrus.Debugf("Could not parse file, or no MCP configuration found: %v", err)
		return fileResult, err
	}

	servers := config.GetServers()

	for name, serverData := range servers {
		serverScanResult := &ServerConfig{Name: name, Server: serverData}
		fileResult.Servers = append(fileResult.Servers, *serverScanResult)

		// Print the server configuration.
		logrus.Debugf("Found server: %s", name)
		if serverJSON, err := json.MarshalIndent(serverData, "  ", "  "); err == nil {
			logrus.Debugf("Configuration:\n%s", string(serverJSON))
		}

		// Submit identifiers for live batched ratings.
		if s.collector != nil {
			s.collector.Submit(name, serverData)
		}
	}

	// Attribute newly discovered secrets from this parse to this file result
	if newCount := len(s.ScanResult.SecretFindings) - prevFindingsCount; newCount > 0 {
		fileResult.SecretFindings = append(
			fileResult.SecretFindings,
			s.ScanResult.SecretFindings[prevFindingsCount:]...,
		)
	}

	return fileResult, nil
}
