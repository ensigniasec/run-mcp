//nolint:testpackage // White-box tests require access to unexported identifiers in this package.
package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMCPScanner(t *testing.T) {
	files := []string{"test1.json", "test2.yaml"}
	storageFile := "/tmp/storage"

	scanner := NewMCPScanner(files, storageFile)

	assert.Equal(t, files, scanner.targets)
	assert.Equal(t, storageFile, scanner.storageFile)
}

func TestMCPScanner_Scan(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(thisFile)
	testdataDir := filepath.Join(baseDir, "..", "..", "testdata")

	tests := []struct {
		name            string
		testdataFiles   []string // Files from testdata to use
		expectedCount   int
		expectedServers map[string]int // filename -> expected server count
	}{
		{
			name:          "empty file list",
			testdataFiles: []string{},
			expectedCount: 0,
		},
		{
			name:          "single Claude config",
			testdataFiles: []string{"claude_desktop_config.json"},
			expectedCount: 1,
			expectedServers: map[string]int{
				"claude_desktop_config.json": 2, // filesystem + git
			},
		},
		{
			name:          "multiple valid configs",
			testdataFiles: []string{"claude_desktop_config.json", "vscode_settings.json", "continue_config.yaml"},
			expectedCount: 3,
			expectedServers: map[string]int{
				"claude_desktop_config.json": 2, // filesystem + git
				"vscode_settings.json":       2, // github + context7
				"continue_config.yaml":       2, // test_server + python_server
			},
		},
		{
			name:            "YAML configs",
			testdataFiles:   []string{"goose_config.yaml", "librechat.yaml"},
			expectedCount:   2,
			expectedServers: map[string]int{"goose_config.yaml": 3, "librechat.yaml": 2},
		},
		{
			name:          "config with no MCP servers",
			testdataFiles: []string{"empty_config.json"},
			expectedCount: 1,
			expectedServers: map[string]int{
				"empty_config.json": 0, // no MCP servers
			},
		},
		{
			name:          "malformed config",
			testdataFiles: []string{"malformed.yaml"},
			expectedCount: 1, // File is processed but has no servers
			expectedServers: map[string]int{
				"malformed.yaml": 0,
			},
		},
		{
			name:          "security test configs",
			testdataFiles: []string{"test_parser_case_conflict.json"},
			expectedCount: 1,
			expectedServers: map[string]int{
				"test_parser_case_conflict.json": 0, // Servers filtered out due to security issue
			},
		},
		{
			name:          "mix of valid and invalid",
			testdataFiles: []string{"claude_desktop_config.json", "malformed.yaml", "empty_config.json"},
			expectedCount: 3, // all files processed, malformed has no servers
			expectedServers: map[string]int{
				"claude_desktop_config.json": 2,
				"malformed.yaml":             0,
				"empty_config.json":          0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build file paths
			var filePaths []string
			for _, filename := range tt.testdataFiles {
				filePath := filepath.Join(testdataDir, filename)
				// Only add files that exist
				if _, err := os.Stat(filePath); err == nil {
					filePaths = append(filePaths, filePath)
				}
			}

			scanner := NewMCPScanner(filePaths, "/tmp/storage")
			result, err := scanner.Scan()

			require.NoError(t, err)
			assert.Len(t, result.Files, tt.expectedCount)

			// Verify server counts for each file
			for _, file := range result.Files {
				filename := filepath.Base(file.Path)
				if expectedCount, exists := tt.expectedServers[filename]; exists {
					assert.Len(t, file.Servers, expectedCount,
						"File %s should have %d servers but had %d", filename, expectedCount, len(file.Servers))
				}

				// Verify structure
				assert.NotEmpty(t, file.Path)
				if file.Error == nil {
					for _, server := range file.Servers {
						assert.NotEmpty(t, server.Name)
						assert.NotNil(t, server.Server)
					}
				}
			}
		})
	}
}

func TestMCPScanner_scanFile(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(thisFile)
	testdataDir := filepath.Join(baseDir, "..", "..", "testdata")

	tests := []struct {
		name          string
		testdataFile  string
		expectError   bool
		expectServers int
		errorMessage  string
		serverNames   []string // Expected server names
	}{
		{
			name:          "Claude desktop config",
			testdataFile:  "claude_desktop_config.json",
			expectError:   false,
			expectServers: 2,
			serverNames:   []string{"filesystem", "git"},
		},
		{
			name:          "VSCode settings with MCP",
			testdataFile:  "vscode_settings.json",
			expectError:   false,
			expectServers: 2,
			serverNames:   []string{"github", "context7"},
		},
		{
			name:          "Continue YAML config",
			testdataFile:  "continue_config.yaml",
			expectError:   false,
			expectServers: 2,
			serverNames:   []string{"test_server", "python_server"},
		},
		{
			name:          "Goose YAML config",
			testdataFile:  "goose_config.yaml",
			expectError:   false,
			expectServers: 3,
			serverNames:   []string{"filesystem", "git", "web-search"},
		},
		{
			name:          "LibreChat YAML config",
			testdataFile:  "librechat.yaml",
			expectError:   false,
			expectServers: 2,
			errorMessage:  "",
			serverNames:   []string{"filesystem", "database"},
		},
		{
			name:          "Empty config (no MCP servers)",
			testdataFile:  "empty_config.json",
			expectError:   false,
			expectServers: 0,
		},
		{
			name:          "Malformed YAML",
			testdataFile:  "malformed.yaml",
			expectError:   false, // File is processed but no valid MCP config found
			expectServers: 0,
		},
		{
			name:          "Security test with case collision",
			testdataFile:  "test_parser_case_collision.json",
			expectError:   false,
			expectServers: 0, // All servers filtered out due to security issue
			serverNames:   []string{},
		},
		{
			name:         "Nonexistent file",
			testdataFile: "nonexistent.json",
			expectError:  true,
			errorMessage: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(testdataDir, tt.testdataFile)

			scanner := NewMCPScanner([]string{}, "/tmp/storage")
			result, err := scanner.scanFile(filePath)

			switch {
			case tt.expectError && err != nil:
				require.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			case tt.expectError && result != nil && result.Error != nil:
				if tt.errorMessage != "" {
					assert.Contains(t, result.Error.Message, tt.errorMessage)
				}
			case tt.expectError:
				t.Errorf("Expected error but got none for %s", tt.testdataFile)
			default:
				// Skip test if file doesn't exist (testdata might be incomplete)
				if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) && tt.testdataFile != "nonexistent.json" {
					t.Skipf("Testdata file %s not found", tt.testdataFile)
				}

				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, filePath, result.Path)
				assert.Len(t, result.Servers, tt.expectServers,
					"Expected %d servers but got %d in %s", tt.expectServers, len(result.Servers), tt.testdataFile)
				assert.Nil(t, result.Error)

				// Verify server structure and names
				actualServerNames := make([]string, len(result.Servers))
				for i, server := range result.Servers {
					assert.NotEmpty(t, server.Name)
					assert.NotNil(t, server.Server)
					actualServerNames[i] = server.Name
				}

				// Check that expected server names are present
				for _, expectedName := range tt.serverNames {
					assert.Contains(t, actualServerNames, expectedName,
						"Expected server %s not found in %v", expectedName, actualServerNames)
				}
			}
		})
	}
}

func TestMCPScanner_Integration(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(thisFile)
	testdataDir := filepath.Join(baseDir, "..", "..", "testdata")

	// Dynamically include all JSON/YAML files from testdata
	var filePaths []string
	entries, err := os.ReadDir(testdataDir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.Type().IsRegular() {
			name := e.Name()
			full := filepath.Join(testdataDir, name)
			if isJSONOrYAMLFile(full) {
				filePaths = append(filePaths, full)
			}
		}
	}

	if len(filePaths) == 0 {
		t.Skip("No testdata files found for integration test")
	}

	// Run scanner
	scanner := NewMCPScanner(filePaths, "/tmp/storage")
	result, err := scanner.Scan()

	require.NoError(t, err)
	assert.LessOrEqual(t, len(result.Files), len(filePaths)) // Some files might be skipped due to errors

	// Expected server counts based on actual testdata
	expectedCounts := map[string]int{
		"claude_desktop_config.json": 2, // filesystem + git
		"vscode_settings.json":       2, // github + context7
		"continue_config.yaml":       2, // test_server + python_server
		"goose_config.yaml":          3, // filesystem + git + web-search
		"empty_config.json":          0, // no MCP servers
	}

	// Verify results
	serverCounts := make(map[string]int)
	serverNames := make(map[string][]string)

	for _, file := range result.Files {
		filename := filepath.Base(file.Path)
		serverCounts[filename] = len(file.Servers)

		var names []string
		for _, server := range file.Servers {
			names = append(names, server.Name)
		}
		serverNames[filename] = names
	}

	// Check expected counts for files that were processed
	for filename, expectedCount := range expectedCounts {
		if actualCount, exists := serverCounts[filename]; exists {
			assert.Equal(t, expectedCount, actualCount,
				"File %s: expected %d servers, got %d. Servers: %v",
				filename, expectedCount, actualCount, serverNames[filename])
		}
	}

	// Verify all processed files have valid structure
	for _, file := range result.Files {
		assert.NotEmpty(t, file.Path)
		if file.Error == nil {
			for _, server := range file.Servers {
				assert.NotEmpty(t, server.Name)
				assert.NotNil(t, server.Server)
			}
		} else {
			t.Logf("File %s had error: %s", file.Path, file.Error.Message)
		}
	}
}

// New: end-to-end secret detection via Scan() across JSON and YAML.
func TestMCPScanner_Secrets_EndToEnd(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(thisFile)
	testdataDir := filepath.Join(baseDir, "..", "..", "testdata")

	// Include specific secret-bearing files
	files := []string{
		"test_secrets_config.json",
		"test_secrets_multiple.json",
		"test_secrets_multiple_occurrences.json",
		"test_secrets_urls.json",
		"test_secrets_yaml.yaml",
	}

	var filePaths []string
	for _, f := range files {
		p := filepath.Join(testdataDir, f)
		if _, err := os.Stat(p); err == nil {
			filePaths = append(filePaths, p)
		}
	}
	if len(filePaths) == 0 {
		t.Skip("no secret-bearing testdata files found")
	}

	s := NewMCPScanner(filePaths, "/tmp/storage")
	res, err := s.Scan()
	require.NoError(t, err)
	require.NotNil(t, res)

	// There should be at least one secret finding overall
	if len(res.SecretFindings) == 0 {
		t.Fatalf("expected at least 1 secret finding, got 0")
	}

	// Ensure each file with known secrets contributes at least one finding
	byFile := make(map[string]int)
	for _, fr := range res.Files {
		if len(fr.SecretFindings) > 0 {
			byFile[filepath.Base(fr.Path)] = len(fr.SecretFindings)
		}
	}

	// JSON files
	require.Contains(t, byFile, "test_secrets_config.json")
	require.Contains(t, byFile, "test_secrets_multiple.json")
	require.Contains(t, byFile, "test_secrets_multiple_occurrences.json")
	require.Contains(t, byFile, "test_secrets_urls.json")

	// YAML secrets file
	require.Contains(t, byFile, "test_secrets_yaml.yaml")
}

// Unit tests for redaction and detector.
func TestSecretRedactionAndDetector(t *testing.T) {
	raw := "sk-proj-abcT3BlbkFJdef1234567890"
	red := redactSecret(raw)
	// Redaction preserves prefix and masks rest
	assert.GreaterOrEqual(t, len(red), 8)
	assert.Equal(t, raw[:4], red[:4])
	// Detector should classify as an OpenAI API Key
	kind, conf, ok := defaultDetector{}.Classify(raw)
	assert.True(t, ok)
	assert.Equal(t, "OpenAI API Key", kind)
	assert.Equal(t, "HIGH", conf)
}

func TestScanResult_Structure(t *testing.T) {
	tempDir := t.TempDir()

	configFile := filepath.Join(tempDir, "test.json")
	// TODO: use testdata
	content := `{
		"mcpServers": {
			"test-server": {
				"command": "python",
				"args": ["-m", "test"],
				"env": {
					"TEST_VAR": "value"
				}
			}
		}
	}`

	err := os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(t, err)

	scanner := NewMCPScanner([]string{}, "/tmp/storage")
	result, err := scanner.scanFile(configFile)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Test JSON serialization
	jsonData, err := json.Marshal(result)
	require.NoError(t, err)

	// Test JSON deserialization
	var unmarshaled FileResult
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, result.Path, unmarshaled.Path)
	assert.Len(t, unmarshaled.Servers, 1)
	assert.Equal(t, "test-server", unmarshaled.Servers[0].Name)
}

// Test error handling edge cases.
func TestMCPScanner_ErrorHandling(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("permission denied", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Cannot test permission denied as root")
		}

		// Create a file and remove read permissions
		restrictedFile := filepath.Join(tempDir, "restricted.json")
		err := os.WriteFile(restrictedFile, []byte(`{"test": "data"}`), 0o000)
		require.NoError(t, err)
		defer os.Remove(restrictedFile)

		scanner := NewMCPScanner([]string{restrictedFile}, "/tmp/storage")
		result, err := scanner.Scan()

		require.NoError(t, err)       // Scanner continues despite individual file errors
		assert.Empty(t, result.Files) // File should be skipped
	})

	t.Run("directory instead of file", func(t *testing.T) {
		scanner := NewMCPScanner([]string{tempDir}, "/tmp/storage")
		result, err := scanner.Scan()

		require.NoError(t, err)
		assert.Empty(t, result.Files) // Directory should be skipped
	})
}

// Benchmark tests.
func BenchmarkMCPScanner_Scan(b *testing.B) {
	tempDir := b.TempDir()

	// Create a test config file
	configFile := filepath.Join(tempDir, "config.json")
	content := `{
		"mcpServers": {
			"server1": {"command": "python", "args": ["-m", "server1"]},
			"server2": {"command": "node", "args": ["server2.js"]},
			"server3": {"command": "go", "args": ["run", "server3.go"]}
		}
	}`

	err := os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(b, err)

	scanner := NewMCPScanner([]string{configFile}, "/tmp/storage")

	b.ResetTimer()
	for range b.N {
		result, err := scanner.Scan()
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Files) != 1 {
			b.Fatal("Expected 1 result")
		}
	}
}

func BenchmarkMCPScanner_scanFile(b *testing.B) {
	tempDir := b.TempDir()

	configFile := filepath.Join(tempDir, "config.json")
	content := `{
		"mcpServers": {
			"filesystem": {
				"command": "python",
				"args": ["-m", "mcp.examples.filesystem", "/tmp"]
			}
		}
	}`

	err := os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(b, err)

	scanner := NewMCPScanner([]string{}, "/tmp/storage")

	b.ResetTimer()
	for range b.N {
		result, err := scanner.scanFile(configFile)
		if err != nil {
			b.Fatal(err)
		}
		if result == nil {
			b.Fatal("Expected non-nil result")
		}
	}
}

// Test with real testdata files - comprehensive validation.
func TestMCPScanner_WithTestdata(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(thisFile)
	testdataDir := filepath.Join(baseDir, "..", "..", "testdata")

	// Dynamically include all JSON/YAML files from testdata
	var existingFiles []string
	entries, err := os.ReadDir(testdataDir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.Type().IsRegular() {
			name := e.Name()
			full := filepath.Join(testdataDir, name)
			if isJSONOrYAMLFile(full) {
				existingFiles = append(existingFiles, full)
			}
		}
	}

	if len(existingFiles) == 0 {
		t.Skip("No testdata files found")
	}

	scanner := NewMCPScanner(existingFiles, "/tmp/storage")
	result, err := scanner.Scan()

	require.NoError(t, err)
	assert.LessOrEqual(t, len(result.Files), len(existingFiles))

	// Track which files had servers and which had errors
	filesWithServers := 0
	filesWithErrors := 0
	totalServers := 0

	// Each result should have valid structure
	for _, file := range result.Files {
		assert.NotEmpty(t, file.Path)
		filename := filepath.Base(file.Path)

		if file.Error != nil {
			filesWithErrors++
			t.Logf("File %s had error: %s", filename, file.Error.Message)
			continue
		}

		if len(file.Servers) > 0 {
			filesWithServers++
			totalServers += len(file.Servers)

			// Validate server structure
			for _, server := range file.Servers {
				assert.NotEmpty(t, server.Name, "Server name should not be empty in %s", filename)
				assert.NotNil(t, server.Server, "Server config should not be nil in %s", filename)
			}
		}
		t.Logf("File %s found %d servers", filename, len(file.Servers))
	}

	// Should have found at least some servers across all files
	assert.Positive(t, totalServers, "Should have found at least one MCP server across all testdata files")
	t.Logf("Summary: %d files with servers, %d files with errors, %d total servers",
		filesWithServers, filesWithErrors, totalServers)
}
