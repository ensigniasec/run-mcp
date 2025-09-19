package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:gochecknoglobals // test binary path is set in TestMain
var testBinaryPath string

// TestMain builds the CLI binary once for the entire package and reuses it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "run-mcp-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1) //nolint:gocritic // Mkdir failed, nothing to cleanup
	}
	defer os.RemoveAll(dir)

	bin := filepath.Join(dir, "run-mcp-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build test binary: %v\nOutput: %s\n", err, string(out))
		os.Exit(1) //nolint:gocritic // Binary failed, nothing to cleanup
	}
	testBinaryPath = bin

	code := m.Run()
	os.Exit(code)
}

func setCmdHome(cmd *exec.Cmd, home string) {
	cmd.Env = append(os.Environ(), "HOME="+home)
}

func defaultStoragePath(home string) string {
	return filepath.Join(home, "Library", "Application Support", "run-mcp", "results.json")
}

// Build the binary for testing.
func buildTestBinary(t *testing.T) string {
	if testBinaryPath == "" {
		t.Fatalf("test binary not built")
	}
	return testBinaryPath
}

// newCmd wraps exec.Command to ensure tests default to offline mode.
// This avoids external network health probes that add seconds of latency.
func newCmd(binary string, args ...string) *exec.Cmd {
	for _, a := range args {
		if a == "--offline" {
			return exec.Command(binary, args...)
		}
	}
	return exec.Command(binary, append([]string{"--offline"}, args...)...)
}

func TestCLI_HelpOutput(t *testing.T) {
	binary := buildTestBinary(t)

	tests := []struct {
		name         string
		args         []string
		contains     []string
		expectError  bool
		expectOutput []string
		expectJSON   bool
	}{
		{
			name: "root help",
			args: []string{"--help"},
			contains: []string{
				"run-mcp",
				"MCP configuration files",
				"security rating",
				"scan",
				"experimental",
				"--org-uuid",
				"--anonymous",
			},
			expectError:  false,
			expectOutput: nil,
			expectJSON:   false,
		},
		{
			name: "scan help",
			args: []string{"scan", "--help"},
			contains: []string{
				"MCP configuration files",
				"CONFIG_FILE",
				"--json",
				"--verbose",
				"--org-uuid",
				"--anonymous",
				"--anon",
			},
			expectError:  false,
			expectOutput: nil,
			expectJSON:   false,
		},
		{
			name:         "allowlist help",
			args:         []string{"experimental", "allowlist", "--help"},
			contains:     []string{"allowlisted entities", "add", "reset"},
			expectError:  false,
			expectOutput: nil,
			expectJSON:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newCmd(binary, tt.args...)
			output, err := cmd.CombinedOutput()

			// Help commands should exit with code 0.
			require.NoError(t, err)

			outputStr := string(output)
			for _, expected := range tt.contains {
				assert.Contains(t, outputStr, expected)
			}
		})
	}
}

func TestCLI_ScanCommand(t *testing.T) {
	binary := buildTestBinary(t)
	tempDir := t.TempDir()

	// Use canonical files from testdata instead of synthesizing content.
	testdataDir := filepath.Join("..", "..", "testdata")
	claudePath := filepath.Join(testdataDir, "claude_desktop_config.json")
	vscodePath := filepath.Join(testdataDir, "vscode_settings.json")
	_ = filepath.Join(testdataDir, "empty_config.json")
	_ = filepath.Join(testdataDir, "malformed.yaml")

	tests := []struct {
		name         string
		args         []string
		expectError  bool
		expectOutput []string
		expectJSON   bool
	}{
		{
			name:         "scan specific valid files",
			args:         []string{"scan", claudePath, vscodePath},
			expectOutput: []string{"SCAN REPORT", "servers detected"},
			expectError:  false,
			expectJSON:   false,
		},
		{
			name:         "scan with JSON output",
			args:         []string{"scan", "--json", claudePath},
			expectError:  false,
			expectOutput: nil,
			expectJSON:   true,
		},
		{
			name: "scan with verbose output",
			args: []string{"scan", "--verbose", claudePath},
			expectOutput: []string{
				"SCAN REPORT",
			},
			expectError: false,
			expectJSON:  false,
		},
		{
			name:         "scan nonexistent file",
			args:         []string{"scan", filepath.Join(tempDir, "nonexistent.json")},
			expectError:  false,
			expectOutput: nil,
			expectJSON:   false,
		},
		{
			name: "scan with offline mode",
			args: []string{"scan", "--offline", claudePath},
			expectOutput: []string{
				"SCAN REPORT",
			},
			expectError: false,
			expectJSON:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newCmd(binary, tt.args...)
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stdout

			err := cmd.Run()
			output := stdout.String()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "Command output: %s", output)
			}

			if tt.expectJSON {
				// Verify it's valid JSON object.
				var jsonResult map[string]interface{}
				err := json.Unmarshal([]byte(output), &jsonResult)
				require.NoError(t, err, "Output should be valid JSON: %s", output)
			}

			for _, expected := range tt.expectOutput {
				assert.Contains(t, output, expected, "Expected '%s' in output: %s", expected, output)
			}
		})
	}
}

func TestCLI_AllowlistCommands(t *testing.T) {
	binary := buildTestBinary(t)
	tempDir := t.TempDir()

	// Use default storage under temp HOME
	home := filepath.Join(tempDir, "home")
	require.NoError(t, os.MkdirAll(home, 0o700))
	storageFile := defaultStoragePath(home)

	tests := []struct {
		name         string
		commands     [][]string // Multiple commands to run in sequence
		expectError  bool
		expectOutput []string
	}{
		{
			name: "view empty allowlist",
			commands: [][]string{
				{"experimental", "allowlist"},
			},
			expectOutput: []string{"Allowlist is empty"},
		},
		{
			name: "add to allowlist",
			commands: [][]string{
				{"experimental", "allowlist", "add", "server", "test-server", "hash123"},
				{"experimental", "allowlist"},
			},
			expectOutput: []string{"server:", "hash123"},
		},
		{
			name: "reset allowlist",
			commands: [][]string{
				{"experimental", "allowlist", "add", "server", "test-server", "hash123"},
				{"experimental", "allowlist", "reset"},
				{"experimental", "allowlist"},
			},
			expectOutput: []string{"Allowlist is empty"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up storage file between tests.
			_ = os.Remove(storageFile)

			var allOutput strings.Builder

			for i, cmdArgs := range tt.commands {
				cmd := newCmd(binary, cmdArgs...)
				setCmdHome(cmd, home)
				var stdout bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stdout

				err := cmd.Run()
				output := stdout.String()
				allOutput.WriteString(output)

				if tt.expectError {
					require.Error(t, err, "Command %d should have failed: %v", i, cmdArgs)
				} else {
					require.NoError(t, err, "Command %d failed: %v\nOutput: %s", i, cmdArgs, output)
				}
			}

			finalOutput := allOutput.String()
			for _, expected := range tt.expectOutput {
				assert.Contains(t, finalOutput, expected, "Expected '%s' in output: %s", expected, finalOutput)
			}
		})
	}
}

func TestCLI_ErrorHandling(t *testing.T) {
	binary := buildTestBinary(t)

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "allowlist add with wrong number of args",
			args:        []string{"experimental", "allowlist", "add", "server"},
			expectError: true,
			errorMsg:    "accepts 3 arg(s)",
		},
		{
			name:        "invalid command",
			args:        []string{"invalid-command"},
			expectError: true,
			errorMsg:    "unknown command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newCmd(binary, tt.args...)
			output, err := cmd.CombinedOutput()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, string(output), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCLI_JSONOutput(t *testing.T) {
	binary := buildTestBinary(t)
	tempDir := t.TempDir()

	// Create a test config file
	configFile := filepath.Join(tempDir, "test.json")
	content := `{
		"mcpServers": {
			"test-server": {
				"command": "python",
				"args": ["-m", "test"]
			}
		}
	}`
	err := os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(t, err)

	cmd := newCmd(binary, "scan", "--json", configFile)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err)

	// Parse JSON output (now ScanSummary shape)
	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	require.NoError(t, err, "Output should be valid JSON: %s", string(output))

	// Verify summary structure
	assert.Contains(t, result, "TotalServers")
	assert.Contains(t, result, "Servers")

	discs, ok := result["Servers"].([]interface{})
	require.True(t, ok)
	require.Len(t, discs, 1)
	disc := discs[0].(map[string]interface{})
	assert.Equal(t, "test-server", disc["name"])
	assert.Contains(t, disc, "path")
}

func TestCLI_WellKnownPaths(t *testing.T) {
	binary := buildTestBinary(t)

	// Test that scanning without arguments uses well-known paths.
	cmd := exec.Command(binary, "scan", "--json", "--offline")
	output, err := cmd.CombinedOutput()

	// Should not error even if no files are found.
	require.NoError(t, err, "Output: %s", string(output))

	// Should return valid JSON (object).
	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	require.NoError(t, err, "Output should be valid JSON: %s", string(output))
}

func TestCLI_Integration_RealFlow(t *testing.T) {
	binary := buildTestBinary(t)
	tempDir := t.TempDir()

	// Use default storage under temp HOME
	home := filepath.Join(tempDir, "home")
	require.NoError(t, os.MkdirAll(home, 0o700))
	storageFile := defaultStoragePath(home)

	// Create a realistic test config
	configFile := filepath.Join(tempDir, "claude_desktop.json")
	content := `{
		"mcpServers": {
			"filesystem": {
				"command": "python",
				"args": ["-m", "mcp.examples.filesystem", "/tmp"]
			},
			"git": {
				"command": "git-mcp-server",
				"env": {
					"GIT_REPOSITORY": "/path/to/repo"
				}
			}
		}
	}`
	err := os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(t, err)

	// Step 1: Initial scan (anon alias should suppress headers internally when used).
	cmd := newCmd(
		binary,
		"scan",
		"--json",
		"--org-uuid",
		"00000000-0000-4000-8000-000000000000",
		"--anon",
		configFile,
	)
	setCmdHome(cmd, home)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Scan failed: %s", string(output))

	var scanResult map[string]interface{}
	err = json.Unmarshal(output, &scanResult)
	require.NoError(t, err)
	// New JSON shape is ScanSummary. Validate servers list.
	discovered, ok := scanResult["Servers"].([]interface{})
	require.True(t, ok)
	// Expect at least the two servers defined in the config.
	assert.GreaterOrEqual(t, len(discovered), 2)

	// Step 2: Check empty allowlist.
	cmd = newCmd(binary, "experimental", "allowlist")
	setCmdHome(cmd, home)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "Allowlist is empty")

	// Step 3: Add server to allowlist.
	cmd = newCmd(binary, "experimental", "allowlist", "add", "server", "filesystem", "test-hash")
	setCmdHome(cmd, home)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Add to allowlist failed: %s", string(output))

	// Step 4: Verify allowlist has entry
	cmd = newCmd(binary, "experimental", "allowlist")
	setCmdHome(cmd, home)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err)
	outputStr := string(output)
	assert.Contains(t, outputStr, "server:")
	assert.Contains(t, outputStr, "test-hash")

	// Step 5: Reset allowlist
	cmd = newCmd(binary, "experimental", "allowlist", "reset")
	setCmdHome(cmd, home)
	_, err = cmd.CombinedOutput()
	require.NoError(t, err)

	// Step 6: Verify allowlist is empty again
	cmd = newCmd(binary, "experimental", "allowlist")
	setCmdHome(cmd, home)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "Allowlist is empty")

	_ = os.Remove(storageFile)
}

// Test CLI with environment variables and edge cases.
func TestCLI_EdgeCases(t *testing.T) {
	binary := buildTestBinary(t)

	t.Run("very long command line", func(t *testing.T) {
		// Create a reasonable number of file arguments (not too many to avoid OS limits)
		tempDir := t.TempDir()
		var args []string
		args = append(args, "scan", "--json")

		// Add a reasonable number of non-existent files
		for i := range 10 {
			args = append(args, filepath.Join(tempDir, fmt.Sprintf("nonexistent%d.json", i)))
		}

		cmd := newCmd(binary, args...)
		output, err := cmd.CombinedOutput()

		// Should handle gracefully
		require.NoError(t, err, "Output: %s", string(output))

		// Should return valid JSON
		var result map[string]interface{}
		err = json.Unmarshal(output, &result)
		require.NoError(t, err)
	})

	t.Run("concurrent execution", func(t *testing.T) {
		// Run multiple instances simultaneously
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "test.json")
		content := `{"mcpServers": {"test": {"command": "echo"}}}`
		err := os.WriteFile(configFile, []byte(content), 0o600)
		require.NoError(t, err)

		// Run 5 instances concurrently
		type result struct {
			output []byte
			err    error
		}
		results := make(chan result, 5)

		for range 5 {
			go func() {
				cmd := newCmd(binary, "scan", "--json", "--anonymous", configFile)
				output, err := cmd.CombinedOutput()
				results <- result{output, err}
			}()
		}

		// Collect results
		for range 5 {
			res := <-results
			require.NoError(t, res.err, "Concurrent execution failed: %s", string(res.output))

			var jsonResult map[string]interface{}
			err := json.Unmarshal(res.output, &jsonResult)
			require.NoError(t, err, "Invalid JSON from concurrent run: %s", string(res.output))
		}
	})
}

// Benchmark CLI performance.
func BenchmarkCLI_Scan(b *testing.B) {
	// Build binary once for benchmark
	binaryPath := filepath.Join(b.TempDir(), "run-mcp-test")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")

	output, err := cmd.CombinedOutput()
	if err != nil {
		b.Fatalf("Failed to build test binary: %v\nOutput: %s", err, string(output))
	}

	tempDir := b.TempDir()

	// Create test config
	configFile := filepath.Join(tempDir, "config.json")
	content := `{
		"mcpServers": {
			"server1": {"command": "python"},
			"server2": {"command": "node"},
			"server3": {"command": "go"}
		}
	}`
	err = os.WriteFile(configFile, []byte(content), 0o600)
	require.NoError(b, err)

	b.ResetTimer()
	for range b.N {
		cmd := exec.Command(binaryPath, "scan", "--json", "--offline", configFile)
		_, err := cmd.CombinedOutput()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestCLI_OrgRegisterShowClear(t *testing.T) {
	binary := buildTestBinary(t)
	tempDir := t.TempDir()

	// Use default storage under temp HOME
	home := filepath.Join(tempDir, "home")
	require.NoError(t, os.MkdirAll(home, 0o700))

	uuid := "123e4567-e89b-12d3-a456-426614174000"

	// Register
	cmd := newCmd(binary, "org", "register", uuid)
	setCmdHome(cmd, home)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Register failed: %s", string(output))
	assert.Contains(t, string(output), "Organization UUID set to "+uuid)

	// Show
	cmd = newCmd(binary, "org", "show")
	setCmdHome(cmd, home)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Equal(t, uuid+"\n", string(output))

	// Clear
	cmd = newCmd(binary, "org", "clear")
	setCmdHome(cmd, home)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "Organization UUID cleared")

	// Show again (should indicate none set)
	cmd = newCmd(binary, "org", "show")
	setCmdHome(cmd, home)
	output, err = cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(output), "No organization UUID set")
}

func TestCLI_OrgRegisterInvalid(t *testing.T) {
	binary := buildTestBinary(t)
	tempDir := t.TempDir()

	// Use default storage under temp HOME
	home := filepath.Join(tempDir, "home")
	require.NoError(t, os.MkdirAll(home, 0o700))

	cmd := newCmd(binary, "org", "register", "not-a-uuid")
	setCmdHome(cmd, home)
	output, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(output), "Invalid organization UUID:")
}
