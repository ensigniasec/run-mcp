//nolint:testpackage // White-box tests require access to unexported identifiers in this package.
package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandTilde(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Tilde expansion not applicable on Windows")
	}

	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "path with tilde",
			input:       "~/.config/test",
			expectError: false,
		},
		{
			name:        "path without tilde",
			input:       "/absolute/path",
			expectError: false,
		},
		{
			name:        "empty path",
			input:       "",
			expectError: false,
		},
		{
			name:        "just tilde",
			input:       "~",
			expectError: false,
		},
		{
			name:        "tilde in middle (should not expand)",
			input:       "/path/~/file",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandTilde(tt.input)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				switch {
				case strings.HasPrefix(tt.input, "~") && tt.input != "~":
					// Should expand to home directory
					home, _ := os.UserHomeDir()
					expected := filepath.Join(home, tt.input[1:])
					assert.Equal(t, expected, result)
				case tt.input == "~":
					// Just tilde should expand to home
					home, _ := os.UserHomeDir()
					assert.Equal(t, home, result)
				default:
					// Should return unchanged
					assert.Equal(t, tt.input, result)
				}
			}
		})
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		checkResult func(t *testing.T, input, result string)
	}{
		{
			name:        "absolute path",
			input:       "/absolute/path",
			expectError: false,
			checkResult: func(t *testing.T, input, result string) {
				assert.Equal(t, input, result)
			},
		},
		{
			name:        "relative path",
			input:       "relative/path",
			expectError: false,
			checkResult: func(t *testing.T, input, result string) {
				assert.Equal(t, input, result)
			},
		},
	}

	// Add OS-specific tests
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name        string
			input       string
			expectError bool
			checkResult func(t *testing.T, input, result string)
		}{
			name:        "tilde path",
			input:       "~/.config/test",
			expectError: false,
			checkResult: func(t *testing.T, input, result string) {
				assert.True(t, strings.HasPrefix(result, "/"))
				assert.True(t, strings.HasSuffix(result, ".config/test"))
			},
		})
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, struct {
			name        string
			input       string
			expectError bool
			checkResult func(t *testing.T, input, result string)
		}{
			name:        "windows env var path with $VAR",
			input:       "$USERPROFILE\\test",
			expectError: false,
			checkResult: func(t *testing.T, input, result string) {
				assert.NotContains(t, result, "$")
			},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandPath(tt.input)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, tt.input, result)
				}
			}
		})
	}
}

func TestGetWellKnownMCPPaths(t *testing.T) {
	paths := GetWellKnownMCPPaths()

	// Should return some paths
	assert.NotEmpty(t, paths)

	// All paths should be expanded (no ~ or % characters)
	for _, path := range paths {
		assert.NotContains(t, path, "~", "Path should be expanded: %s", path)
		if runtime.GOOS == "windows" {
			assert.NotContains(t, path, "%", "Path should be expanded: %s", path)
		}
	}

	// Should include project-level paths
	foundProjectPath := false
	for _, path := range paths {
		if strings.Contains(path, ".vscode/settings.json") ||
			strings.Contains(path, "mcp.json") {
			foundProjectPath = true
			break
		}
	}
	assert.True(t, foundProjectPath, "Should include at least one project-level path")

	// Soft-check that at least one of our new project-level client hints exists.
	wantProjectHints := []string{
		".boltai/mcp.json",
		".witsy/mcp.json",
		".enconvo/mcp.json",
		".roo/mcp.json",
		".vscode-insiders/settings.json",
	}
	foundAnyNew := false
	for _, path := range paths {
		for _, hint := range wantProjectHints {
			if strings.Contains(path, hint) {
				foundAnyNew = true
				break
			}
		}
		if foundAnyNew {
			break
		}
	}
	assert.True(t, foundAnyNew, "Should include at least one newly added project-level client path")

	// OS-specific path checks
	switch runtime.GOOS {
	case "darwin":
		// Should include macOS-specific paths
		foundMacPath := false
		for _, path := range paths {
			if strings.Contains(path, "Library/Application Support") {
				foundMacPath = true
				break
			}
		}
		assert.True(t, foundMacPath, "Should include macOS-specific paths")

	case "linux":
		// Should include Linux-specific paths
		foundLinuxPath := false
		for _, path := range paths {
			if strings.Contains(path, ".config/") || strings.Contains(path, "/etc/") {
				foundLinuxPath = true
				break
			}
		}
		assert.True(t, foundLinuxPath, "Should include Linux-specific paths")

	case "windows":
		// Should include Windows-specific paths (now expanded)
		foundWindowsPath := false
		for _, path := range paths {
			if strings.Contains(path, "\\Code\\User\\") || strings.Contains(path, "ProgramData") {
				foundWindowsPath = true
				break
			}
		}
		assert.True(t, foundWindowsPath, "Should include Windows-specific paths")
	}
}

func TestIsYAMLFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "yaml extension",
			path:     "config.yaml",
			expected: true,
		},
		{
			name:     "yml extension",
			path:     "config.yml",
			expected: true,
		},
		{
			name:     "YAML uppercase",
			path:     "config.YAML",
			expected: true,
		},
		{
			name:     "json file",
			path:     "config.json",
			expected: false,
		},
		{
			name:     "no extension",
			path:     "config",
			expected: false,
		},
		{
			name:     "yaml in path but not extension",
			path:     "yaml/config.json",
			expected: false,
		},
		{
			name:     "full path with yaml",
			path:     "/home/user/.config/app/config.yaml",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isYAMLFile(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test path expansion with actual filesystem.
func TestPathExpansionIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix-style integration test on Windows")
	}

	tempDir := t.TempDir()

	// Create a test file in temp directory
	testFile := filepath.Join(tempDir, "test-config.json")
	err := os.WriteFile(testFile, []byte(`{"test": "data"}`), 0o600)
	require.NoError(t, err)

	// Test that we can find the file through path expansion
	relativePath := filepath.Join(".", "test-config.json")

	// Change to temp directory for the duration of the test
	t.Chdir(tempDir)

	expanded, err := expandPath(relativePath)
	require.NoError(t, err)

	// File should exist at expanded path
	_, err = os.Stat(expanded)
	require.NoError(t, err)
}

// Benchmark path operations.
func BenchmarkGetWellKnownMCPPaths(b *testing.B) {
	for range b.N {
		paths := GetWellKnownMCPPaths()
		if len(paths) == 0 {
			b.Fatal("Expected non-empty paths")
		}
	}
}

func BenchmarkExpandPath(b *testing.B) {
	testPaths := []string{
		"~/.config/test",
		"/absolute/path",
		"relative/path",
		"~/.local/share/app/config.json",
	}

	if runtime.GOOS == "windows" {
		testPaths = []string{
			"$USERPROFILE\\.config\\test",
			"C:\\absolute\\path",
			"relative\\path",
			"$APPDATA\\app\\config.json",
		}
	}

	b.ResetTimer()
	for range b.N {
		for _, path := range testPaths {
			_, err := expandPath(path)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// Property-based testing.
func TestPathExpansionProperties(t *testing.T) {
	// Property: expanding an already expanded absolute path should return the same path
	t.Run("idempotent absolute path expansion", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			path := "C:\\Program Files\\test"
			result1, err1 := expandPath(path)
			require.NoError(t, err1)
			result2, err2 := expandPath(result1)
			require.NoError(t, err2)
			assert.Equal(t, result1, result2)
		} else {
			path := "/usr/local/bin/test"
			result1, err1 := expandPath(path)
			require.NoError(t, err1)
			result2, err2 := expandPath(result1)
			require.NoError(t, err2)
			assert.Equal(t, result1, result2)
		}
	})

	// Property: all well-known paths should be expandable without error
	t.Run("all well-known paths expandable", func(t *testing.T) {
		paths := GetWellKnownMCPPaths()
		for _, path := range paths {
			// Since paths are already expanded, expanding again should not error
			_, err := expandPath(path)
			require.NoError(t, err, "Path should be expandable: %s", path)
		}
	})
}
