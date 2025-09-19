//nolint:testpackage // White-box tests require access to unexported identifiers in this package.
package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFile(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		fileSize    int64
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid small file",
			fileContent: `{"test": "data"}`,
			expectError: false,
		},
		{
			name:        "empty file",
			fileContent: "",
			expectError: false,
		},
		{
			name:        "file too large",
			fileSize:    maxConfigSize + 1,
			expectError: true,
			errorMsg:    "config file too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			filePath := filepath.Join(tempDir, "test.json")

			if tt.fileSize > 0 {
				// Create a large file for size test
				file, err := os.Create(filePath)
				require.NoError(t, err)
				defer file.Close()

				// Write large file
				content := strings.Repeat("a", int(tt.fileSize))
				_, err = file.WriteString(content)
				require.NoError(t, err)
			} else {
				err := os.WriteFile(filePath, []byte(tt.fileContent), 0o600)
				require.NoError(t, err)
			}

			data, err := readFile(filePath)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.fileContent, string(data))
			}
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid JSON",
			jsonData:    `{"test": "value"}`,
			expectError: false,
		},
		{
			name:        "case-insensitive key collision",
			jsonData:    `{"Test": "value1", "test": "value2"}`,
			expectError: true,
			errorMsg:    "case-insensitive key collision",
		},
		{
			name:        "nested case collision",
			jsonData:    `{"outer": {"Inner": "value1", "inner": "value2"}}`,
			expectError: true,
			errorMsg:    "case-insensitive key collision",
		},
		{
			name:        "invalid JSON",
			jsonData:    `{"test": }`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			err := unmarshal("test.json", []byte(tt.jsonData), &result)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name        string
		yamlData    string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid YAML",
			yamlData: `

test: value
number: 42
`,
			expectError: false,
		},
		{
			name:        "empty YAML",
			yamlData:    `{}`,
			expectError: false,
		},
		{
			name: "invalid YAML",
			yamlData: `

test: value
  invalid_indent: error
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result map[string]interface{}
			err := unmarshal("test.yaml", []byte(tt.yamlData), &result)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDetectCaseInsensitiveKeyCollisions(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		hasError bool
		errorMsg string
	}{
		{
			name:     "no collisions",
			jsonData: `{"test": "value", "other": "value2"}`,
			hasError: false,
		},
		{
			name:     "direct collision",
			jsonData: `{"Test": "value1", "test": "value2"}`,
			hasError: true,
			errorMsg: "case-insensitive key collision",
		},
		{
			name:     "nested collision",
			jsonData: `{"outer": {"Inner": "value1", "inner": "value2"}}`,
			hasError: true,
			errorMsg: "case-insensitive key collision at 'outer.Inner'",
		},
		{
			name:     "array with nested collision",
			jsonData: `{"items": [{"Name": "test", "name": "collision"}]}`,
			hasError: true,
			errorMsg: "case-insensitive key collision at 'items[0].Name'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detectCaseInsensitiveKeyCollisions([]byte(tt.jsonData))

			if tt.hasError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		server     Server
		expectErr  bool
		errorMsg   string
	}{
		{
			name:       "valid server config",
			serverName: "test-server",
			server: Server{
				"command": "python",
				"args":    []interface{}{"-m", "server"},
			},
			expectErr: false,
		},
		{
			name:       "server with case collision",
			serverName: "bad-server",
			server: Server{
				"Command": "python",
				"command": "python2",
			},
			expectErr: true,
			errorMsg:  "server 'bad-server' has security issue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.serverName, tt.server)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFilterConfig(t *testing.T) {
	tests := []struct {
		name     string
		servers  map[string]Server
		expected int // expected number of valid servers
	}{
		{
			name:     "nil servers",
			servers:  nil,
			expected: 0,
		},
		{
			name:     "empty servers",
			servers:  map[string]Server{},
			expected: 0,
		},
		{
			name: "all valid servers",
			servers: map[string]Server{
				"server1": {"command": "python"},
				"server2": {"command": "node"},
			},
			expected: 2,
		},
		{
			name: "mixed valid and invalid servers",
			servers: map[string]Server{
				"valid-server": {"command": "python"},
				"invalid-server": {
					"Command": "python",
					"command": "python2", // case collision
				},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterConfig(tt.servers)

			if tt.expected == 0 {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Len(t, result, tt.expected)
			}
		})
	}
}

// Test data structures for config parsing.
func TestParseConfigStructures(t *testing.T) {
	t.Run("ClaudeConfigFile", func(t *testing.T) {
		data := `{
			"mcpServers": {
				"filesystem": {
					"command": "python",
					"args": ["-m", "mcp.examples.filesystem", "/path/to/directory"]
				}
			}
		}`

		var config ClaudeConfigFile
		err := json.Unmarshal([]byte(data), &config)
		require.NoError(t, err)

		servers := config.GetServers()
		assert.Len(t, servers, 1)
		assert.Contains(t, servers, "filesystem")
	})

	t.Run("VSCodeConfigFile", func(t *testing.T) {
		data := `{
			"mcp": {
				"servers": {
					"filesystem": {
						"command": "python",
						"args": ["-m", "mcp.examples.filesystem", "/path/to/directory"]
					}
				}
			}
		}`

		var config VSCodeConfigFile
		err := json.Unmarshal([]byte(data), &config)
		require.NoError(t, err)

		servers := config.GetServers()
		assert.Len(t, servers, 1)
		assert.Contains(t, servers, "filesystem")
	})

	t.Run("VSCodeConfigFile without MCP", func(t *testing.T) {
		data := `{
			"editor.fontSize": 14,
			"workbench.theme": "dark"
		}`

		var config VSCodeConfigFile
		err := json.Unmarshal([]byte(data), &config)
		require.NoError(t, err)

		servers := config.GetServers()
		assert.Nil(t, servers)
	})
}

// Benchmark tests for performance-critical parsing functions.
func BenchmarkReadFile(b *testing.B) {
	tempDir := b.TempDir()
	filePath := filepath.Join(tempDir, "test.json")
	content := strings.Repeat(`{"test": "data"}`, 1000)
	err := os.WriteFile(filePath, []byte(content), 0o600)
	require.NoError(b, err)

	b.ResetTimer()
	for range b.N {
		_, err := readFile(filePath)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	data := []byte(`{"mcpServers": {"filesystem": {"command": "python", "args": ["-m", "mcp.examples.filesystem"]}}}`)

	b.ResetTimer()
	for range b.N {
		var result ClaudeConfigFile
		err := unmarshal("bench.json", data, &result)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDetectCaseInsensitiveKeyCollisions(b *testing.B) {
	data := []byte(`{"test": "value", "other": "value2", "nested": {"inner": "value", "array": [{"item": "test"}]}}`)

	b.ResetTimer()
	for range b.N {
		err := detectCaseInsensitiveKeyCollisions(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Fuzz test for parser robustness.
func FuzzUnmarshalJSON(f *testing.F) {
	// Seed with valid JSON examples
	seeds := []string{
		`{"test": "value"}`,
		`{"mcpServers": {"server": {"command": "python"}}}`,
		`{"nested": {"key": "value"}}`,
		`{"array": [{"item": "test"}]}`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, jsonData string) {
		var result map[string]interface{}
		// Should not panic, even with malformed input
		_ = unmarshal("fuzz.json", []byte(jsonData), &result)
	})
}
