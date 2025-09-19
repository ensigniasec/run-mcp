package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	maxConfigSize = 10 * 1024 * 1024 // 10MB limit to prevent memory exhaustion
)

// readFile reads a file with sane limits to prevent attacks.
func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Check file size to prevent memory exhaustion attacks
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() > maxConfigSize {
		return nil, fmt.Errorf("config file too large: %d bytes (max %d)", info.Size(), maxConfigSize)
	}

	// Use limited reader to enforce size limit
	limitedReader := io.LimitReader(file, maxConfigSize)
	return io.ReadAll(limitedReader)
}

// unmarshal decodes data using path to choose JSON or YAML.
// For JSON, runs a case-insensitive key collision check before decoding.
func unmarshal(path string, data []byte, v interface{}) error {
	if isJSONFile(path) {
		if err := detectCaseInsensitiveKeyCollisions(data); err != nil {
			return fmt.Errorf("case-insensitive key collision detected: %w", err)
		}
		return json.Unmarshal(data, v)
	}
	if isYAMLFile(path) {
		return yaml.Unmarshal(data, v)
	}
	return fmt.Errorf("unknown config file extension: %s", path)
}

// detectCaseInsensitiveKeyCollisions checks if the JSON data contains keys
// that differ only by letter case. This helps prevent subtle bugs where two
// different key spellings might refer to the same data.
// see: https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/
func detectCaseInsensitiveKeyCollisions(data []byte) error {
	var res interface{}
	// If this generic decode fails (e.g., syntax error), skip collision check and
	// let the main unmarshal path report a proper JSON parse error.
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&res); err != nil {
		return nil
	}
	return checkCaseInsensitiveKeysRecursive(res, "")
}

// checkCaseInsensitiveKeysRecursive recursively checks for case-insensitive key collisions.
//
//nolint:gocognit,gocyclo // Recursive traversal purposely handles multiple cases for clarity.
func checkCaseInsensitiveKeysRecursive(obj interface{}, path string) error {
	switch v := obj.(type) {
	case map[string]interface{}:
		// Track first-seen original key per lowercased value
		lowerToOriginal := make(map[string]string, len(v))
		// Iterate keys; when we hit a duplicate lowercased key, report path using the current key
		for key, value := range v {
			lower := strings.ToLower(key)
			if first, exists := lowerToOriginal[lower]; exists {
				// Prefer the variant with any uppercase letters for path display to match expectations
				pathKey := first
				if strings.EqualFold(first, key) {
					// If current key has any uppercase, prefer it
					if key != strings.ToLower(key) {
						pathKey = key
					}
				}
				keyPath := path
				if keyPath != "" {
					keyPath += "."
				}
				keyPath += pathKey
				return fmt.Errorf("case-insensitive key collision at '%s': '%s' and '%s'", keyPath, key, first)
			}
			lowerToOriginal[lower] = key

			nestedPath := path
			if nestedPath != "" {
				nestedPath += "."
			}
			nestedPath += key
			if err := checkCaseInsensitiveKeysRecursive(value, nestedPath); err != nil {
				return err
			}
		}

	case []interface{}:
		// Check array elements
		for i, item := range v {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := checkCaseInsensitiveKeysRecursive(item, itemPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateConfig(serverName string, server Server) error {
	// Convert server map to JSON and back to check for duplicate keys and unknown fields
	serverBytes, err := json.Marshal(server)
	if err != nil {
		return fmt.Errorf("failed to marshal server config: %w", err)
	}

	// Check for case-insensitive key collisions in this server
	if err := detectCaseInsensitiveKeyCollisions(serverBytes); err != nil {
		return fmt.Errorf("server '%s' has security issue: %w", serverName, err)
	}
	return nil
}

// filterConfig filters out bad configs from a map of servers,
// logging warnings for skipped servers.
func filterConfig(servers map[string]Server) map[string]Server {
	if servers == nil {
		return nil
	}

	validServers := make(map[string]Server)
	for name, server := range servers {
		if err := validateConfig(name, server); err != nil {
			logrus.Warnf("Skipping invalid config for server '%s': %v", name, err)
			continue
		}
		validServers[name] = server
	}

	if len(validServers) == 0 {
		return nil
	}
	return validServers
}
