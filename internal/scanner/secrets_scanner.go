package scanner

import (
	"fmt"
)

// secretScanContext holds per-file scanning state and aggregates findings by hash of secret value.
type secretScanContext struct {
	filePath            string
	fileContent         []byte
	findings            *FindingSet
	detector            Detector
	redactor            Redactor
	currentServer       string
	originalFileContent []byte
}

func newSecretScanContext(filePath string, fileContent []byte) *secretScanContext {
	return &secretScanContext{
		filePath:            filePath,
		fileContent:         fileContent,
		findings:            NewFindingSet(),
		detector:            defaultDetector{},
		redactor:            redactSecret,
		currentServer:       "",
		originalFileContent: append([]byte(nil), fileContent...),
	}
}

// TraverseServer sets the active server context and traverses its data.
func (c *secretScanContext) TraverseServer(serverName string, data interface{}) interface{} {
	c.currentServer = serverName
	return c.Traverse(data, "")
}

// Traverse recursively walks the data structure, looking for strings that look like secrets.
// It returns a redacted secret and records secret findings.
//
// The structure of a config is a JSON like object:
// -  map of general values (we don't care about these & recurse through them) e.g. {"command": "npx"}
// -  map of ENV values (secrets live here)      e.g. {"ENV": "SECRET_GOES_HERE"}
// -  a slice of ARGS values (secrets live here) e.g.  {"args": ["-y", "server", "SECRET_GOES_HERE"]}
//
// We recurse through these until we find a string.
func (c *secretScanContext) Traverse(data interface{}, dotPath string) interface{} {
	switch v := data.(type) {
	case map[string]interface{}: // usually ENV values
		out := make(map[string]interface{}, len(v))
		for key, value := range v {
			out[key] = c.Traverse(value, childPath(dotPath, key))
		}
		return out
	case []interface{}: // ususally ARGS values
		out := make([]interface{}, len(v))
		for key, value := range v {
			out[key] = c.Traverse(value, childPath(dotPath, key))
		}
		return out
	case string:
		return c.handleString(dotPath, v)
	default:
		return v
	}
}

func childPath(parent string, segment interface{}) string {
	switch v := segment.(type) {
	case string: // map key
		if parent == "" {
			return v
		}
		return parent + "." + v
	case int: // slice index
		return fmt.Sprintf("%s[%d]", parent, v)
	default:
		return parent
	}
}
