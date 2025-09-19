package scanner

import "github.com/sirupsen/logrus"

type ConfigKind int

const (
	KindUnknown ConfigKind = iota
	KindClaude
	KindVSCodeConfig
	KindVSCodeMCP
	KindContinue
	KindGoose
	KindLibreChat
)

func (k ConfigKind) String() string {
	switch k {
	case KindUnknown:
		return "UnknownConfig"
	case KindClaude:
		return "ClaudeConfigFile"
	case KindVSCodeConfig:
		return "VSCodeConfigFile"
	case KindVSCodeMCP:
		return "VSCodeMCPConfig"
	case KindContinue:
		return "ContinueConfigFile"
	case KindGoose:
		return "GooseConfigFile"
	case KindLibreChat:
		return "LibreChatConfigFile"
	default:
		return "UnknownConfig"
	}
}

func (s *MCPScanner) ParseMCPConfigFile(path string) (MCPConfig, error) {
	content, err := readFile(path)
	if err != nil {
		logrus.Debugf("Failed to read file: %v", err)
		return nil, err
	}

	// 1) Parse once generically so we can detect the config kind
	var generic map[string]interface{}
	if err := unmarshal(path, content, &generic); err != nil {
		logrus.Debugf("Unknown or invalid config format for %s: %v", path, err)
		return nil, nil
	}

	// 2) Detect configKind without constructing all concrete types
	var chosen configDetector
	found := false
	for _, d := range configDetectors {
		if d.match(generic) {
			chosen = d
			found = true
			break
		}
	}
	if !found {
		logrus.Debugf("Unknown config kind: %v", path)
		return nil, nil
	}

	// 3) Unmarshal into the chosen concrete configKind now that we know it
	cfg := chosen.new()
	if err := unmarshal(path, content, cfg); err != nil {
		logrus.Warnf("Failed to unmarshal config: %v", err)
		return nil, err
	}

	// 4) Scan + redact via the wrapper (hides iteration/write-back)
	if servers := cfg.GetServers(); len(servers) == 0 {
		return nil, nil
	}
	_ = s.findAndRedactSecrets(cfg, path, content)
	return cfg, nil
}

// findAndRedactSecrets scans all servers, redacts secrets in-place on cfg, and only returns an error.
func (s *MCPScanner) findAndRedactSecrets(cfg MCPConfig, filePath string, fileContent []byte) error {
	if cfg == nil {
		return nil
	}
	ctx := newSecretScanContext(filePath, fileContent)

	servers := cfg.GetServers()
	redactedServers := make(map[string]Server, len(servers))
	for name, srv := range servers {
		out := ctx.TraverseServer(name, srv)
		if m, ok := out.(map[string]interface{}); ok {
			redactedServers[name] = m
		} else {
			redactedServers[name] = srv
		}
	}
	setServers(cfg, redactedServers)
	findings := ctx.Findings()
	if len(findings) > 0 {
		s.ScanResult.SecretFindings = append(s.ScanResult.SecretFindings, findings...)
	}
	return nil
}

// setServers writes the provided servers map back to the config.
func setServers(config MCPConfig, servers map[string]Server) {
	switch c := config.(type) {
	case *ClaudeConfigFile:
		c.MCPServers = servers
	case *VSCodeMCPConfig:
		c.Servers = servers
	case *VSCodeConfigFile:
		if c.MCP == nil {
			c.MCP = &VSCodeMCPConfig{}
		}
		c.MCP.Servers = servers
	case *ContinueConfigFile:
		c.MCP = servers
	case *GooseConfigFile:
		c.MCPServers = servers
	case *LibreChatConfigFile:
		c.MCP.Servers = servers
	}
}
