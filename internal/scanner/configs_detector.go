package scanner

type configDetector struct {
	kind  ConfigKind
	match func(m map[string]interface{}) bool
	new   func() MCPConfig
}

//nolint:gochecknoglobals,gofumpt // Static registry of config detectors used across package.
var configDetectors = []configDetector{
	{KindClaude,
		func(m map[string]interface{}) bool { return hasKey(m, "mcpServers") },
		func() MCPConfig { return &ClaudeConfigFile{} },
	},
	{KindVSCodeMCP,
		func(m map[string]interface{}) bool { return hasKey(m, "servers") },
		func() MCPConfig { return &VSCodeMCPConfig{} },
	},
	{KindVSCodeConfig,
		func(m map[string]interface{}) bool { return hasNested(m, "mcp", "servers") },
		func() MCPConfig { return &VSCodeConfigFile{} },
	},
	{KindContinue,
		func(m map[string]interface{}) bool { return hasKey(m, "mcp") },
		func() MCPConfig { return &ContinueConfigFile{} },
	},
	{KindGoose,
		func(m map[string]interface{}) bool { return hasKey(m, "mcp_servers") },
		func() MCPConfig { return &GooseConfigFile{} },
	},
	{KindLibreChat,
		func(m map[string]interface{}) bool { return hasNested(m, "mcp", "servers") },
		func() MCPConfig { return &LibreChatConfigFile{} },
	},
}

func hasKey(m map[string]interface{}, k string) bool {
	_, ok := m[k]
	return ok
}

func hasNested(m map[string]interface{}, ks ...string) bool {
	cur := any(m)
	for _, k := range ks {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return false
		}
		next, ok := obj[k]
		if !ok {
			return false
		}
		cur = next
	}
	return true
}
