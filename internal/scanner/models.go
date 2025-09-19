package scanner

import "time"

type ScanError struct {
	Message string `json:"message,omitempty"`
	// Cause is a serialized error message for JSON friendliness.
	Cause string `json:"cause,omitempty"`
}

type ServerConfig struct {
	Name   string      `json:"name,omitempty"`
	Server interface{} `json:"server"`
}

// FileResult represents the scan output for a single config file.
type FileResult struct {
	Path           string          `json:"path" validate:"omitempty,filepath"`
	Servers        []ServerConfig  `json:"servers,omitempty"`
	Error          *ScanError      `json:"error,omitempty"`
	SecretFindings []SecretFinding `json:"secret_findings,omitempty"`
}

// ServerReport represents a server with attached rating and findings.
type ServerReport struct {
	// TODO: add an id field to match IDs.md
	Name        string          `json:"name"`
	Path        string          `json:"path" validate:"omitempty,filepath"`
	Rating      *SecurityRating `json:"rating,omitempty"`
	Secrets     []SecretFinding `json:"secrets,omitempty"`
	LocalPolicy string          `json:"local_policy,omitempty"` // allowed|denied|unknown
}

// SecurityRating represents a server's security assessment.
type SecurityRating struct {
	Hash            string    `json:"hash"`
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Category        string    `json:"category"` // TRUSTED, SUSPICIOUS, UNTRUSTED, MALICIOUS
	RiskScore       float64   `json:"risk_score"`
	Vulnerabilities []string  `json:"vulnerabilities"` // CVE list
	LastUpdated     time.Time `json:"last_updated"`
	Source          string    `json:"source"` // "api", "heuristic", "manual"
}

// MCP Config Models

// Server represents a generic MCP server.
// Type alias to simplify handling in type switches.
type Server = map[string]interface{}

type MCPConfig interface {
	GetServers() map[string]Server
}

// Claude

type ClaudeConfigFile struct {
	MCPServers map[string]Server `json:"mcpServers"`
}

func (c *ClaudeConfigFile) GetServers() map[string]Server {
	return filterConfig(c.MCPServers)
}

// VSCode

type VSCodeMCPConfig struct {
	Servers map[string]Server `json:"servers"`
}

func (c *VSCodeMCPConfig) GetServers() map[string]Server {
	return filterConfig(c.Servers)
}

type VSCodeConfigFile struct {
	MCP *VSCodeMCPConfig `json:"mcp"`
}

func (c *VSCodeConfigFile) GetServers() map[string]Server {
	if c.MCP != nil {
		return filterConfig(c.MCP.Servers)
	}
	return nil
}

// YAML Config types for Continue, Goose, LibreChat etc.

type ContinueConfigFile struct {
	MCP map[string]Server `yaml:"mcp" json:"mcp"`
}

func (c *ContinueConfigFile) GetServers() map[string]Server {
	return filterConfig(c.MCP)
}

type GooseConfigFile struct {
	MCPServers map[string]Server `yaml:"mcp_servers" json:"mcp_servers"`
}

func (c *GooseConfigFile) GetServers() map[string]Server {
	return filterConfig(c.MCPServers)
}

type LibreChatConfigFile struct {
	MCP struct {
		Servers map[string]Server `yaml:"servers" json:"servers"`
	} `yaml:"mcp" json:"mcp"`
}

func (c *LibreChatConfigFile) GetServers() map[string]Server {
	return filterConfig(c.MCP.Servers)
}
