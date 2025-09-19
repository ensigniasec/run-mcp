# Test Data for MCP Configuration Parser

This directory contains sample MCP configuration files for testing the parser functionality.

## Valid Configuration Files

### JSON Formats
- `claude_desktop_config.json` - Claude Desktop config with filesystem and git servers
- `vscode_settings.json` - VS Code settings.json with MCP section
- `vscode_mcp.json` - Standalone VS Code MCP config
- `continuerc.json` - Continue extension config with MCP servers

### YAML Formats  
- `continue_config.yaml` - Continue config in YAML format
- `goose_config.yaml` - Goose MCP server configuration
- `librechat.yaml` - LibreChat configuration with MCP servers

## Edge Cases
- `empty_config.json` - Valid JSON without MCP configuration
- `malformed.yaml` - Invalid YAML with syntax errors
- `invalid_large.json` - Potentially malicious config (for security testing)

## Usage

These files can be used to test:
- Parser format detection (JSON vs YAML)
- Config type identification (Claude, VSCode, Continue, etc.) 
- Security limits and error handling
- Performance benchmarks

Run tests with:
```bash
go test ./internal/scanner -v
```
