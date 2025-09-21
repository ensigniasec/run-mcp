# RUN MCP

[![test](https://github.com/ensigniasec/run-mcp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/ensigniasec/run-mcp/actions/workflows/test.yml)
[![lint](https://github.com/ensigniasec/run-mcp/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/ensigniasec/run-mcp/actions/workflows/lint.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ensigniasec/run-mcp?cache=v1)](https://goreportcard.com/report/github.com/ensigniasec/run-mcp)
[![Release](https://img.shields.io/github/release/ensigniasec/run-mcp.svg?color=%23007ec6)](https://github.com/ensigniasec/run-mcp/releases/latest)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ensigniasec/run-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/ensigniasec/run-mcp)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ensigniasec/run-mcp/blob/main/LICENSE)

**A fast, portable, single-binary security scanner for the Model Context Protocol (MCP).**

![Run MCP](docs/RUN-MCP.svg)

This tool scans MCP (modelcontextprotocol.io) configurations for security vulnerabilities, and helps you enforce security policies for your MCP Configurations.

# WARNING: This software is early-alpha, under active development and is subject to breaking changes.

## Features

- **Discovery (`scan`):** Scans all your installed MCP servers for misconfigured secrets, and submits them for ratings across
- **Automatic Discovery:** Automatically discovers MCP configurations from well-known clients, including VSCode, Claude, Cursor, and Windsurf.
- _(experimental) Allowlisting:`experimental allow/deny` Manage a local allowlist of blessed MCP Servers._
- _(experimental) Inspect: `experimental inspect`: Actively enumerates an MCP server for tool calls, malicious tool descriptions, prompt injection vulnerabilities, tool poisoning attacks, cross-origin escalations, and rug pull attacks._
- _(experimental) Proxy: `experimental proxy` Forwards traffic for a given MCP server through a local proxy for inspection._
- **Flexible Output:** Supports both human-readable, colorized output for interactive use and structured JSON output for integration with other tools and systems.
- **Portable & Performant:** Distributed as a single, self-contained binary, written in Go for high performance.

## Quick Start

```sh
npm i -g @ensignia/run-mcp
run-mcp scan
# This will look for 
```

## Installation

The easiest way to get started is via package managers:

### npm (all platforms):

```sh
npm i -g @ensignia/run-mcp
run-mcp --version
```

### Homebrew (macOS)

```sh
brew tap ensigniasec/run-mcp
brew install --cask run-mcp
run-mcp --version
```

### Downloading pre-built binaries

Use the installer script to download the correct archive for your OS/arch and
verify checksums and signatures with cosign.

```sh
git clone git@github.com:ensigniasec/run-mcp.git
chmod +x run-mcp/scripts/install.sh
less ./run-mcp/scripts/install.sh
bash ./run-mcp/scripts/install.sh

# Or fetch and run directly
curl -fsSL https://raw.githubusercontent.com/ensigniasec/run-mcp/main/scripts/install.sh -o install.sh
less install.sh
bash ./install.sh
```

Requirements: `cosign` and either `wget` or `curl`. On macOS, `shasum` is used; on Linux, `sha256sum`.

Alternative verification with GitHub CLI:

```sh
gh release verify v0.1.1 --repo ensigniasec/run-mcp
gh attestation verify --owner ensigniasec *.tar.gz
gh attestation verify --owner ensigniasec checksums.txt
```

### FAQ:

If Gatekeeper blocks the binary ("Apple could not verify"), you have a few options:

- Open via System Settings: System Settings → Privacy & Security → Open Anyway
- Reinstall without quarantine:

```sh
brew reinstall --cask run-mcp
```

- Or remove the quarantine attribute after install:

```sh
# For cask installs
sudo xattr -dr com.apple.quarantine "$(brew --prefix)/Caskroom/run-mcp/*/run-mcp"

# If you installed elsewhere, dequarantine the installed path
sudo xattr -dr com.apple.quarantine "$(command -v run-mcp)"
```

### Build from source (GO 1.25.0)

```sh
git clone https://github.com/ensigniasec/run-mcp.git
cd run-mcp
go build -o build/run-mcp ./cmd/run-mcp
./build/run-mcp --help
```

#### Go version compatibility

- npm/prebuilt binaries work without Go installed.
- If your local Go is older and you encounter errors, either enable `GOTOOLCHAIN=auto` or upgrade Go to `1.25.0`.

## Usage

### Scanning for Vulnerabilities

To run a static scan on all discovered MCP configurations, simply run the `scan` command:

```sh
run-mcp scan
```

To scan a specific configuration file, or directory:

```sh
run-mcp scan /path/to/your/mcp_config.json
run-mcp scan / 2>/dev/null # send errors to /dev/null if running a whole system scan
```

## Usage

### Commands

#### `scan`

Scans MCP configurations for security vulnerabilities.

```sh
# Scan common configuration paths for MCP servers
run-mcp scan

# Output results in JSON format
run-mcp scan --json

# Run only local checks without contacting the ratings server
run-mcp scan --offline

# Use experimental TUI mode (interactive)
run-mcp scan --tui
```

#### `experimental inspect`

Actively queries an MCP server for enumeration. Prints descriptions of tools & prompts. (under construction).

```sh
run-mcp experimental inspect
```

#### `experimental proxy`

Forward tool_calls to/from an MCP server through a local proxy for inspection (under construction).

```sh
run-mcp experimental proxy
```

#### `experimental deep-scan`

Scan entire filesystem to match on all MCP configs (under construction).

```sh
run-mcp experimental deep-scan
```

#### `experimental allowlist`

Manages the local allowlist of blessed servers. This feature is experimental and may change. (under contstruction)

```sh
# View the current allowlist
run-mcp experimental allowlist

# Add a tool to the allowlist
run-mcp experimental allowlist add tool "my-tool-name" "sha256:a1b2c3..."

# Reset the allowlist
run-mcp experimental allowlist reset
```

#### `org`

Manage organization identity settings used for reporting.

```sh
# Show the current organization UUID (if any)
run-mcp org show

# Register and persist an organization UUID
run-mcp org register 123e4567-e89b-12d3-a456-426614174000

# Clear the persisted organization UUID
run-mcp org clear
```

### Global Flags

- `-v, --verbose`: Enable detailed logging output.
- `--json`: Output results in JSON format.
- `--tui` experimentail TUI mode for interactive results.
- `--offline`: Run locally without contacting the ratings server.
- `--org-uuid <UUID>`: Optional organization UUID for reporting. Temporarily overrides the value set in `org register`
- `--anonymous` (alias `--anon`): Do not send any UUIDs or tracking information.

## Configuration

`run-mcp` stores its state, including the allowlist and cached results, under `~/Library/Application Support/run-mcp/results.json` by default.

### Further documentation

- API spec: hosted on Scalar Registry: [API Reference](https://registry.scalar.com/@ensignia/apis/mcp-api/latest?format=preview).

## Contributing

You can develop in a reproducible containerized environment using Dev Containers (VS Code) or GitHub Codespaces.

### VS Code Dev Containers

1. Install the "Dev Containers" extension in your preferred IDE.
2. Open this repository in your preferred IDE.
3. When prompted, select "Reopen in Container". Alternatively, use the command palette: "Dev Containers: Reopen in Container".

On first start, dependencies are downloaded automatically.

Common commands inside the container:

```sh
task build            # Build the CLI
task test             # Run tests
task lint             # Run linters
task scan-example     # Demo scan
task pin-dependencies # hash-pin depdendencies of Github Actions
```

Notes:

- If your local Go version differs from the version specified in `go.mod`, the container uses Go's toolchain auto-download to match it.

## License

This project is licensed under the [Apache 2.0 License](./LICENSE).
