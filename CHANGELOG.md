# Changelog

All notable changes to the MCP Scanner CLI tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Installer: automatically remove macOS quarantine bit after install to avoid
  Gatekeeper blocks.
- Homebrew cask: post-install hook to de-quarantine the binary on macOS.

### Changed

- GoReleaser: inject build metadata into `main.Version`, `main.Commit`,
  `main.Date` and `internal/api` build variables for accurate `--version` info.
- Documentation: add npm (global) and Homebrew install instructions, a
  Gatekeeper FAQ for macOS, document `--tui`, and clarify `--offline` wording.
- CI: bump Anchore Syft action used in release workflow to v0.20.6.
- Install script: refresh usage/help and examples; support `--version` long
  flag.
- Homebrew cask: enable commit signing; refine uninstall paths to user-level
  directories.

- CLI/TUI: Performance improvements: star to initialize the API client in the
  background for faster startup when online.
- Ratings: `RatingsCollector` now buffers submissions while offline and flushes
  when a client becomes available; debounce timer only runs when a client is
  set.
- API: `NewURLTarget` now enforces `http`/`https` schemes and requires a host
  component.

## [0.1.1] - Initial public release

- No changes

## [0.1.0] - 2025-09-18

Initial release of RUN MCP — a fast, portable,
single-binary security scanner for the Model Context Protocol (MCP). It
scans local MCP configurations and helps enforce security policies.

### Added

- Core CLI:
  - `scan`: scan discovered or specified MCP configs for vulnerabilities
  - Global flags: `--json`, `--verbose`, `--offline`, `--base-url`,
    `--org-uuid`, `--anonymous`
- Configuration discovery:
  - Auto-detect configs from Claude Desktop, VS Code, Cursor, and Windsurf
  - Scan custom files and directories
- Security detectors:
  - Secrets finding with automatic redaction (API keys/tokens, high-entropy
    strings, URLs with embedded credentials)
- Parsers:
  - JSON and YAML with normalization across MCP formats
- Output:
  - Human-readable output and structured JSON
- Local storage:
  - Results cache and allowlist in a user-writable file (default
    `~/Library/Application Support/run-mcp/results.json`)
- API integration:
  - Typed HTTP client generated from OpenAPI; offline & anon mode supported
- Streaming callback on `MCPScanner` via `WithStreamingCallback(func(path,
result, err))` to push per-file updates to the UI.

### Experimental

- Experimental: Interactive TUI mode for scans with real-time streaming updates. Enable
  with `--tui`. Displays file scanning progress first, then a server ratings
  table with spinners, stopwatches, and A–F grades.
- `experimental inspect`: enumerate MCP server tools/prompts and common risks
- `experimental proxy`: forward MCP traffic through a local proxy
- `experimental allowlist`: manage local allow/deny lists
- `experimental deep-scan`: scan filesystem for configs

### Documentation

- README with installation/usage and examples; API spec draft under `docs/`

### Changed

- OpenAPI spec bumped to `0.0.8` and environments moved to new base URLs:
  `https://mcp.ensignia.com/v1/api` (prod) and
  `https://mcp.ensignia.dev/v1/api` (staging).
- Health response schema updated:
  - Adds `api_spec_version` and `server_version` fields.
  - Clarifies `version` as API spec version.
- Generated client types updated in `internal/api-gen/types.gen.go`.
- Ratings service refactor: prepare identifiers via the new extractor in
  `internal/scanner`.

- API:

  - All endpoints now require a publishable key via `Authorization: Bearer
<ens_pk_live_...>`. Client sets the header when configured; documentation
    updated in `internal/api/README.md`.

- GoReleaser:

  - Adopt v2 schema; refine archives and checksums; add SBOMs for archives and
    source; sign checksums with `cosign`.

[Unreleased]: https://github.com/ensigniasec/run-mcp/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ensigniasec/run-mcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/ensigniasec/run-mcp/releases/tag/v0.1.0
