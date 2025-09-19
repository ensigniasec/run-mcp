package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/charlievieth/fastwalk"
	"github.com/sirupsen/logrus"
)

//nolint:gochecknoglobals // immutable lookup table used across the package.
var (
	WellKnownMCPFilenames = []string{
		// Claude Code
		"managed-settings.json",
		"settings.json",
		"mcp.json",

		// Continue
		"config.yaml",
		".continuerc.json",
		"config.json",

		// LibreChat
		"librechat.yaml",

		// Common
		"mcp_config.json",
		"mcp_settings.json",
	}

	wellKnownMCPPathsMacOS = []string{
		// Claude Code
		"~/Library/Application Support/Claude/managed-settings.json",
		// VS Code
		"~/Library/Application Support/Code/User/settings.json",
		"~/Library/Application Support/Code/User/mcp.json",
		// Cursor
		"~/Library/Application Support/Cursor/User/settings.json",
		// VS Code Insiders
		"~/Library/Application Support/Code - Insiders/User/settings.json",
		"~/Library/Application Support/Code - Insiders/User/mcp.json",
		// Windsurf Editor
		"~/.codeium/windsurf/mcp_config.json",
		// Zed
		"~/Library/Application Support/Zed/settings.json",
		// Continue
		"~/.continue/config.yaml",
		"~/.continuerc.json",
		// Goose
		"~/Library/Application Support/goose/config.yaml",
		// Roo Code (user-level if present)
		"~/Library/Application Support/Roo Code/mcp.json",
		// BoltAI
		"~/Library/Application Support/BoltAI/mcp.json",
		// Witsy
		"~/Library/Application Support/Witsy/mcp.json",
		// Enconvo
		"~/Library/Application Support/Enconvo/mcp.json",
		// Warp
		"~/Library/Application Support/dev.warp.Warp-Stable/config/settings.yaml",
	}

	wellKnownMCPPathsWindows = []string{
		// Claude Code
		"C:\\ProgramData\\ClaudeCode\\managed-settings.json",
		// VS Code
		"$APPDATA\\Code\\User\\settings.json",
		"$APPDATA\\Code\\User\\mcp.json",
		// VS Code Insiders
		"$APPDATA\\Code - Insiders\\User\\settings.json",
		"$APPDATA\\Code - Insiders\\User\\mcp.json",
		// Cursor
		"$APPDATA\\Cursor\\settings.json",
		// Windsurf Editor
		"$USERPROFILE\\.codeium\\windsurf\\mcp_config.json",
		// Zed
		"$APPDATA\\Zed\\settings.json",
		// Continue
		"$USERPROFILE\\.continue\\config.yaml",
		"$USERPROFILE\\.continuerc.json",
		// Warp
		"$LOCALAPPDATA\\warp\\Warp\\config\\settings.yaml",
		// Cursor (User home)
		"$USERPROFILE\\.cursor",
		"$USERPROFILE\\.cursor\\settings.json",
		"$USERPROFILE\\.cursor\\mcp.json",
		"$USERPROFILE\\.cursor\\mcp_config.json",
		"$USERPROFILE\\.cursor\\mcp_settings.json",
		// Other assistants (if they store MCP configs)
		"$USERPROFILE\\.claude\\mcp.json",
		"$USERPROFILE\\.gemini\\mcp.json",
		"$USERPROFILE\\.grok\\mcp.json",
		"$USERPROFILE\\.chatgpt\\mcp.json",
		"$USERPROFILE\\.openai\\mcp.json",
		"$USERPROFILE\\.anthropic\\mcp.json",
		"$USERPROFILE\\.xai\\mcp.json",
		"$USERPROFILE\\.codex\\mcp.json",
		// Cline (Windows)
		"$USERPROFILE\\.cline\\mcp_config.json",
		// Amazon Q CLI (Windows)
		"$USERPROFILE\\.aws\\amazonq\\cli-config.json",
		// Roo Code (user)
		"$APPDATA\\Roo Code\\mcp.json",
		// BoltAI
		"$APPDATA\\BoltAI\\mcp.json",
		// Witsy
		"$APPDATA\\Witsy\\mcp.json",
		// Enconvo
		"$APPDATA\\Enconvo\\mcp.json",
	}

	wellKnownMCPPathsLinux = []string{
		// Claude Code
		"/etc/claude-code/managed-settings.json",
		// VS Code
		"~/.config/Code/User/settings.json",
		"~/.config/Code/User/mcp.json",
		// Cursor
		"~/.config/Cursor/settings.json",
		"~/.cursor/settings.json",
		"~/.cursor/mcp.json",
		"~/.cursor/mcp_config.json",
		"~/.cursor/mcp_settings.json",
		// Zed
		"~/.config/zed/settings.json",
		// Goose
		"~/.config/goose/config.yaml",
		// Roo Code
		"~/.config/roo-code/mcp.json",
		"~/.roo/mcp.json",
		// BoltAI
		"~/.config/boltai/mcp.json",
		// Witsy
		"~/.config/witsy/mcp.json",
		// Enconvo
		"~/.config/enconvo/mcp.json",
		// Warp
		"~/.local/state/warp-terminal/config/settings.yaml",
	}

	wellKnownMCPPathsUnix = []string{
		// Claude Code
		"~/.claude/settings.json",
		// Windsurf Editor (macOS/Linux)
		"~/.codeium/windsurf/mcp_config.json",
		// Cline (Legacy)
		"~/.cline/mcp_config.json",
		// Continue (macOS/Linux)
		"~/.continue/config.yaml",
		"~/.continuerc.json",
		// Amazon Q CLI
		"~/.aws/amazonq/cli-config.json",
		// Cursor (User home on macOS/Linux)
		"~/.cursor",
		"~/.cursor/settings.json",
		"~/.cursor/mcp.json",
		"~/.cursor/mcp_config.json",
		"~/.cursor/mcp_settings.json",
		// Other assistants (if they store MCP configs)
		"~/.claude/mcp.json",
		"~/.gemini/mcp.json",
		"~/.grok/mcp.json",
		"~/.chatgpt/mcp.json",
		"~/.openai/mcp.json",
		"~/.anthropic/mcp.json",
		"~/.xai/mcp.json",
		"~/.codex/mcp.json",
		// Roo Code (home fallback)
		"~/.roo/mcp.json",
		// BoltAI
		"~/.boltai/mcp.json",
		// Witsy
		"~/.witsy/mcp.json",
		// Enconvo
		"~/.enconvo/mcp.json",
	}

	// wellKnownMCPPathsProject contains project-level paths (work on all platforms).
	wellKnownMCPPathsProject = []string{
		// Claude Code
		".claudecode/mcp.json",
		".claude/mcp.json",

		".mcp.json",
		// VS Code
		".vscode/settings.json",
		// VS Code Insiders
		".vscode-insiders/settings.json",
		// Continue
		".continue/config.yaml",
		".continuerc.json",
		".continue/config.json",
		// Roo Code
		".roo/mcp.json",
		// BoltAI
		".boltai/mcp.json",
		// Witsy
		".witsy/mcp.json",
		// Enconvo
		".enconvo/mcp.json",
		// Generic assistants (project-level overrides)
		".gemini/mcp.json",
		".grok/mcp.json",
		".chatgpt/mcp.json",
		".openai/mcp.json",
		".anthropic/mcp.json",
		".xai/mcp.json",
		".codex/mcp.json",
		// Cursor project directory and common files
		".cursor",
		".cursor/settings.json",
		".cursor/mcp.json",
		".cursor/mcp_config.json",
		".cursor/mcp_settings.json",
		// LibreChat
		"librechat.yaml",
		// LM Studio & Common
		"mcp.json",
		"mcp_config.json",
		"mcp_settings.json",
	}

	// skipDirs are directories we don't want to scan.
	skipDirs = []string{
		".git",
		".ssh",
		".npm",
		"node_modules",
		"dist",
		"build",
		"target",
		"__pycache__",
		".pyenv",
		".cache",
	}
)

// GetWellKnownMCPPaths returns the appropriate MCP config paths for the current operating system.
// Paths are expanded (~ and environment variables resolved) for immediate use.
func GetWellKnownMCPPaths() []string {
	var rawPaths []string
	// Add OS-specific paths
	switch runtime.GOOS {
	case "darwin": // macOS
		rawPaths = append(rawPaths, wellKnownMCPPathsMacOS...)
		rawPaths = append(rawPaths, wellKnownMCPPathsUnix...)
	case "linux":
		rawPaths = append(rawPaths, wellKnownMCPPathsLinux...)
		rawPaths = append(rawPaths, wellKnownMCPPathsUnix...)
	case "windows":
		rawPaths = append(rawPaths, wellKnownMCPPathsWindows...)
	}
	// Always add project-level paths (work on all platforms), resolved against plausible roots
	for _, root := range getProjectRoots() {
		for _, rel := range wellKnownMCPPathsProject {
			rawPaths = append(rawPaths, filepath.Join(root, rel))
		}
	}
	// Expand all paths (resolve ~ and environment variables)
	var expandedPaths []string
	for _, path := range rawPaths {
		expanded, err := expandPath(path)
		if err != nil {
			logrus.Debugf("Failed to expand path '%s': %v", path, err)
			continue
		}
		expandedPaths = append(expandedPaths, expanded)
	}
	return expandedPaths
}

// getProjectRoots returns plausible roots for resolving project-level relative paths.
// It includes the current working directory and the enclosing git repository root, if any.
func getProjectRoots() []string {
	const initialRootsCapacity = 2
	roots := make([]string, 0, initialRootsCapacity)
	if wd, err := os.Getwd(); err == nil && wd != "" {
		roots = append(roots, wd)
		if repo := findGitRoot(wd); repo != "" && repo != wd {
			roots = append(roots, repo)
		}
	}
	return roots
}

// findGitRoot walks up from start until a directory containing .git is found.
// Returns the directory path or empty string if not found.
func findGitRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "" { // reached filesystem root
			return ""
		}
		dir = parent
	}
}

func expandTilde(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, path[1:]), nil
}

// expandPath expands both tilde and environment variables based on the OS.

func expandPath(path string) (string, error) {
	var err error

	// First expand tilde for Unix-like systems
	if runtime.GOOS != "windows" {
		path, err = expandTilde(path)
		if err != nil {
			return "", err
		}
	}

	// Expand $VAR and ${VAR} across all platforms
	path = os.ExpandEnv(path)

	return filepath.Clean(path), nil
}

func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

func isJSONFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".json"
}

func isJSONOrYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".json" || ext == ".yaml" || ext == ".yml"
}

func stringInListCaseInsensitive(name string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}

func isWellKnownMCPFilename(name string) bool {
	return stringInListCaseInsensitive(name, WellKnownMCPFilenames)
}

func isSkippedDir(name string) bool {
	return stringInListCaseInsensitive(name, skipDirs)
}

// streamConfigFiles walks a directory and streams files that look like MCP configs
// (naively for now, matches common MCP config filenames and JSON/YAML files)
// over a channel. The channel is closed when walking completes or the context is canceled.
const streamBufferSize = 64

//nolint:gocognit // file walking logic is intentionally explicit for clarity; refactor deferred.
func streamConfigFiles(ctx context.Context, root string) <-chan string {
	out := make(chan string, streamBufferSize)
	go func() {
		defer close(out)
		conf := fastwalk.DefaultConfig
		_ = fastwalk.Walk(&conf, root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // Skip unreadable entries.
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			name := d.Name()
			if d.IsDir() {
				if isSkippedDir(name) {
					return fs.SkipDir
				}
				return nil
			}
			if isWellKnownMCPFilename(name) || isJSONOrYAMLFile(path) {
				select {
				case out <- path:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}()
	return out
}
