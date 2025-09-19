package scanner

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
)

// IdentifierExtractor exposes helpers to derive zero or more TargetIdentifier from a server config.
// It centralizes heuristics previously scattered in ratings.go.
type IdentifierExtractor struct{}

// NewIdentifierExtractor returns a new extractor instance.
func NewIdentifierExtractor() *IdentifierExtractor { //nolint:ireturn
	return &IdentifierExtractor{}
}

// ExtractIdentifiers inspects a single server config and returns zero or more identifiers.
// The order is deterministic and stable across platforms.
func (x *IdentifierExtractor) ExtractIdentifiers(serverName string, serverConfig interface{}) []apigen.TargetIdentifier {
	cfg, ok := serverConfig.(map[string]interface{})
	if !ok || cfg == nil {
		return nil
	}

	var out []apigen.TargetIdentifier

	// 1) URL-based servers (http/sse): accept common keys: url, endpoint, baseUrl.
	for _, key := range []string{"url", "endpoint", "baseUrl"} {
		if u := getString(cfg, key); u != "" {
			if norm := normalizeURL(u); norm != "" {
				out = append(out, apigen.TargetIdentifier{Kind: apigen.Url, Value: norm})
				break
			}
		}
	}

	// 2) Stdio package runners: infer purl from command/args heuristics.
	if p := extractPurlFromStdio(cfg); p != "" {
		out = append(out, apigen.TargetIdentifier{Kind: apigen.Purl, Value: p})
	}

	// 3) OCI image references inside docker/podman invocations or explicit images.
	if ref := extractOCIFromDocker(cfg); ref != "" {
		out = append(out, apigen.TargetIdentifier{Kind: apigen.Oci, Value: ref})
	}

	// 4a) Repository inference when command suggests a well-known repo path.
	if org, repo := extractRepoHint(cfg, serverName); org != "" && repo != "" {
		out = append(out, apigen.TargetIdentifier{Kind: apigen.Repo, Value: org + "/" + repo})
	}
	// 4b) Official repo inference from built artifacts.
	if r := extractRepoFromNodeDist(cfg); r != "" {
		out = append(out, apigen.TargetIdentifier{Kind: apigen.Repo, Value: r})
	}

	// Deduplicate while preserving order.
	return dedupeIdentifiers(out)
}

// ExtractIdentifiersFromServers returns identifiers for all servers in a config map.
func (x *IdentifierExtractor) ExtractIdentifiersFromServers(servers map[string]Server) []apigen.TargetIdentifier {
	if len(servers) == 0 {
		return nil
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	var all []apigen.TargetIdentifier
	for _, name := range names {
		all = append(all, x.ExtractIdentifiers(name, servers[name])...)
	}
	return dedupeIdentifiers(all)
}

// Helpers.

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func normalizeURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return parsed.String()
}

// npm patterns like npx -y @scope/name@version or @scope/name in stdio.command or stdio.args.
var npmPkgRe = regexp.MustCompile(`^(?:@[^/]+/)?[^@\s]+(?:@[^\s]+)?$`)

func extractPurlFromStdio(cfg map[string]interface{}) string { //nolint:gocyclo,gocognit
	stdio, _ := cfg["stdio"].(map[string]interface{})
	if stdio == nil {
		stdio = cfg
	}

	var tokens []string
	switch v := stdio["command"].(type) {
	case []interface{}:
		for _, it := range v {
			tokens = append(tokens, toString(it))
		}
	case string:
		if v != "" {
			tokens = append(tokens, v)
		}
	}
	if args, ok := stdio["args"].([]interface{}); ok {
		for _, it := range args {
			tokens = append(tokens, toString(it))
		}
	}

	if len(tokens) == 0 {
		return ""
	}

	// Detect `npx` pattern: find first non-flag token after npx and treat it as package.
	for i, tok := range tokens {
		if tok == "npx" {
			for k := i + 1; k < len(tokens); k++ {
				if strings.HasPrefix(tokens[k], "-") {
					continue
				}
				if isNpmPackageToken(tokens[k]) {
					return toPurlNPM(tokens[k])
				}
				break
			}
		}
	}

	// Detect uvx pattern or python -m.
	for i, cur := range tokens {
		if cur == "uvx" && i+1 < len(tokens) {
			cand := tokens[i+1]
			if isPyPackageToken(cand) {
				return toPurlPyPI(cand)
			}
		}
		if (cur == "python" || cur == "python3") && i+2 < len(tokens) && tokens[i+1] == "-m" {
			mod := tokens[i+2]
			if isPyModuleToken(mod) {
				return toPurlPyPI(mod)
			}
		}
		if cur == "pipx" && i+2 < len(tokens) && tokens[i+1] == "run" {
			if isPyPackageToken(tokens[i+2]) {
				return toPurlPyPI(tokens[i+2])
			}
		}
	}

	return ""
}

func isNpmPackageToken(tok string) bool {
	if tok == "" {
		return false
	}
	if strings.Contains(tok, " ") {
		return false
	}
	return npmPkgRe.MatchString(tok)
}

func toPurlNPM(tok string) string {
	return "pkg:npm/" + tok
}

func isPyPackageToken(tok string) bool { return isAlphaNumPlus(tok) }
func isPyModuleToken(tok string) bool  { return isAlphaNumPlus(tok) }

func toPurlPyPI(tok string) string { return "pkg:pypi/" + strings.ReplaceAll(tok, "_", "-") }

func isAlphaNumPlus(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' || r == '+' || r == ':' || r == '@' ||
			('0' <= r && r <= '9') || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') {
			continue
		}
		return false
	}
	return true
}

func extractOCIFromDocker(cfg map[string]interface{}) string { //nolint:gocyclo,gocognit
	var tokens []string
	for _, m := range []map[string]interface{}{cfg, getMap(cfg, "stdio")} {
		if m == nil {
			continue
		}
		switch v := m["command"].(type) {
		case []interface{}:
			for _, it := range v {
				tokens = append(tokens, toString(it))
			}
		case string:
			if v != "" {
				tokens = append(tokens, v)
			}
		}
		if args, ok := m["args"].([]interface{}); ok {
			for _, it := range args {
				tokens = append(tokens, toString(it))
			}
		}
	}
	if len(tokens) == 0 {
		return ""
	}
	for i, tok := range tokens {
		if (tok == "docker" || tok == "podman") && i+1 < len(tokens) && tokens[i+1] == "run" {
			const imageOffset = 2
			for j := i + imageOffset; j < len(tokens); j++ {
				tj := tokens[j]
				if strings.HasPrefix(tj, "-") {
					if takesValue(tj) && j+1 < len(tokens) {
						j++
					}
					continue
				}
				if looksLikeOCIRef(tj) {
					return tj
				}
				break
			}
		}
	}
	return ""
}

// extractRepoFromNodeDist infers the official MCP servers repo when executing built artifacts.
// Heuristic: command is 'node' and first arg matches 'dist/<name>/index.js'.
func extractRepoFromNodeDist(cfg map[string]interface{}) string {
	cmd := getString(cfg, "command")
	if cmd == "" {
		if stdio := getMap(cfg, "stdio"); stdio != nil {
			cmd = getString(stdio, "command")
		}
	}
	if cmd != "node" {
		return ""
	}
	var firstArg string
	if args, ok := cfg["args"].([]interface{}); ok && len(args) > 0 {
		firstArg = toString(args[0])
	}
	if firstArg == "" {
		if stdio := getMap(cfg, "stdio"); stdio != nil {
			if args, ok := stdio["args"].([]interface{}); ok && len(args) > 0 {
				firstArg = toString(args[0])
			}
		}
	}
	if strings.HasPrefix(firstArg, "dist/") && strings.HasSuffix(firstArg, "/index.js") {
		return "modelcontextprotocol/servers"
	}
	return ""
}

// extractRepoHint infers an org/repo from the server name or embedded VCS URL (GitHub/GitLab).
func extractRepoHint(cfg map[string]interface{}, serverName string) (string, string) { //nolint:gocognit
	name := strings.ReplaceAll(serverName, " ", "")
	name = strings.ReplaceAll(name, "_", "-")
	if strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1]
		}
	}
	if strings.Contains(name, "-") {
		parts := strings.Split(name, "-")
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1]
		}
	}
	for _, key := range []string{"url", "endpoint", "baseUrl"} {
		u := getString(cfg, key)
		if u == "" {
			continue
		}
		if pu, err := url.Parse(u); err == nil {
			segs := strings.Split(strings.Trim(pu.Path, "/"), "/")
			const minSegs = 2
			if hostEqual(pu.Host, "github.com") {
				if len(segs) >= minSegs {
					return segs[0], trimGitSuffix(segs[1])
				}
			}
			if hostEqual(pu.Host, "gitlab.com") {
				if len(segs) >= minSegs {
					owner := segs[len(segs)-2]
					repo := trimGitSuffix(segs[len(segs)-1])
					return owner, repo
				}
			}
		}
	}
	return "", ""
}

func trimGitSuffix(s string) string { return strings.TrimSuffix(s, ".git") }

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func takesValue(flag string) bool {
	switch flag {
	case "-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network":
		return true
	default:
		return false
	}
}

func looksLikeOCIRef(s string) bool {
	if !strings.Contains(s, "/") {
		return false
	}
	if strings.Contains(s, " ") {
		return false
	}
	host := strings.Split(s, "/")[0]
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return false
	}
	return true
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.TrimSpace(fmt.Sprintf("%v", v)), "\n", " "), "\""))
	}
}

func hostEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, ":443"), strings.TrimSuffix(b, ":443"))
}

func dedupeIdentifiers(in []apigen.TargetIdentifier) []apigen.TargetIdentifier {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[apigen.IdentifierKind]map[string]struct{})
	var out []apigen.TargetIdentifier
	for _, ti := range in {
		if ti.Kind == "" || ti.Value == "" {
			continue
		}
		if _, ok := seen[ti.Kind]; !ok {
			seen[ti.Kind] = make(map[string]struct{})
		}
		if _, ok := seen[ti.Kind][ti.Value]; ok {
			continue
		}
		seen[ti.Kind][ti.Value] = struct{}{}
		out = append(out, ti)
	}
	return out
}
