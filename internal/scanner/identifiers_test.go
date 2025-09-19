package scanner

import (
	"path/filepath"
	"strings"
	"testing"

	apigen "github.com/ensigniasec/run-mcp/internal/api-gen"
)

func TestIdentifierExtractor_SingleServer_Cases(t *testing.T) {
	t.Parallel()

	x := NewIdentifierExtractor()

	tests := []struct {
		name   string
		server Server
		want   []apigen.TargetIdentifier
	}{
		{
			name: "vscode http url",
			server: Server{
				"type": "http",
				"url":  "https://api.githubcopilot.com/mcp/",
			},
			want: []apigen.TargetIdentifier{{Kind: apigen.Url, Value: "https://api.githubcopilot.com/mcp"}},
		},
		{
			name: "npx scoped pkg",
			server: Server{
				"stdio": map[string]interface{}{
					"command": []interface{}{"npx", "-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
				},
			},
			want: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:npm/@modelcontextprotocol/server-filesystem@1.2.3"}},
		},
		{
			name: "uvx pypi",
			server: Server{
				"command": "uvx",
				"args":    []interface{}{"consult7"},
			},
			want: []apigen.TargetIdentifier{{Kind: apigen.Purl, Value: "pkg:pypi/consult7"}},
		},
		{
			name: "docker run image",
			server: Server{
				"command": "docker",
				"args":    []interface{}{"run", "-i", "--rm", "ghcr.io/github/github-mcp-server"},
			},
			want: []apigen.TargetIdentifier{{Kind: apigen.Oci, Value: "ghcr.io/github/github-mcp-server"}},
		},
		{
			name: "repo from url",
			server: Server{
				"url": "https://github.com/ensignia/run-mcp",
			},
			want: []apigen.TargetIdentifier{{Kind: apigen.Url, Value: "https://github.com/ensignia/run-mcp"}, {Kind: apigen.Repo, Value: "ensignia/run-mcp"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := x.ExtractIdentifiers(tt.name, tt.server)
			if len(got) != len(tt.want) {
				t.Fatalf("len(got)=%d len(want)=%d got=%v", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("at %d, got=%v want=%v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIdentifierExtractor_FromConfigFiles(t *testing.T) {
	t.Parallel()

	s := NewMCPScanner(nil, "")
	x := NewIdentifierExtractor()

	// VSCode settings fixture
	p := filepath.Join("..", "..", "testdata", "vscode_settings.json")
	cfg, err := s.ParseMCPConfigFile(p)
	if err != nil || cfg == nil {
		t.Fatalf("failed to parse %s: %v", p, err)
	}
	servers := cfg.GetServers()
	ids := x.ExtractIdentifiersFromServers(servers)
	// Expect URL for github and PURL for context7.
	assertHas(t, ids, apigen.Url, "https://api.githubcopilot.com/mcp")
	assertHasPrefix(t, ids, apigen.Purl, "pkg:npm/@upstash/context7-mcp")

	// GitHub MCP via docker run fixture
	p = filepath.Join("..", "..", "testdata", "test_github_mcp.json")
	cfg, err = s.ParseMCPConfigFile(p)
	if err != nil || cfg == nil {
		t.Fatalf("failed to parse %s: %v", p, err)
	}
	ids = x.ExtractIdentifiersFromServers(cfg.GetServers())
	assertHas(t, ids, apigen.Oci, "ghcr.io/github/github-mcp-server")
}

func assertHas(t *testing.T, ids []apigen.TargetIdentifier, k apigen.IdentifierKind, v string) {
	t.Helper()
	for _, id := range ids {
		if id.Kind == k && id.Value == v {
			return
		}
	}
	t.Fatalf("missing identifier %s:%s in %v", k, v, ids)
}

func assertHasPrefix(t *testing.T, ids []apigen.TargetIdentifier, k apigen.IdentifierKind, prefix string) {
	t.Helper()
	for _, id := range ids {
		if id.Kind == k && strings.HasPrefix(id.Value, prefix) {
			return
		}
	}
	t.Fatalf("missing identifier with prefix %s:%s in %v", k, prefix, ids)
}
