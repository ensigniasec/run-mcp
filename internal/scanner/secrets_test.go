package scanner

import (
	"path/filepath"
	"testing"
)

// TestScanSecuritySecretsConfig_Findings verifies we detect three secrets with file:line info.
func TestScanSecuritySecretsConfig_Findings(t *testing.T) {
	testPath := filepath.Join("..", "..", "testdata", "test_secrets_config.json")

	s := NewMCPScanner(nil, "")
	cfg, err := s.ParseMCPConfigFile(testPath)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	findings := s.ScanResult.SecretFindings

	// Expect at least 3 relevant findings with correct lines.
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d: %#v", len(findings), findings)
	}

	assertFinding := func(server, kind string, line int) {
		t.Helper()
		for _, f := range findings {
			if f.ServerName == server && f.Kind == kind {
				if len(f.Occurrences) == 0 {
					t.Fatalf("expected paths with line for %s/%s, got empty", server, kind)
				}
				if !hasOccurrenceForLine(f.Occurrences, line) {
					t.Fatalf("expected %s/%s at line %d, got occurrences %v", server, kind, line, f.Occurrences)
				}
				return
			}
		}
		t.Fatalf("missing finding %s/%s", server, kind)
	}

	// Detector associates provider matches with the owning server.
	assertFinding("consult7", "Google Token", 31)
	assertFinding("supabase", "Supabase Access Token", 12)
	assertFinding("hyperbrowser", "Generic Secret", 48)
}

func hasOccurrenceForLine(occ map[string][]int, line int) bool {
	if line <= 0 {
		return false
	}
	for _, lines := range occ {
		for _, ln := range lines {
			if ln == line {
				return true
			}
		}
	}
	return false
}

// Test that repeated occurrences of the same secret value in one file are merged
// into a single finding with multiple unique paths.
func TestSecrets_MultipleOccurrences_MergedPaths(t *testing.T) {
	testPath := filepath.Join("..", "..", "testdata", "test_secrets_multiple_occurrences.json")

	s := NewMCPScanner(nil, "")
	cfg, err := s.ParseMCPConfigFile(testPath)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	findings := s.ScanResult.SecretFindings

	// Find the OpenRouter API Key finding and assert multiple unique paths.
	var openRouter *SecretFinding
	for i := range findings {
		if findings[i].Kind == "OpenRouter API Key" {
			openRouter = &findings[i]
			break
		}
	}
	if openRouter == nil {
		t.Fatalf("expected an OpenRouter API Key finding")
	}
	total := 0
	for _, lines := range openRouter.Occurrences {
		total += len(lines)
	}
	if total < 3 { // expect several occurrences
		t.Fatalf("expected multiple occurrences, got %d: %v", total, openRouter.Occurrences)
	}
	// Ensure lines are unique per file
	for file, lines := range openRouter.Occurrences {
		seen := map[int]struct{}{}
		for _, ln := range lines {
			if _, ok := seen[ln]; ok {
				t.Fatalf("duplicate line found in merged occurrences for %s: %d", file, ln)
			}
			seen[ln] = struct{}{}
		}
	}
}

// Test URL/token provider patterns are detected and include path info.
func TestSecrets_URLProviderDetections(t *testing.T) {
	testPath := filepath.Join("..", "..", "testdata", "test_secrets_urls.json")

	s := NewMCPScanner(nil, "")
	cfg, err := s.ParseMCPConfigFile(testPath)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	findings := s.ScanResult.SecretFindings

	requireFinding := func(kind string, minTotal int) {
		t.Helper()
		for _, f := range findings {
			if f.Kind == kind {
				total := 0
				for _, lines := range f.Occurrences {
					total += len(lines)
				}
				if total < minTotal {
					t.Fatalf("%s expected at least %d occurrences, got %d: %v", kind, minTotal, total, f.Occurrences)
				}
				return
			}
		}
		t.Fatalf("missing finding kind %q", kind)
	}

	requireFinding("Database URL with Credentials", 1)
	requireFinding("Slack Webhook URL", 1)
	requireFinding("Atlassian URL with Credentials", 1)
}

// Test OpenAI new-style keys with base64 OpenAI marker are detected.
func TestSecrets_OpenAI(t *testing.T) {
	testPath := filepath.Join("..", "..", "testdata", "test_secrets_config.json")

	s := NewMCPScanner(nil, "")
	cfg, err := s.ParseMCPConfigFile(testPath)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	findings := s.ScanResult.SecretFindings

	// Expect 2 OpenAI API Key findings.
	matched := 0
	for _, f := range findings {
		if f.Kind == "OpenAI API Key" {
			matched++
		}
	}
	if matched != 2 {
		t.Fatalf("expected 2 OpenAI API Key findings, got %d: %#v", matched, findings)
	}
}

// Test that identical secret values across different servers are merged by value hash
// resulting in a single finding with combined paths (server name is not asserted).
func TestSecrets_MergeAcrossServers_ByValueHash(t *testing.T) {
	testPath := filepath.Join("..", "..", "testdata", "test_secrets_multiple.json")

	s := NewMCPScanner(nil, "")
	cfg, err := s.ParseMCPConfigFile(testPath)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected config, got nil")
	}
	findings := s.ScanResult.SecretFindings

	// Count OpenAI API Key findings; should be exactly one merged finding.
	count := 0
	var openAI SecretFinding
	for _, f := range findings {
		if f.Kind == "OpenAI API Key" {
			count++
			openAI = f
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 OpenAI API Key finding after merge, got %d: %#v", count, findings)
	}
	total := 0
	for _, lines := range openAI.Occurrences {
		total += len(lines)
	}
	if total < 3 {
		t.Fatalf("expected merged occurrences from multiple locations, got %d: %v", total, openAI.Occurrences)
	}
}
